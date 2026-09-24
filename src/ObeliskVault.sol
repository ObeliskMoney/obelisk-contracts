// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";
import {IObeliskVault, Intent, PolicyOutput, Limits, OBELISK_VAULT_VERSION} from "./interfaces/IObeliskVault.sol";

/// @title ObeliskVault
/// @notice Holds funds and only executes agent intents that carry
///         (1) a signature from a registered TEE key and (2) a ZK proof of policy compliance.
///         v4 adds onchain limits: the vault also checks the call itself (only approve to a router, transfer to a
///         payee, or a swap from the limited token back to the vault) and measures how much of the limited token
///         actually leaves, per call and per day. The proof stays the main check; the limits cap the damage if the
///         SP1 program ever accepts something it should not.
/// @dev Order of checks: docs/spec.md §5.
contract ObeliskVault is IObeliskVault, Ownable2Step, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    error PolicyNotSet();
    error Expired();
    error NonceUsed();
    error AgentNotActive();
    error PolicyMismatch();
    error IntentMismatch();
    error WrongDay();
    error SpentMismatch();
    error SpentDecreased();
    error ValueNotAllowed();
    error SelfCall();
    error BadLimits();
    error CallNotAllowed();
    error SpenderNotAllowed(address spender);
    error ApproveAboveDailyLimit();
    error PayeeNotAllowed(address to);
    error SwapNotAllowed();
    error OutflowAbovePerTx(uint256 outflow);
    error OutflowAbovePerDay(uint256 outflowToday);

    bytes32 public constant INTENT_TYPEHASH =
        keccak256("Intent(address target,uint256 value,bytes data,uint256 nonce,uint64 deadline)");

    uint8 public constant VERSION = OBELISK_VAULT_VERSION;
    /// @notice Most routers or payees in the onchain limits.
    uint256 public constant MAX_LIST = 32;

    bytes4 private constant APPROVE = 0x095ea7b3; // approve(address,uint256)
    bytes4 private constant TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    bytes4 private constant EXACT_INPUT_SINGLE = 0x04e45aaf; // SwapRouter02 exactInputSingle(ExactInputSingleParams)

    ISP1Verifier public immutable verifier;
    IAgentRegistry public immutable registry;

    bytes32 public policyHash;
    bytes32 public programVKey;

    mapping(uint256 nonce => bool) public usedNonce;
    mapping(uint64 day => uint256) public spentOnDay;
    /// @notice Agents chosen by the owner for this vault. They must also be active in AgentRegistry.
    mapping(address agent => bool) public agentAllowed;

    // Onchain limits (see Limits in IObeliskVault).
    address public limitToken;
    uint256 public limitPerTx;
    uint256 public limitPerDay;
    address[] private _routers;
    address[] private _payees;
    mapping(address => bool) public isRouter;
    mapping(address => bool) public isPayee;
    /// @notice limitToken that actually left the vault through execute, per UTC day (measured, not proven).
    mapping(uint64 day => uint256) public outflowOnDay;

    constructor(
        address owner_,
        ISP1Verifier verifier_,
        IAgentRegistry registry_,
        bytes32 policyHash_,
        bytes32 programVKey_,
        Limits memory limits_,
        address agent_
    ) Ownable(owner_) EIP712("Obelisk", "1") {
        verifier = verifier_;
        registry = registry_;
        if (policyHash_ != bytes32(0)) _setRules(policyHash_, programVKey_, limits_);
        if (agent_ != address(0)) _setAgent(agent_, true);
    }

    receive() external payable {}

    // ---------------------------------------------------------------- owner

    /// @notice Replaces the policy, the program and the onchain limits together, so they cannot drift apart.
    ///         A zero policyHash switches the agent off (every execute reverts) and clears the limits.
    function setRules(bytes32 policyHash_, bytes32 programVKey_, Limits calldata limits_) external onlyOwner {
        _setRules(policyHash_, programVKey_, limits_);
    }

    /// @notice Allow or revoke an agent for this vault (revoking is the per-vault emergency brake).
    function setAgent(address agent, bool allowed) external onlyOwner {
        _setAgent(agent, allowed);
    }

    function _setRules(bytes32 policyHash_, bytes32 programVKey_, Limits memory l) internal {
        policyHash = policyHash_;
        programVKey = programVKey_;
        emit PolicyUpdated(policyHash_, programVKey_);

        for (uint256 k; k < _routers.length; k++) isRouter[_routers[k]] = false;
        for (uint256 k; k < _payees.length; k++) isPayee[_payees[k]] = false;
        delete _routers;
        delete _payees;
        if (policyHash_ == bytes32(0)) {
            (limitToken, limitPerTx, limitPerDay) = (address(0), 0, 0);
            emit LimitsUpdated(address(0), 0, 0, _routers, _payees);
            return;
        }

        if (l.token == address(0) || l.token == address(this)) revert BadLimits();
        if (l.routers.length > MAX_LIST || l.payees.length > MAX_LIST) revert BadLimits();
        for (uint256 k; k < l.routers.length; k++) {
            address r = l.routers[k];
            // The token is never a router: calls to it are only approve or transfer.
            if (r == address(0) || r == l.token || r == address(this) || isRouter[r]) revert BadLimits();
            isRouter[r] = true;
            _routers.push(r);
        }
        for (uint256 k; k < l.payees.length; k++) {
            address p = l.payees[k];
            if (p == address(0) || isPayee[p]) revert BadLimits();
            isPayee[p] = true;
            _payees.push(p);
        }
        (limitToken, limitPerTx, limitPerDay) = (l.token, l.maxPerTx, l.maxPerDay);
        emit LimitsUpdated(l.token, l.maxPerTx, l.maxPerDay, l.routers, l.payees);
    }

    function _setAgent(address agent, bool allowed) internal {
        agentAllowed[agent] = allowed;
        emit AgentSet(agent, allowed);
    }

    /// @notice The owner can always withdraw directly; the policy only limits the agent.
    function withdraw(address token, address to, uint256 amount) external nonReentrant onlyOwner {
        if (token == address(0)) Address.sendValue(payable(to), amount);
        else IERC20(token).safeTransfer(to, amount);
        emit Withdrawn(token, to, amount);
    }

    // ---------------------------------------------------------------- agent

    function execute(Intent calldata intent, bytes calldata agentSig, bytes calldata publicValues, bytes calldata proof)
        external
        nonReentrant
        returns (bytes memory result)
    {
        if (policyHash == bytes32(0)) revert PolicyNotSet();
        if (block.timestamp > intent.deadline) revert Expired();
        if (usedNonce[intent.nonce]) revert NonceUsed();
        // Defense in depth: these two rules are also enforced by the SP1 program.
        if (intent.value != 0) revert ValueNotAllowed();
        if (intent.target == address(this)) revert SelfCall();

        address agent = ECDSA.recover(_typedIntentDigest(intent), agentSig);
        if (!agentAllowed[agent] || !registry.isActive(agent)) revert AgentNotActive();

        verifier.verifyProof(programVKey, publicValues, proof);
        PolicyOutput memory out = abi.decode(publicValues, (PolicyOutput));

        if (out.policyHash != policyHash) revert PolicyMismatch();
        bytes32 intentHash = hashIntent(intent);
        if (out.intentHash != intentHash) revert IntentMismatch();

        uint64 today = uint64(block.timestamp / 1 days);
        if (out.day != today) revert WrongDay();
        if (out.spentBefore != spentOnDay[today]) revert SpentMismatch();
        if (out.spentAfter < out.spentBefore) revert SpentDecreased();

        usedNonce[intent.nonce] = true;
        spentOnDay[today] = out.spentAfter;

        _checkCall(intent.target, intent.data);
        result = _callWithOutflowCap(intent.target, intent.data, today);
        emit Executed(intentHash, agent, intent.nonce, today, out.spentAfter);
    }

    /// @notice The onchain limits for this vault.
    function limits() external view returns (Limits memory) {
        return Limits(limitToken, limitPerTx, limitPerDay, _routers, _payees);
    }

    // ---------------------------------------------------------------- onchain limits

    /// @dev Only three calls exist: token.approve(router, <= maxPerDay), token.transfer(payee, _) and
    ///      router.exactInputSingle with tokenIn = token and recipient = this vault. Fixed-length calldata only,
    ///      decoded with Solidity's checked abi.decode (dirty address bits revert).
    function _checkCall(address target, bytes calldata data) internal view {
        if (data.length < 4) revert CallNotAllowed();
        bytes4 sel = bytes4(data[:4]);
        if (target == limitToken) {
            if (data.length != 4 + 32 * 2) revert CallNotAllowed();
            (address who, uint256 amount) = abi.decode(data[4:], (address, uint256));
            if (sel == APPROVE) {
                if (!isRouter[who]) revert SpenderNotAllowed(who);
                if (amount > limitPerDay) revert ApproveAboveDailyLimit();
            } else if (sel == TRANSFER) {
                if (!isPayee[who]) revert PayeeNotAllowed(who);
            } else {
                revert CallNotAllowed();
            }
        } else if (isRouter[target]) {
            if (sel != EXACT_INPUT_SINGLE || data.length != 4 + 32 * 7) revert CallNotAllowed();
            (address tokenIn,,, address recipient,,,) =
                abi.decode(data[4:], (address, address, uint24, address, uint256, uint256, uint160));
            if (tokenIn != limitToken || recipient != address(this)) revert SwapNotAllowed();
        } else {
            revert CallNotAllowed();
        }
    }

    /// @dev Measures the limited token leaving the vault during the call, whatever the calldata claims.
    function _callWithOutflowCap(address target, bytes calldata data, uint64 today)
        internal
        returns (bytes memory result)
    {
        IERC20 token = IERC20(limitToken);
        uint256 balBefore = token.balanceOf(address(this));
        result = Address.functionCall(target, data);
        uint256 balAfter = token.balanceOf(address(this));
        if (balAfter < balBefore) {
            uint256 outflow = balBefore - balAfter;
            if (outflow > limitPerTx) revert OutflowAbovePerTx(outflow);
            uint256 outToday = outflowOnDay[today] + outflow;
            if (outToday > limitPerDay) revert OutflowAbovePerDay(outToday);
            outflowOnDay[today] = outToday;
        }
    }

    // ---------------------------------------------------------------- views

    /// @notice intentHash per docs/spec.md §1.1 (also computed by the SP1 program).
    function hashIntent(Intent calldata intent) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                intent.target,
                intent.value,
                keccak256(intent.data),
                intent.nonce,
                intent.deadline
            )
        );
    }

    function typedIntentDigest(Intent calldata intent) external view returns (bytes32) {
        return _typedIntentDigest(intent);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _typedIntentDigest(Intent calldata intent) internal view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INTENT_TYPEHASH, intent.target, intent.value, keccak256(intent.data), intent.nonce, intent.deadline
                )
            )
        );
    }
}
