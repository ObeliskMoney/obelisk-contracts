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
import {IObeliskVault, Intent, PolicyOutput} from "./interfaces/IObeliskVault.sol";

/// @title ObeliskVault
/// @notice Holds funds and only executes agent intents that carry
///         (1) a signature from a registered TEE key and (2) a ZK proof of policy compliance.
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

    bytes32 public constant INTENT_TYPEHASH =
        keccak256("Intent(address target,uint256 value,bytes data,uint256 nonce,uint64 deadline)");

    ISP1Verifier public immutable verifier;
    IAgentRegistry public immutable registry;

    bytes32 public policyHash;
    bytes32 public programVKey;

    mapping(uint256 nonce => bool) public usedNonce;
    mapping(uint64 day => uint256) public spentOnDay;
    /// @notice Agents chosen by the owner for this vault. They must also be active in AgentRegistry.
    mapping(address agent => bool) public agentAllowed;

    constructor(
        address owner_,
        ISP1Verifier verifier_,
        IAgentRegistry registry_,
        bytes32 policyHash_,
        bytes32 programVKey_,
        address agent_
    ) Ownable(owner_) EIP712("Obelisk", "1") {
        verifier = verifier_;
        registry = registry_;
        if (policyHash_ != bytes32(0)) _setPolicy(policyHash_, programVKey_);
        if (agent_ != address(0)) _setAgent(agent_, true);
    }

    receive() external payable {}

    // ---------------------------------------------------------------- owner

    function setPolicy(bytes32 policyHash_, bytes32 programVKey_) external onlyOwner {
        _setPolicy(policyHash_, programVKey_);
    }

    /// @notice Allow or revoke an agent for this vault (revoking is the per-vault emergency brake).
    function setAgent(address agent, bool allowed) external onlyOwner {
        _setAgent(agent, allowed);
    }

    function _setPolicy(bytes32 policyHash_, bytes32 programVKey_) internal {
        policyHash = policyHash_;
        programVKey = programVKey_;
        emit PolicyUpdated(policyHash_, programVKey_);
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

        result = Address.functionCall(intent.target, intent.data);
        emit Executed(intentHash, agent, intent.nonce, today, out.spentAfter);
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
