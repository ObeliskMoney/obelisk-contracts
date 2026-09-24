// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ObeliskVault} from "../../src/ObeliskVault.sol";
import {AgentRegistry} from "../../src/AgentRegistry.sol";
import {MockVerifier} from "../../src/mocks/MockVerifier.sol";
import {MockERC20} from "../../src/mocks/MockERC20.sol";
import {MockSwapRouter} from "../../src/mocks/MockSwapRouter.sol";
import {ISP1Verifier} from "../../src/interfaces/ISP1Verifier.sol";
import {IAgentRegistry} from "../../src/interfaces/IAgentRegistry.sol";
import {Intent, PolicyOutput} from "../../src/interfaces/IObeliskVault.sol";

abstract contract Base is Test {
    bytes32 constant POLICY = keccak256("policy-v1");
    bytes32 constant VKEY = keccak256("vkey");
    bytes32 constant MEASUREMENT = keccak256("agent-image-v1");
    uint256 constant USDC_UNIT = 1e6;

    address owner = makeAddr("owner");
    address executor = makeAddr("executor");
    address attacker = makeAddr("attacker");
    uint256 agentPk;
    address agent;

    ObeliskVault vault;
    AgentRegistry registry;
    MockVerifier verifier;
    MockERC20 usdc;
    MockERC20 weth;
    MockSwapRouter router;

    function setUp() public virtual {
        vm.warp(1_790_000_000);
        (agent, agentPk) = makeAddrAndKey("agent");

        verifier = new MockVerifier();
        registry = new AgentRegistry(owner);
        vault = new ObeliskVault(
            owner, ISP1Verifier(address(verifier)), IAgentRegistry(address(registry)), POLICY, VKEY, agent
        );
        usdc = new MockERC20("USD Coin", "USDC", 6);
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        router = new MockSwapRouter(1e18, 4000e6); // 1 ETH = 4000 USDC

        vm.prank(owner);
        registry.registerAgent(agent, MEASUREMENT);

        usdc.mint(address(vault), 500 * USDC_UNIT);
    }

    // ------------------------------------------------------------ builders

    function _today() internal view returns (uint64) {
        return uint64(block.timestamp / 1 days);
    }

    function _intent(address target, bytes memory data, uint256 nonce) internal view returns (Intent memory) {
        return Intent({target: target, value: 0, data: data, nonce: nonce, deadline: uint64(block.timestamp + 1 hours)});
    }

    function _approveIntent(uint256 amount, uint256 nonce) internal view returns (Intent memory) {
        return _intent(address(usdc), abi.encodeCall(usdc.approve, (address(router), amount)), nonce);
    }

    function _swapIntent(uint256 amountIn, uint256 nonce) internal view returns (Intent memory) {
        MockSwapRouter.ExactInputSingleParams memory p = MockSwapRouter.ExactInputSingleParams({
            tokenIn: address(usdc),
            tokenOut: address(weth),
            fee: 500,
            recipient: address(vault),
            amountIn: amountIn,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        });
        return _intent(address(router), abi.encodeCall(router.exactInputSingle, (p)), nonce);
    }

    function _sign(uint256 pk, Intent memory i) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, vault.typedIntentDigest(i));
        return abi.encodePacked(r, s, v);
    }

    /// @dev Mirrors the output of an honest SP1 program.
    function _pv(Intent memory i, uint256 spend) internal view returns (bytes memory) {
        uint256 before = vault.spentOnDay(_today());
        return abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), before, before + spend, _today()));
    }

    function _exec(Intent memory i, uint256 spend) internal returns (bytes memory) {
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, spend);
        vm.prank(executor);
        return vault.execute(i, sig, pv, "");
    }
}
