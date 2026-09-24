// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Base} from "./utils/Base.t.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockSwapRouter} from "../src/mocks/MockSwapRouter.sol";
import {Intent, PolicyOutput} from "../src/interfaces/IObeliskVault.sol";

/// @dev Runs a mix of honest executions (limited by the policy, mirroring the SP1 program)
///      and attacks (arbitrary public values, transfer intents to the attacker).
contract VaultHandler is Test {
    uint256 constant MAX_PER_TX = 100e6;
    uint256 constant MAX_PER_DAY = 300e6;

    ObeliskVault vault;
    MockERC20 usdc;
    MockSwapRouter router;
    MockERC20 weth;
    uint256 agentPk;
    address attacker;
    bytes32 policy;

    uint256 public nextNonce = 1;
    mapping(uint64 => uint256) public outflowOnDay;
    uint64[] public days_;
    mapping(uint64 => bool) seenDay;
    uint256 public honestOk;
    uint256 public attacksLanded;

    constructor(
        ObeliskVault v,
        MockERC20 u,
        MockERC20 w,
        MockSwapRouter r,
        uint256 pk,
        address atk,
        bytes32 pol
    ) {
        (vault, usdc, weth, router, agentPk, attacker, policy) = (v, u, w, r, pk, atk, pol);
    }

    function _today() internal view returns (uint64) {
        return uint64(block.timestamp / 1 days);
    }

    function _sign(Intent memory i) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, vault.typedIntentDigest(i));
        return abi.encodePacked(r, s, v);
    }

    function _swap(uint256 amountIn) internal returns (Intent memory) {
        MockSwapRouter.ExactInputSingleParams memory p = MockSwapRouter.ExactInputSingleParams(
            address(usdc), address(weth), 500, address(vault), amountIn, 0, 0
        );
        return Intent(address(router), 0, abi.encodeCall(router.exactInputSingle, (p)), nextNonce++, uint64(block.timestamp + 1 hours));
    }

    function _track() internal {
        uint64 d = _today();
        if (!seenDay[d]) {
            seenDay[d] = true;
            days_.push(d);
        }
    }

    /// Honest execution: a proof only exists when the policy holds (like the SP1 program).
    function honestSwap(uint256 amountIn) external {
        amountIn = bound(amountIn, 1, 200e6);
        _track();
        uint64 d = _today();
        uint256 before = vault.spentOnDay(d);
        if (amountIn > MAX_PER_TX || before + amountIn > MAX_PER_DAY) return; // the prover refuses
        if (usdc.balanceOf(address(vault)) < amountIn) return;
        Intent memory i = _swap(amountIn);
        bytes memory pv = abi.encode(PolicyOutput(policy, vault.hashIntent(i), before, before + amountIn, d));
        uint256 bal = usdc.balanceOf(address(vault));
        vault.execute(i, _sign(i), pv, "");
        outflowOnDay[d] += bal - usdc.balanceOf(address(vault));
        honestOk++;
    }

    /// Attack: a transfer intent to the attacker with fabricated public values.
    function attackTransfer(uint256 amount, uint256 spentBefore, uint256 spentAfter, uint64 dayDelta, bool reuseIntent)
        external
    {
        _track();
        amount = bound(amount, 1, 500e6);
        Intent memory evil = Intent(
            address(usdc), 0, abi.encodeCall(usdc.transfer, (attacker, amount)), nextNonce++, uint64(block.timestamp + 1 hours)
        );
        // Since the SP1 program will not prove a transfer to the attacker, the attacker can only
        // fabricate public values for another intent (reuseIntent) or for this intent
        // with a fake policyHash.
        bytes32 ih = reuseIntent ? keccak256(abi.encode(amount)) : vault.hashIntent(evil);
        bytes32 ph = reuseIntent ? policy : keccak256("forged-policy");
        bytes memory pv = abi.encode(PolicyOutput(ph, ih, spentBefore, spentAfter, _today() + (dayDelta % 3)));
        try vault.execute(evil, _sign(evil), pv, "") {
            attacksLanded++;
        } catch {}
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 2 days));
    }

    function daysLength() external view returns (uint256) {
        return days_.length;
    }
}

contract ObeliskVaultInvariantTest is Base {
    VaultHandler handler;

    function setUp() public override {
        super.setUp();
        usdc.mint(address(vault), 10_000e6);
        handler = new VaultHandler(vault, usdc, weth, router, agentPk, attacker, POLICY);
        // approve once at the start, as in the demo scenario
        _exec(_approveIntent(type(uint256).max, 999_999), 0);
        targetContract(address(handler));
    }

    function invariant_AttackerNeverPaid() public view {
        assertEq(usdc.balanceOf(attacker), 0);
        assertEq(handler.attacksLanded(), 0);
    }

    function invariant_DailyOutflowWithinLimitAndRecorded() public view {
        for (uint256 k; k < handler.daysLength(); k++) {
            uint64 d = handler.days_(k);
            assertLe(vault.spentOnDay(d), 300e6);
            assertEq(handler.outflowOnDay(d), vault.spentOnDay(d));
        }
    }
}
