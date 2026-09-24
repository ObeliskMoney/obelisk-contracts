// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {MockSwapRouter} from "../src/mocks/MockSwapRouter.sol";
import {IObeliskVault, Intent, PolicyOutput, Limits} from "../src/interfaces/IObeliskVault.sol";

/// @notice v4 onchain limits. Every test here assumes the SP1 program is broken: the (mock) verifier accepts public
///         values that match the intent and claim no spending at all, for any intent. The vault must still stop
///         anything outside its onchain limits.
contract ObeliskVaultLimitsTest is Base {
    /// A "proof" from a broken program: right policy, right intent, and it claims the intent spends nothing.
    function _brokenExec(Intent memory i) internal returns (bytes memory) {
        uint256 before = vault.spentOnDay(_today());
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), before, before, _today()));
        return vault.execute(i, _sign(agentPk, i), pv, "");
    }

    function _expectBroken(Intent memory i, bytes memory err) internal {
        uint256 before = vault.spentOnDay(_today());
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), before, before, _today()));
        bytes memory sig = _sign(agentPk, i);
        vm.expectRevert(err);
        vault.execute(i, sig, pv, "");
    }

    function _swapTo(address tokenIn, address recipient, uint256 amountIn, uint256 nonce)
        internal
        view
        returns (Intent memory)
    {
        MockSwapRouter.ExactInputSingleParams memory p =
            MockSwapRouter.ExactInputSingleParams(tokenIn, address(weth), 500, recipient, amountIn, 0, 0);
        return _intent(address(router), abi.encodeCall(router.exactInputSingle, (p)), nonce);
    }

    // ------------------------------------------------------------ calls outside the limits

    function test_BrokenProgram_TransferToAttacker() public {
        Intent memory i = _intent(address(usdc), abi.encodeCall(usdc.transfer, (attacker, 50e6)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.PayeeNotAllowed.selector, attacker));
        assertEq(usdc.balanceOf(attacker), 0);
    }

    function test_BrokenProgram_ApproveAttacker() public {
        Intent memory i = _intent(address(usdc), abi.encodeCall(usdc.approve, (attacker, 1)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.SpenderNotAllowed.selector, attacker));
    }

    function test_BrokenProgram_UnlimitedApprove() public {
        Intent memory i = _approveIntent(LIMIT_PER_DAY + 1, 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.ApproveAboveDailyLimit.selector));
    }

    function test_BrokenProgram_SwapOutputToAttacker() public {
        _brokenExec(_approveIntent(LIMIT_PER_DAY, 1));
        _expectBroken(_swapTo(address(usdc), attacker, 50e6, 2), abi.encodeWithSelector(ObeliskVault.SwapNotAllowed.selector));
    }

    function test_BrokenProgram_SwapOtherTokenIn() public {
        weth.mint(address(vault), 1 ether);
        _expectBroken(_swapTo(address(weth), address(vault), 1 ether, 1), abi.encodeWithSelector(ObeliskVault.SwapNotAllowed.selector));
    }

    function test_BrokenProgram_OtherTarget() public {
        weth.mint(address(vault), 1 ether);
        Intent memory i = _intent(address(weth), abi.encodeCall(weth.transfer, (attacker, 1 ether)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.CallNotAllowed.selector));
        assertEq(weth.balanceOf(attacker), 0);
    }

    function test_BrokenProgram_OtherSelectorOnToken() public {
        Intent memory i = _intent(address(usdc), abi.encodeCall(usdc.transferFrom, (address(vault), attacker, 1)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.CallNotAllowed.selector));
    }

    function test_BrokenProgram_OtherSelectorOnRouter() public {
        Intent memory i = _intent(address(router), abi.encodeCall(router.setRate, (1, 1)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.CallNotAllowed.selector));
    }

    function test_BrokenProgram_TrailingCalldata() public {
        Intent memory i = _intent(address(usdc), abi.encodePacked(abi.encodeCall(usdc.transfer, (payee, 1)), bytes1(0)), 1);
        _expectBroken(i, abi.encodeWithSelector(ObeliskVault.CallNotAllowed.selector));
    }

    function test_BrokenProgram_ShortCalldata() public {
        _expectBroken(_intent(address(usdc), hex"a9059c", 1), abi.encodeWithSelector(ObeliskVault.CallNotAllowed.selector));
    }

    /// An address word with dirty upper bits must not pass as an allowed payee.
    function test_BrokenProgram_DirtyAddressBits() public {
        bytes memory data = abi.encodeWithSelector(usdc.transfer.selector, uint256(uint160(payee)) | (1 << 200), uint256(1));
        Intent memory i = _intent(address(usdc), data, 1);
        uint256 before = vault.spentOnDay(_today());
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), before, before, _today()));
        bytes memory sig = _sign(agentPk, i);
        vm.expectRevert();
        vault.execute(i, sig, pv, "");
    }

    // ------------------------------------------------------------ measured outflow

    /// The program claims a 150 USDC swap spends nothing; the vault measures 150 leaving and refuses.
    function test_BrokenProgram_OutflowAbovePerTx() public {
        _brokenExec(_approveIntent(LIMIT_PER_DAY, 1));
        _expectBroken(
            _swapTo(address(usdc), address(vault), 150e6, 2),
            abi.encodeWithSelector(ObeliskVault.OutflowAbovePerTx.selector, 150e6)
        );
    }

    function test_BrokenProgram_OutflowAbovePerDay() public {
        _brokenExec(_approveIntent(LIMIT_PER_DAY, 1));
        for (uint256 k; k < 3; k++) _brokenExec(_swapTo(address(usdc), address(vault), 100e6, 2 + k));
        assertEq(vault.outflowOnDay(_today()), 300e6);
        assertEq(vault.spentOnDay(_today()), 0); // the broken program recorded nothing
        _brokenExec(_approveIntent(LIMIT_PER_DAY, 5));
        _expectBroken(
            _swapTo(address(usdc), address(vault), 1, 6), abi.encodeWithSelector(ObeliskVault.OutflowAbovePerDay.selector, 300e6 + 1)
        );
        // A payee transfer counts against the same daily cap.
        _expectBroken(
            _intent(address(usdc), abi.encodeCall(usdc.transfer, (payee, 1)), 7),
            abi.encodeWithSelector(ObeliskVault.OutflowAbovePerDay.selector, 300e6 + 1)
        );
        vm.warp(block.timestamp + 1 days);
        _brokenExec(_swapTo(address(usdc), address(vault), 100e6, 8));
        assertEq(vault.outflowOnDay(_today()), 100e6);
    }

    function test_PayeeTransferCountsOutflow() public {
        _exec(_intent(address(usdc), abi.encodeCall(usdc.transfer, (payee, 40e6)), 1), 40e6);
        assertEq(usdc.balanceOf(payee), 40e6);
        assertEq(vault.outflowOnDay(_today()), 40e6);
        assertEq(vault.spentOnDay(_today()), 40e6);
    }

    function test_ApproveHasNoOutflow() public {
        _exec(_approveIntent(LIMIT_PER_DAY, 1), 0);
        assertEq(vault.outflowOnDay(_today()), 0);
    }

    /// Money coming in (a deposit racing a call) never counts as outflow.
    function test_InflowIsNotOutflow() public {
        _exec(_approveIntent(LIMIT_PER_DAY, 1), 0);
        _exec(_swapIntent(100e6, 2), 100e6);
        assertEq(vault.outflowOnDay(_today()), 100e6);
    }

    // ------------------------------------------------------------ setRules

    function test_LimitsGetter() public view {
        Limits memory l = vault.limits();
        assertEq(l.token, address(usdc));
        assertEq(l.maxPerTx, LIMIT_PER_TX);
        assertEq(l.maxPerDay, LIMIT_PER_DAY);
        assertEq(l.routers.length, 1);
        assertEq(l.routers[0], address(router));
        assertEq(l.payees[0], payee);
        assertEq(vault.VERSION(), 4);
    }

    function test_SetRulesReplacesLists() public {
        address newPayee = makeAddr("new-payee");
        address[] memory routers = new address[](0);
        address[] memory payees = new address[](1);
        payees[0] = newPayee;
        vm.expectEmit(true, false, false, true, address(vault));
        emit IObeliskVault.LimitsUpdated(address(usdc), 1e6, 2e6, routers, payees);
        vm.prank(owner);
        vault.setRules(POLICY, VKEY, Limits(address(usdc), 1e6, 2e6, routers, payees));

        assertFalse(vault.isRouter(address(router)));
        assertFalse(vault.isPayee(payee));
        assertTrue(vault.isPayee(newPayee));
        assertEq(vault.limitPerTx(), 1e6);
        _expectBroken(_approveIntent(1, 1), abi.encodeWithSelector(ObeliskVault.SpenderNotAllowed.selector, address(router)));
    }

    function test_SetRulesZeroPolicyClearsLimits() public {
        vm.prank(owner);
        vault.setRules(bytes32(0), VKEY, _limits());
        assertEq(vault.limitToken(), address(0));
        assertFalse(vault.isRouter(address(router)));
        assertEq(vault.limits().payees.length, 0);
    }

    function test_RevertWhen_BadLimits() public {
        Limits memory l = _limits();
        vm.startPrank(owner);

        l.token = address(0);
        vm.expectRevert(ObeliskVault.BadLimits.selector);
        vault.setRules(POLICY, VKEY, l);

        l = _limits();
        l.routers[0] = address(usdc); // the token as a router would allow token.exactInputSingle-shaped calls
        vm.expectRevert(ObeliskVault.BadLimits.selector);
        vault.setRules(POLICY, VKEY, l);

        l = _limits();
        l.routers[0] = address(vault);
        vm.expectRevert(ObeliskVault.BadLimits.selector);
        vault.setRules(POLICY, VKEY, l);

        l = _limits();
        l.payees = new address[](2);
        (l.payees[0], l.payees[1]) = (payee, payee);
        vm.expectRevert(ObeliskVault.BadLimits.selector);
        vault.setRules(POLICY, VKEY, l);

        l = _limits();
        l.payees = new address[](33);
        for (uint256 k; k < 33; k++) l.payees[k] = address(uint160(1000 + k));
        vm.expectRevert(ObeliskVault.BadLimits.selector);
        vault.setRules(POLICY, VKEY, l);
        vm.stopPrank();
    }

    function test_RevertWhen_NonOwnerSetRules() public {
        vm.prank(attacker);
        vm.expectRevert();
        vault.setRules(POLICY, VKEY, _limits());
    }

    // ------------------------------------------------------------ fuzz

    /// Whatever a broken program lets through, nothing reaches the attacker and daily outflow stays capped.
    function testFuzz_BrokenProgramBounded(uint8 kind, uint256 amount, address who) public {
        vm.assume(who != address(vault) && who != payee);
        amount = bound(amount, 1, 1_000e6);
        usdc.mint(address(vault), 1_000e6);
        _brokenExec(_approveIntent(LIMIT_PER_DAY, 1));

        Intent memory i;
        kind = kind % 4;
        if (kind == 0) i = _intent(address(usdc), abi.encodeCall(usdc.transfer, (who, amount)), 2);
        else if (kind == 1) i = _intent(address(usdc), abi.encodeCall(usdc.approve, (who, amount)), 2);
        else if (kind == 2) i = _swapTo(address(usdc), who, amount, 2);
        else i = _swapTo(address(usdc), address(vault), amount, 2);

        uint256 balBefore = usdc.balanceOf(address(vault));
        try this.brokenExecExternal(i) {} catch {}
        uint256 lost = balBefore - usdc.balanceOf(address(vault));
        assertLe(lost, LIMIT_PER_TX);
        assertLe(vault.outflowOnDay(_today()), LIMIT_PER_DAY);
        if (who != address(router)) {
            assertEq(usdc.balanceOf(who), 0);
            assertEq(weth.balanceOf(who), 0);
            assertEq(usdc.allowance(address(vault), who), 0);
        }
    }

    function brokenExecExternal(Intent memory i) external {
        _brokenExec(i);
    }
}
