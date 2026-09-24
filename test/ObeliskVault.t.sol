// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {IObeliskVault, Intent, PolicyOutput} from "../src/interfaces/IObeliskVault.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ObeliskVaultTest is Base {
    // ------------------------------------------------------------ happy path

    function test_ApproveThenSwap() public {
        _exec(_approveIntent(50 * USDC_UNIT, 1), 0);
        _exec(_swapIntent(50 * USDC_UNIT, 2), 50 * USDC_UNIT);

        assertEq(usdc.balanceOf(address(vault)), 450 * USDC_UNIT);
        assertEq(weth.balanceOf(address(vault)), 0.0125 ether);
        assertEq(vault.spentOnDay(_today()), 50 * USDC_UNIT);
        assertTrue(vault.usedNonce(1) && vault.usedNonce(2));
    }

    function test_EmitsExecuted() public {
        Intent memory i = _approveIntent(1, 7);
        vm.expectEmit(true, true, false, true, address(vault));
        emit IObeliskVault.Executed(vault.hashIntent(i), agent, 7, _today(), 0);
        _exec(i, 0);
    }

    function test_DailyLimitResetsNextDay() public {
        _exec(_approveIntent(LIMIT_PER_DAY, 1), 0);
        _exec(_swapIntent(100 * USDC_UNIT, 2), 100 * USDC_UNIT);
        uint64 d0 = _today();
        vm.warp(block.timestamp + 1 days);
        assertEq(vault.spentOnDay(_today()), 0);
        _exec(_swapIntent(100 * USDC_UNIT, 3), 100 * USDC_UNIT);
        assertEq(vault.spentOnDay(d0), 100 * USDC_UNIT);
        assertEq(vault.spentOnDay(_today()), 100 * USDC_UNIT);
    }

    // ------------------------------------------------------------ rejections

    function test_RevertWhen_PolicyNotSet() public {
        vm.prank(owner);
        vault.setRules(bytes32(0), VKEY, _limits());
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        vm.expectRevert(ObeliskVault.PolicyNotSet.selector);
        vault.execute(i, sig, "", "");
    }

    function test_RevertWhen_Expired() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.warp(i.deadline + 1);
        vm.expectRevert(ObeliskVault.Expired.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_NonceReplayed() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vault.execute(i, sig, pv, "");
        vm.expectRevert(ObeliskVault.NonceUsed.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_ValueNonZero() public {
        Intent memory i = _approveIntent(1, 1);
        i.value = 1;
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.ValueNotAllowed.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_SelfCall() public {
        Intent memory i = _intent(address(vault), abi.encodeCall(vault.setAgent, (attacker, true)), 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.SelfCall.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_SignerNotRegistered() public {
        (, uint256 pk) = makeAddrAndKey("rogue");
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(pk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.AgentNotActive.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_AgentRevoked() public {
        vm.prank(owner);
        registry.revokeAgent(agent);
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.AgentNotActive.selector);
        vault.execute(i, sig, pv, "");
    }

    /// An agent registered globally but not chosen by this vault's owner is refused.
    function test_RevertWhen_AgentNotAllowedByVault() public {
        (address other, uint256 pk) = makeAddrAndKey("other-agent");
        vm.prank(owner);
        registry.registerAgent(other, MEASUREMENT);
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(pk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.AgentNotActive.selector);
        vault.execute(i, sig, pv, "");
    }

    /// Per-vault emergency brake: the owner revokes the agent without waiting for the global registry.
    function test_OwnerCanDisallowAgent() public {
        vm.expectEmit(true, false, false, true, address(vault));
        emit IObeliskVault.AgentSet(agent, false);
        vm.prank(owner);
        vault.setAgent(agent, false);
        assertFalse(vault.agentAllowed(agent));
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.AgentNotActive.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_MalformedSignature() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 3));
        vault.execute(i, hex"010203", pv, "");
    }

    function test_RevertWhen_ProofInvalid() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(MockVerifier.InvalidProof.selector);
        vault.execute(i, sig, pv, hex"deadbeef");
    }

    function test_RevertWhen_PolicyHashMismatch() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = abi.encode(PolicyOutput(keccak256("other"), vault.hashIntent(i), 0, 0, _today()));
        vm.expectRevert(ObeliskVault.PolicyMismatch.selector);
        vault.execute(i, sig, pv, "");
    }

    /// Prompt injection: the agent signs a malicious intent, but the proof was made for another intent.
    function test_RevertWhen_ProofForDifferentIntent() public {
        Intent memory honest = _swapIntent(50 * USDC_UNIT, 1);
        Intent memory evil = _intent(address(usdc), abi.encodeCall(usdc.transfer, (attacker, 500 * USDC_UNIT)), 1);
        bytes memory sig = _sign(agentPk, evil);
        bytes memory pv = _pv(honest, 50 * USDC_UNIT);
        vm.expectRevert(ObeliskVault.IntentMismatch.selector);
        vault.execute(evil, sig, pv, "");
        assertEq(usdc.balanceOf(attacker), 0);
    }

    function test_RevertWhen_ProofFromOtherDay() public {
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), 0, 0, _today() + 1));
        vm.expectRevert(ObeliskVault.WrongDay.selector);
        vault.execute(i, sig, pv, "");
    }

    /// A proof that claims a smaller spentBefore than the onchain record is refused.
    function test_RevertWhen_SpentBeforeUnderstated() public {
        _exec(_approveIntent(LIMIT_PER_DAY, 1), 0);
        _exec(_swapIntent(100 * USDC_UNIT, 2), 100 * USDC_UNIT);
        Intent memory i = _swapIntent(100 * USDC_UNIT, 3);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), 0, 100 * USDC_UNIT, _today()));
        vm.expectRevert(ObeliskVault.SpentMismatch.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_SpentDecreases() public {
        _exec(_approveIntent(LIMIT_PER_DAY, 1), 0);
        _exec(_swapIntent(100 * USDC_UNIT, 2), 100 * USDC_UNIT);
        Intent memory i = _approveIntent(1, 3);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = abi.encode(PolicyOutput(POLICY, vault.hashIntent(i), 100 * USDC_UNIT, 0, _today()));
        vm.expectRevert(ObeliskVault.SpentDecreased.selector);
        vault.execute(i, sig, pv, "");
    }

    function test_RevertWhen_TargetCallFails_StateRolledBack() public {
        // swap without approval → transferFrom fails → the whole tx reverts
        Intent memory i = _swapIntent(50 * USDC_UNIT, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 50 * USDC_UNIT);
        vm.expectRevert();
        vault.execute(i, sig, pv, "");
        assertFalse(vault.usedNonce(1));
        assertEq(vault.spentOnDay(_today()), 0);
    }

    /// A signature for another vault cannot be used on this vault.
    function test_RevertWhen_SignatureForOtherVault() public {
        ObeliskVault other = new ObeliskVault(owner, verifier, registry, POLICY, VKEY, _limits(), agent);
        Intent memory i = _approveIntent(1, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, other.typedIntentDigest(i));
        bytes memory pv = _pv(i, 0);
        vm.expectRevert(ObeliskVault.AgentNotActive.selector);
        vault.execute(i, abi.encodePacked(r, s, v), pv, "");
    }

    // ------------------------------------------------------------ owner

    function test_OwnerWithdraw() public {
        vm.prank(owner);
        vault.withdraw(address(usdc), owner, 500 * USDC_UNIT);
        assertEq(usdc.balanceOf(owner), 500 * USDC_UNIT);

        vm.deal(address(vault), 1 ether);
        vm.prank(owner);
        vault.withdraw(address(0), owner, 1 ether);
        assertEq(owner.balance, 1 ether);
    }

    function test_RevertWhen_NonOwnerAdmin() public {
        vm.startPrank(attacker);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.withdraw(address(usdc), attacker, 1);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.setRules(bytes32(0), bytes32(0), _limits());
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, attacker));
        vault.setAgent(attacker, true);
        vm.stopPrank();
    }

    // ------------------------------------------------------------ fuzz

    /// Changing any field of a signed intent must fail.
    function testFuzz_TamperedIntentRejected(uint8 field, uint256 delta) public {
        delta = bound(delta, 1, type(uint64).max);
        Intent memory i = _swapIntent(50 * USDC_UNIT, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = _pv(i, 50 * USDC_UNIT);

        field = field % 4;
        if (field == 0) i.target = address(uint160(i.target) ^ uint160(delta));
        else if (field == 1) i.data = abi.encodePacked(i.data, bytes1(uint8(delta)));
        else if (field == 2) i.nonce += delta;
        else i.deadline -= uint64(bound(delta, 1, 1 hours));

        vm.expectRevert();
        vault.execute(i, sig, pv, "");
    }

    function testFuzz_DayAndSpentMustMatch(uint64 dayOffset, uint256 spentBefore) public {
        dayOffset = dayOffset % 1000;
        vm.assume(dayOffset != 0 || spentBefore != 0);
        Intent memory i = _approveIntent(1, 1);
        bytes memory sig = _sign(agentPk, i);
        bytes memory pv = abi.encode(
            PolicyOutput(POLICY, vault.hashIntent(i), spentBefore, spentBefore, _today() + dayOffset)
        );
        vm.expectRevert();
        vault.execute(i, sig, pv, "");
    }

    function testFuzz_HashIntentBindsChain(uint64 chainId) public {
        vm.assume(chainId != block.chainid && chainId != 0);
        Intent memory i = _approveIntent(1, 1);
        bytes32 h = vault.hashIntent(i);
        vm.chainId(chainId);
        assertTrue(vault.hashIntent(i) != h);
    }
}
