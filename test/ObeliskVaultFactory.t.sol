// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base} from "./utils/Base.t.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {ObeliskVaultFactory} from "../src/ObeliskVaultFactory.sol";
import {Intent, PolicyOutput} from "../src/interfaces/IObeliskVault.sol";

contract ObeliskVaultFactoryTest is Base {
    ObeliskVaultFactory factory;
    address alice = makeAddr("alice");

    function setUp() public override {
        super.setUp();
        factory = new ObeliskVaultFactory(verifier, registry, VKEY);
    }

    function test_CreateVault() public {
        vm.expectEmit(true, false, false, false, address(factory));
        emit ObeliskVaultFactory.VaultCreated(alice, address(0), POLICY, agent);
        vm.prank(alice);
        ObeliskVault v = ObeliskVault(payable(factory.createVault(POLICY, agent)));

        assertEq(v.owner(), alice);
        assertEq(v.policyHash(), POLICY);
        assertEq(v.programVKey(), VKEY);
        assertTrue(v.agentAllowed(agent));
        assertEq(address(v.verifier()), address(verifier));
        assertEq(factory.vaultsOf(alice).length, 1);
        assertEq(factory.vaultCount(), 1);
    }

    function test_VaultFromFactoryExecutes() public {
        vm.prank(alice);
        ObeliskVault v = ObeliskVault(payable(factory.createVault(POLICY, agent)));
        usdc.mint(address(v), 100e6);

        Intent memory i = Intent({
            target: address(usdc),
            value: 0,
            data: abi.encodeCall(usdc.approve, (address(router), 10e6)),
            nonce: 1,
            deadline: uint64(block.timestamp + 1 hours)
        });
        (uint8 sv, bytes32 r, bytes32 s) = vm.sign(agentPk, v.typedIntentDigest(i));
        bytes memory pv = abi.encode(PolicyOutput(POLICY, v.hashIntent(i), 0, 0, _today()));
        v.execute(i, abi.encodePacked(r, s, sv), pv, "");
        assertEq(usdc.allowance(address(v), address(router)), 10e6);
    }

    function test_VaultWithoutAgentOrPolicy() public {
        vm.prank(alice);
        ObeliskVault v = ObeliskVault(payable(factory.createVault(bytes32(0), address(0))));
        assertEq(v.policyHash(), bytes32(0));
        assertFalse(v.agentAllowed(agent));
    }
}
