// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {IAgentRegistry} from "../src/interfaces/IAgentRegistry.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract AgentRegistryTest is Test {
    AgentRegistry reg;
    address owner = makeAddr("owner");
    address agent = makeAddr("agent");
    bytes32 constant M = keccak256("m");

    function setUp() public {
        reg = new AgentRegistry(owner);
    }

    function test_RegisterAndRevoke() public {
        vm.expectEmit(true, true, false, false);
        emit IAgentRegistry.AgentRegistered(agent, M);
        vm.prank(owner);
        reg.registerAgent(agent, M);
        assertTrue(reg.isActive(agent));
        assertEq(reg.measurementOf(agent), M);

        vm.prank(owner);
        reg.revokeAgent(agent);
        assertFalse(reg.isActive(agent));
        assertEq(reg.measurementOf(agent), M);
    }

    function test_RevertWhen_ReRegisterRevoked() public {
        vm.startPrank(owner);
        reg.registerAgent(agent, M);
        reg.revokeAgent(agent);
        vm.expectRevert(AgentRegistry.AlreadyRegistered.selector);
        reg.registerAgent(agent, M);
    }

    function test_RevertWhen_BadInputs() public {
        vm.startPrank(owner);
        vm.expectRevert(AgentRegistry.ZeroAgent.selector);
        reg.registerAgent(address(0), M);
        vm.expectRevert(AgentRegistry.ZeroMeasurement.selector);
        reg.registerAgent(agent, bytes32(0));
        vm.expectRevert(AgentRegistry.NotActive.selector);
        reg.revokeAgent(agent);
    }

    function testFuzz_OnlyOwner(address caller) public {
        vm.assume(caller != owner);
        vm.startPrank(caller);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        reg.registerAgent(agent, M);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, caller));
        reg.revokeAgent(agent);
    }
}
