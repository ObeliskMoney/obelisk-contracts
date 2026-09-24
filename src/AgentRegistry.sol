// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";

/// @title AgentRegistry
/// @notice Records agent keys born in a TEE, together with their code measurement.
/// @dev The attestation is verified offchain by the owner before registerAgent.
contract AgentRegistry is IAgentRegistry, Ownable2Step {
    error ZeroAgent();
    error ZeroMeasurement();
    error AlreadyRegistered();
    error NotActive();

    struct Agent {
        bytes32 codeMeasurement;
        bool active;
    }

    mapping(address => Agent) private _agents;

    constructor(address owner_) Ownable(owner_) {}

    function registerAgent(address agentKey, bytes32 codeMeasurement) external onlyOwner {
        if (agentKey == address(0)) revert ZeroAgent();
        if (codeMeasurement == bytes32(0)) revert ZeroMeasurement();
        // A revoked key can never be reactivated: a new TEE key means a new address.
        if (_agents[agentKey].codeMeasurement != bytes32(0)) revert AlreadyRegistered();
        _agents[agentKey] = Agent(codeMeasurement, true);
        emit AgentRegistered(agentKey, codeMeasurement);
    }

    function revokeAgent(address agentKey) external onlyOwner {
        if (!_agents[agentKey].active) revert NotActive();
        _agents[agentKey].active = false;
        emit AgentRevoked(agentKey);
    }

    function isActive(address agentKey) external view returns (bool) {
        return _agents[agentKey].active;
    }

    function measurementOf(address agentKey) external view returns (bytes32) {
        return _agents[agentKey].codeMeasurement;
    }
}
