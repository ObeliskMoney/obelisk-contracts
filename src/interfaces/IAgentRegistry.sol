// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAgentRegistry {
    event AgentRegistered(address indexed agentKey, bytes32 indexed codeMeasurement);
    event AgentRevoked(address indexed agentKey);

    function registerAgent(address agentKey, bytes32 codeMeasurement) external;
    function revokeAgent(address agentKey) external;
    function isActive(address agentKey) external view returns (bool);
    function measurementOf(address agentKey) external view returns (bytes32);
}
