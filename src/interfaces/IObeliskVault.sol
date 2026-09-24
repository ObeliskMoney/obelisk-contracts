// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice See docs/spec.md §1.
struct Intent {
    address target;
    uint256 value;
    bytes data;
    uint256 nonce;
    uint64 deadline;
}

/// @notice Public values of the SP1 program. See docs/spec.md §4.
struct PolicyOutput {
    bytes32 policyHash;
    bytes32 intentHash;
    uint256 spentBefore;
    uint256 spentAfter;
    uint64 day;
}

interface IObeliskVault {
    event PolicyUpdated(bytes32 indexed policyHash, bytes32 indexed programVKey);
    event AgentSet(address indexed agent, bool allowed);
    event Executed(
        bytes32 indexed intentHash, address indexed agent, uint256 nonce, uint64 day, uint256 spentAfter
    );
    event Withdrawn(address indexed token, address indexed to, uint256 amount);

    function setPolicy(bytes32 policyHash, bytes32 programVKey) external;
    function setAgent(address agent, bool allowed) external;
    function execute(Intent calldata intent, bytes calldata agentSig, bytes calldata publicValues, bytes calldata proof)
        external
        returns (bytes memory result);
    function hashIntent(Intent calldata intent) external view returns (bytes32);
}
