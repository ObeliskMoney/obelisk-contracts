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

// Contract version of ObeliskVault. 4 = onchain limits.
uint8 constant OBELISK_VAULT_VERSION = 4;

/// @notice Onchain limits (v4): a second copy of the spending rules that the vault checks itself, so a bug in the
///         SP1 program can at most spend what these limits allow. They must agree with the policy behind policyHash;
///         where they differ, the stricter one wins.
/// @param token the only asset the agent may spend (the policy token)
/// @param maxPerTx most `token` that may leave the vault in one execute
/// @param maxPerDay most `token` that may leave the vault per UTC day
/// @param routers exchanges the agent may swap through and approve (policy allowedTargets)
/// @param payees addresses the agent may transfer `token` to (policy allowedRecipients)
struct Limits {
    address token;
    uint256 maxPerTx;
    uint256 maxPerDay;
    address[] routers;
    address[] payees;
}

interface IObeliskVault {
    event PolicyUpdated(bytes32 indexed policyHash, bytes32 indexed programVKey);
    event AgentSet(address indexed agent, bool allowed);
    event Executed(
        bytes32 indexed intentHash, address indexed agent, uint256 nonce, uint64 day, uint256 spentAfter
    );
    event Withdrawn(address indexed token, address indexed to, uint256 amount);
    event LimitsUpdated(address indexed token, uint256 maxPerTx, uint256 maxPerDay, address[] routers, address[] payees);

    function setRules(bytes32 policyHash, bytes32 programVKey, Limits calldata limits) external;
    function setAgent(address agent, bool allowed) external;
    function execute(Intent calldata intent, bytes calldata agentSig, bytes calldata publicValues, bytes calldata proof)
        external
        returns (bytes memory result);
    function hashIntent(Intent calldata intent) external view returns (bytes32);
}
