// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice SP1 verifier interface (same as succinctlabs/sp1-contracts).
interface ISP1Verifier {
    /// @dev Reverts if the proof is invalid.
    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
}
