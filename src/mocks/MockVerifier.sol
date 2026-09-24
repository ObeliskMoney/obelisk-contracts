// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISP1Verifier} from "../interfaces/ISP1Verifier.sol";

/// @notice Mirrors SP1MockVerifier: a proof is valid only if empty. For dev and tests ONLY.
contract MockVerifier is ISP1Verifier {
    error InvalidProof();

    function verifyProof(bytes32, bytes calldata, bytes calldata proofBytes) external pure {
        if (proofBytes.length != 0) revert InvalidProof();
    }
}
