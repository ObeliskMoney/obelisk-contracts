// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {PolicyOutput} from "../src/interfaces/IObeliskVault.sol";

/// @notice A REAL Groth16 proof from the Obelisk policy program (made on a server, SP1 v6.1.0, about 34 CPU minutes)
///         verified by Succinct's official verifier contract. Fixture: test/fixtures/real-proof.json.
contract RealProofTest is Test {
    using stdJson for string;

    SP1Verifier verifier;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;

    function setUp() public {
        string memory j = vm.readFile("test/fixtures/real-proof.json");
        vkey = j.readBytes32(".vkey");
        publicValues = j.readBytes(".publicValues");
        proof = j.readBytes(".proof");
        verifier = new SP1Verifier();
    }

    function test_RealProofVerifies() public view {
        verifier.verifyProof(vkey, publicValues, proof);
        PolicyOutput memory o = abi.decode(publicValues, (PolicyOutput));
        assertEq(o.spentBefore, 100e6);
        assertEq(o.spentAfter, 150e6);
    }

    function test_RevertWhen_PublicValuesTampered() public {
        PolicyOutput memory o = abi.decode(publicValues, (PolicyOutput));
        o.spentAfter = 100e6; // the attacker tries to "hide" spending
        vm.expectRevert();
        verifier.verifyProof(vkey, abi.encode(o), proof);
    }

    function test_RevertWhen_WrongProgram() public {
        vm.expectRevert();
        verifier.verifyProof(bytes32(uint256(vkey) ^ 1), publicValues, proof);
    }

    function test_RevertWhen_ProofTampered() public {
        bytes memory p = proof;
        p[100] = bytes1(uint8(p[100]) ^ 0x01);
        vm.expectRevert();
        verifier.verifyProof(vkey, publicValues, p);
    }

    function test_GasCost() public {
        uint256 g = gasleft();
        verifier.verifyProof(vkey, publicValues, proof);
        emit log_named_uint("Groth16 verification gas", g - gasleft());
    }
}
