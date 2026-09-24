// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {Intent, PolicyOutput} from "../src/interfaces/IObeliskVault.sol";

/// @notice Checks that the Solidity encoding matches zk/lib (Rust) through vectors.json.
contract VectorsTest is Test {
    using stdJson for string;

    string json;

    function setUp() public {
        json = vm.readFile("test/fixtures/vectors.json");
    }

    function test_IntentHashMatchesRust() public {
        vm.chainId(json.readUint(".input.chainId"));
        address vaultAddr = json.readAddress(".input.vault");
        deployCodeTo("ObeliskVault.sol:ObeliskVault", abi.encode(address(1), address(2), address(3), bytes32(0), bytes32(0), address(0)), vaultAddr);

        Intent memory i = Intent({
            target: json.readAddress(".input.intent.target"),
            value: json.readUint(".input.intent.value"),
            data: json.readBytes(".input.intent.data"),
            nonce: json.readUint(".input.intent.nonce"),
            deadline: uint64(json.readUint(".input.intent.deadline"))
        });
        assertEq(ObeliskVault(payable(vaultAddr)).hashIntent(i), json.readBytes32(".intentHash"));
    }

    function test_PolicyHashMatchesRust() public view {
        bytes32 h = keccak256(
            abi.encode(
                uint8(json.readUint(".input.policy.version")),
                json.readAddress(".input.policy.token"),
                json.readUint(".input.policy.maxPerTx"),
                json.readUint(".input.policy.maxPerDay"),
                json.readAddressArray(".input.policy.allowedTargets"),
                json.readAddressArray(".input.policy.allowedRecipients"),
                _bytes4Array(json.readUintArray(".input.policy.allowedSelectors")),
                json.readBool(".input.policy.denyUnlimitedApprove"),
                json.readAddressArray(".input.policy.allowedTokensOut")
            )
        );
        assertEq(h, json.readBytes32(".policyHash"));
    }

    function test_PublicValuesDecode() public view {
        PolicyOutput memory o = abi.decode(json.readBytes(".publicValues"), (PolicyOutput));
        assertEq(o.policyHash, json.readBytes32(".policyHash"));
        assertEq(o.intentHash, json.readBytes32(".intentHash"));
        assertEq(o.spentBefore, 100e6);
        assertEq(o.spentAfter, 150e6);
        assertEq(o.day, json.readUint(".input.day"));
    }

    function _bytes4Array(uint256[] memory a) internal pure returns (bytes4[] memory r) {
        r = new bytes4[](a.length);
        for (uint256 k; k < a.length; k++) r[k] = bytes4(uint32(a[k]));
    }
}
