// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ObeliskVaultFactory} from "../src/ObeliskVaultFactory.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {IAgentRegistry} from "../src/interfaces/IAgentRegistry.sol";

/// @notice Deploys a new vault factory for a new policy program, reusing the deployed verifier and registry.
///         Used when the SP1 program changes (new programVKey) but the contracts do not.
/// @dev Env:
///   CHAIN_NAME     deployments/<CHAIN_NAME>.json to update (for example robinhood)
///   PROGRAM_VKEY   the new program's verification key (zk/script: cargo run --release --bin vkey)
///   The broadcaster pays for one contract creation. On a real broadcast the deployment file gets the new
///   `factory` and `programVKey`, and the old factory moves to `legacyFactories` so its vaults stay listed.
contract DeployFactory is Script {
    using stdJson for string;

    function run() external returns (ObeliskVaultFactory factory) {
        string memory path = string.concat("deployments/", vm.envString("CHAIN_NAME"), ".json");
        string memory dep = vm.readFile(path);
        address verifier = dep.readAddress(".verifier");
        address registry = dep.readAddress(".registry");
        address oldFactory = dep.readAddress(".factory");
        bytes32 oldVKey = dep.readBytes32(".programVKey");
        bytes32 vkey = vm.envBytes32("PROGRAM_VKEY");

        require(verifier.code.length > 0, "verifier has no code on this chain");
        require(registry.code.length > 0, "registry has no code on this chain");
        require(block.chainid == dep.readUint(".chainId"), "wrong chain");
        require(vkey != bytes32(0), "PROGRAM_VKEY is empty");
        require(vkey != oldVKey, "PROGRAM_VKEY is the program the current factory already uses");

        vm.startBroadcast();
        factory = new ObeliskVaultFactory(ISP1Verifier(verifier), IAgentRegistry(registry), vkey);
        vm.stopBroadcast();

        require(factory.programVKey() == vkey, "factory programVKey mismatch");
        console2.log("factory      ", address(factory));
        console2.log("old factory  ", oldFactory);
        console2.logBytes32(vkey);

        // Only a real broadcast updates the deployment file, so a dry run can never be mistaken for a deploy.
        if (!vm.isContext(VmSafe.ForgeContext.ScriptBroadcast)) return factory;
        address[] memory legacy = dep.keyExists(".legacyFactories") ? dep.readAddressArray(".legacyFactories") : new address[](0);
        string memory list = string.concat("[\"", vm.toString(oldFactory), "\"");
        for (uint256 k; k < legacy.length; k++) {
            list = string.concat(list, ",\"", vm.toString(legacy[k]), "\"");
        }
        list = string.concat(list, "]");
        vm.writeJson(string.concat("\"", vm.toString(address(factory)), "\""), path, ".factory");
        vm.writeJson(string.concat("\"", vm.toString(vkey), "\""), path, ".programVKey");
        vm.writeJson(list, path, ".legacyFactories");
    }
}
