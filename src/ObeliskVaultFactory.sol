// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ObeliskVault} from "./ObeliskVault.sol";
import {ISP1Verifier} from "./interfaces/ISP1Verifier.sol";
import {IAgentRegistry} from "./interfaces/IAgentRegistry.sol";

/// @title ObeliskVaultFactory
/// @notice Anyone can create their own vault with the policy of their choice.
///         The verifier, registry and SP1 program (vkey) are shared by every vault from this factory.
contract ObeliskVaultFactory {
    event VaultCreated(address indexed owner, address indexed vault, bytes32 policyHash, address agent);

    ISP1Verifier public immutable verifier;
    IAgentRegistry public immutable registry;
    bytes32 public immutable programVKey;

    address[] public allVaults;
    mapping(address owner => address[]) private _vaultsOf;

    constructor(ISP1Verifier verifier_, IAgentRegistry registry_, bytes32 programVKey_) {
        verifier = verifier_;
        registry = registry_;
        programVKey = programVKey_;
    }

    /// @param policyHash policy hash (docs/spec.md §2); the policy JSON is registered with the agent API.
    /// @param agent agent allowed right away (may be address(0) and set later).
    function createVault(bytes32 policyHash, address agent) external returns (address vault) {
        vault = address(new ObeliskVault(msg.sender, verifier, registry, policyHash, programVKey, agent));
        allVaults.push(vault);
        _vaultsOf[msg.sender].push(vault);
        emit VaultCreated(msg.sender, vault, policyHash, agent);
    }

    function vaultsOf(address owner) external view returns (address[] memory) {
        return _vaultsOf[owner];
    }

    function vaultCount() external view returns (uint256) {
        return allVaults.length;
    }
}
