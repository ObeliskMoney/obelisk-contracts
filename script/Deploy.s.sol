// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ObeliskVault} from "../src/ObeliskVault.sol";
import {AgentRegistry} from "../src/AgentRegistry.sol";
import {ObeliskVaultFactory} from "../src/ObeliskVaultFactory.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockSwapRouter} from "../src/mocks/MockSwapRouter.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {SP1Verifier as SP1VerifierV600} from "../src/sp1/v6.0.0/SP1VerifierGroth16.sol";
import {SP1Verifier as SP1VerifierV610} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";
import {IAgentRegistry} from "../src/interfaces/IAgentRegistry.sol";

/// @notice Deploy Obelisk. Two modes:
///   - dev/testnet: mock token and router (MockERC20, MockSwapRouter) are deployed too;
///   - real assets (mainnet): TOKEN/WETH/ROUTER are set; no mocks and no minting.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY   required
///   CHAIN_NAME             output file name in deployments/ (for example local, robinhood-testnet)
///   SP1_VERIFIER           address of an existing SP1 verifier (for example the official gateway), or
///   SP1_VERIFIER_VERSION   "v6.0.0" / "v6.1.0" → deploy our own SP1VerifierGroth16 (chains without a gateway, such as Robinhood)
///                          both empty = MockVerifier (dev)
///   PROGRAM_VKEY           output `zk/target/release/vkey`
///   VAULT_USDC             mock USDC minted to the demo vault (default 500 USDC, mock mode only)
///   TOKEN, WETH, ROUTER    real assets: the limited stablecoin, WETH, Uniswap SwapRouter02
///   QUOTER, TOKEN_SYMBOL, SWAP_FEE   Uniswap QuoterV2, token symbol (for example USDG), pool fee tier (for example 100)
contract Deploy is Script {
    using stdJson for string;

    uint256 constant MAX_PER_TX = 100e6;
    uint256 constant MAX_PER_DAY = 300e6;

    // kept in storage so run() does not hit stack-too-deep
    address verifier;
    AgentRegistry registry;
    ObeliskVault vault;
    ObeliskVaultFactory factory;
    address usdc;
    address weth;
    address router;
    address quoter;
    string symbol;
    uint24 swapFee;
    bool realAssets;
    bytes32 policyHash;
    bytes32 vkey;
    bool isMock;

    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address sp1 = vm.envOr("SP1_VERIFIER", address(0));
        string memory version = vm.envOr("SP1_VERIFIER_VERSION", string(""));
        vkey = vm.envBytes32("PROGRAM_VKEY");
        isMock = sp1 == address(0) && bytes(version).length == 0;

        vm.startBroadcast(pk);
        if (isMock) verifier = address(new MockVerifier());
        else if (sp1 != address(0)) verifier = sp1;
        else if (keccak256(bytes(version)) == keccak256("v6.0.0")) verifier = address(new SP1VerifierV600());
        else if (keccak256(bytes(version)) == keccak256("v6.1.0")) verifier = address(new SP1VerifierV610());
        else revert("unknown SP1_VERIFIER_VERSION");
        registry = new AgentRegistry(vm.addr(pk));
        factory = new ObeliskVaultFactory(ISP1Verifier(verifier), IAgentRegistry(address(registry)), vkey);
        usdc = vm.envOr("TOKEN", address(0));
        realAssets = usdc != address(0);
        if (realAssets) {
            weth = vm.envAddress("WETH");
            router = vm.envAddress("ROUTER");
            quoter = vm.envAddress("QUOTER");
            symbol = vm.envString("TOKEN_SYMBOL");
            swapFee = uint24(vm.envUint("SWAP_FEE"));
            require(usdc.code.length > 0 && weth.code.length > 0 && router.code.length > 0, "assets are not deployed on this chain");
        } else {
            usdc = address(new MockERC20("Obelisk Test USD", "USDC", 6));
            weth = address(new MockERC20("Obelisk Test ETH", "WETH", 18));
            router = address(new MockSwapRouter(1e18, 4000e6)); // 1 ETH = 4000 USDC, updated by the keeper
            symbol = "USDC";
            swapFee = 500;
        }
        policyHash = _policyHash();
        // Demo vault owned by the deployer; the agent can be allowed later with setAgent.
        vault = ObeliskVault(payable(factory.createVault(policyHash, vm.envOr("AGENT_ADDRESS", address(0)))));
        if (!realAssets) MockERC20(usdc).mint(address(vault), vm.envOr("VAULT_USDC", uint256(500e6)));
        vm.stopBroadcast();

        _write(vm.envOr("CHAIN_NAME", string("local")));
    }

    function _targets() internal view returns (address[] memory t) {
        t = new address[](1);
        t[0] = router;
    }

    function _tokensOut() internal view returns (address[] memory t) {
        t = new address[](1);
        t[0] = weth;
    }

    function _selectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](2);
        s[0] = 0x095ea7b3; // approve
        s[1] = 0x04e45aaf; // exactInputSingle
    }

    function _policyHash() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                uint8(2), usdc, MAX_PER_TX, MAX_PER_DAY, _targets(), new address[](0), _selectors(), true, _tokensOut()
            )
        );
    }

    function _policyJson() internal returns (string memory) {
        string memory p = "policy";
        p.serialize("version", uint256(2));
        p.serialize("token", usdc);
        p.serialize("maxPerTx", vm.toString(MAX_PER_TX));
        p.serialize("maxPerDay", vm.toString(MAX_PER_DAY));
        p.serialize("allowedTargets", _targets());
        p.serialize("allowedRecipients", new address[](0));
        string[] memory sel = new string[](2);
        sel[0] = "0x095ea7b3";
        sel[1] = "0x04e45aaf";
        p.serialize("allowedSelectors", sel);
        p.serialize("denyUnlimitedApprove", true);
        return p.serialize("allowedTokensOut", _tokensOut());
    }

    /// Write deployments/<chain>.json (read by the agent and executor).
    function _write(string memory chainName) internal {
        string memory policyJson = _policyJson();
        string memory o = "out";
        o.serialize("chainId", block.chainid);
        o.serialize("vault", address(vault));
        o.serialize("registry", address(registry));
        o.serialize("factory", address(factory));
        o.serialize("verifier", verifier);
        o.serialize("verifierKind", isMock ? string("mock") : string("sp1-groth16"));
        o.serialize("usdc", usdc);
        o.serialize("weth", weth);
        o.serialize("router", router);
        o.serialize("quoter", quoter);
        o.serialize("tokenSymbol", symbol);
        o.serialize("swapFee", uint256(swapFee));
        o.serialize("mockAssets", !realAssets);
        o.serialize("programVKey", vkey);
        o.serialize("policyHash", policyHash);
        o.serialize("startBlock", block.number);
        string memory out = o.serialize("policy", policyJson);
        string memory path = string.concat("deployments/", chainName, ".json");
        vm.writeJson(out, path);
        console.log("vault", address(vault));
        console.log("wrote", path);
    }
}

/// @notice Register the agent key after its attestation is verified offchain.
/// Env: DEPLOYER_PRIVATE_KEY, REGISTRY, AGENT_ADDRESS, CODE_MEASUREMENT
contract RegisterAgent is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        AgentRegistry(vm.envAddress("REGISTRY")).registerAgent(
            vm.envAddress("AGENT_ADDRESS"), vm.envBytes32("CODE_MEASUREMENT")
        );
        vm.stopBroadcast();
    }
}
