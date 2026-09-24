# Obelisk contracts

Solidity contracts for [Obelisk](https://obelisk.cash), an onchain vault for AI agents on Robinhood Chain mainnet.

A vault only executes an agent's transaction when it carries two things: an EIP-712 signature from an agent key the owner allowed (and that is active in `AgentRegistry`), and an SP1 Groth16 proof that the transaction follows the owner's policy. If either is missing or wrong, `execute` reverts. The owner can always withdraw.

> Beta. These contracts have not had a third-party audit. Deposit only what you can afford to lose.

## Contracts

| Contract | Role |
|---|---|
| [`ObeliskVault`](src/ObeliskVault.sol) | Holds funds. `execute` checks the agent signature, verifies the proof, checks every public value against its own state (policy hash, intent hash, day, daily spend), then makes the call. |
| [`ObeliskVaultFactory`](src/ObeliskVaultFactory.sol) | Anyone can create a vault with their own policy hash. Shares the verifier, registry and program key across vaults. A new policy program gets a new factory ([`DeployFactory.s.sol`](script/DeployFactory.s.sol)); existing vaults move to it with `setPolicy`. |
| [`AgentRegistry`](src/AgentRegistry.sol) | Records agent keys created in a TEE together with their code measurement. A revoked key can never be reactivated. |

The policy itself is checked inside the SP1 program, which lives in [obelisk-zk](https://github.com/ObeliskMoney/obelisk-zk).

## Mainnet (Robinhood Chain, chainId 4663)

| Contract | Address |
|---|---|
| ObeliskVaultFactory (policy v3) | `0x4530A51f8efB1A3Fc3d57e14db1965A1038Bb15c` |
| Earlier factory (policy v2, legacy) | `0xadDe5A5cF722Ef1e6a55fB15d84Fd4A9a71a2429` |
| AgentRegistry | `0xd79210b37c548584f87d66B07C8296db75678FE8` |
| SP1VerifierGroth16 v6.1.0 (Succinct) | `0x735A8EbC91e7ccC02A7275e13F4e02eab93cB5CA` |

Full deployment record: [`deployments/robinhood.json`](deployments/robinhood.json). Explorer: [explorer.mainnet.chain.robinhood.com](https://explorer.mainnet.chain.robinhood.com).

## Tests

```bash
forge test -vv
```

```bash
forge coverage --report summary --no-match-coverage "(test|mocks|script)"
```

- Unit tests for every revert path of `execute`, the factory and the registry
- Fuzz tests (1,000 runs each): tampered intents, fake day or spend, chain binding, `onlyOwner`
- Invariants (256 runs, depth 64): the attacker is never paid, and daily outflow equals `spentOnDay` and stays within the limit
- Cross-language vectors: `intentHash`, `policyHash` and the public values match the Rust program byte for byte
- A real Groth16 proof from the deployed policy program (v3), verified by Succinct's verifier contract, plus a gate that fails if the fixture and the deployed program ever differ

Solidity 0.8.28, EVM `cancun`, OpenZeppelin v5. Third-party code is vendored under `lib/` and `src/sp1/`.

## Related

- [ObeliskMoney/Obelisk](https://github.com/ObeliskMoney/Obelisk): the full system (agent, executor, website, docs, spec and threat model)
- [ObeliskMoney/obelisk-zk](https://github.com/ObeliskMoney/obelisk-zk): the SP1 policy program

## License

MIT
