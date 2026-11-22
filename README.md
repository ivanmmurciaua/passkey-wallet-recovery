# passkey-wallet-recovery

Recoverable passkey smart wallets: rotate a lost WebAuthn signer without the old device, keeping the same address and funds. Pluggable recovery authority, P-256 precompile, post-quantum path.

> **Status: proof of concept, unaudited, testnet only.** Do not use it with real funds.

---

## The idea

A passkey is a great signer for a smart wallet: the private key never leaves the authenticator and every signature needs a user gesture. Its weak point is loss. A passkey that is lost, or that was never synced, does not come back.

What can be recovered is the **account**, not the credential: the wallet rotates its authorized signer on-chain to a new passkey. The address does not change, so the funds stay where they are and the new passkey controls them.

## What is proven today (phase F1)

Validated end to end on **Sepolia** on 2026-11-15 (Safe 1.4.1) and again on 2026-11-22 on **Safe 1.5.0** ([tx](https://sepolia.etherscan.io/tx/0x1dea46b53eba9454d0bedbfb9abadb2d2d0ea876b1b3e26716b735ac45bfd1af)):

1. Passkey A creates and deploys a Safe whose owner is the `SafeWebAuthnSharedSigner`, and enables a `RecoveryModule`.
2. A recovery key is registered in the module for that Safe.
3. Passkey A is "lost". A new passkey B is created and the recovery key signs an EIP-712 authorization. The module rewrites the passkey coordinates stored in the Safe. **Passkey A signs nothing.**
4. The on-chain configuration holds passkey B's coordinates.
5. Passkey B loads the **original** Safe (same address).
6. Passkey B signs a real UserOperation on that Safe, sponsored by a paymaster ([tx](https://sepolia.etherscan.io/tx/0x9ddf9839b7fd7b57500a032eed4cd12aa48994c629304a6fd3a85abe9ca8a98b)).

Recovery works from a fresh session: with only the encrypted backup of the recovery key and its password, step 3 finds the Safe on its own from the module's `RecoverySetup(safe, recoveryKey)` events and rotates it. The address of the Safe does not need to be remembered.

Signature verification goes through the **P256VERIFY precompile** (`0x0100`), with the Solidity Daimo verifier only as a fallback. This was checked by removing the fallback with a state override: validation still passes with the same gas.

## Architecture

```
Safe (v1.5.0, ERC-4337 via Safe4337Module v0.3.0, EntryPoint v0.7)
 └─ owner: SafeWebAuthnSharedSigner (singleton)
      └─ stores (x, y, verifiers) in the Safe's own storage
           verifiers = (0x0100 << 160) | DaimoP256Verifier   (precompile first, Solidity fallback)

RecoveryModule (enabled on the Safe)
 ├─ setupRecovery(recoveryKey)            called by the Safe
 └─ recover(safe, newX, newY, verifiers, sig)
      ├─ checks an EIP-712 signature of the registered recovery key (with nonce)
      └─ Safe.execTransactionFromModule(SharedSigner, configure(newX, newY, verifiers), DelegateCall)
```

`configure()` must run as a **DelegateCall** from the Safe: it writes to the Safe's own storage slot, not to the singleton's.

## Versions and addresses

Everything lives in one file, [`src/app/constants.ts`](src/app/constants.ts): versions, canonical addresses and the network registry (Ethereum Sepolia only, for now). The app, the scripts and the Hardhat config import from it; nothing else hardcodes an address or an RPC URL.

| Component | Version |
|---|---|
| Safe | 1.5.0 (adds the module guard needed to enforce a policy on UserOps) |
| Safe4337Module / SafeModuleSetup | 0.3.0 |
| Safe passkey module (SharedSigner, SignerFactory, Daimo verifier) | 0.2.1 |
| EntryPoint | 0.7 |
| `@safe-global/protocol-kit` / `relay-kit` | 8.0.11 / 6.1.5 |

```bash
npm run check:constants            # all networks
npm run check:constants -- sepolia # one network
```

It compares every address with the official Safe deployment registries, checks that each one has code on-chain, and sends a freshly signed P-256 vector to the P256VERIFY precompile. It fails loudly on any mismatch. Today the precompile answers on all three testnets.

## Run it

```bash
npm install
cp .env.local.example .env.local   # add your Pimlico API key
npm run build && npm run start
# open http://localhost:3000 (use localhost: WebAuthn requires a secure context)
```

The RecoveryModule is already deployed on Sepolia and registered in `constants.ts`. To use another network, deploy it there (`npx hardhat run scripts/deploy.ts --network <key>`, with `DEPLOYER_PRIVATE_KEY` funded on that network), add its address to the network entry and set `NEXT_PUBLIC_NETWORK`.

Then follow steps 1 to 6 in the page. Copy the recovery private key shown in step 2: it is needed in step 3 and is not stored anywhere.

## Lessons learned

- **DelegateCall, not Call.** `SharedSigner.configure()` writes to the caller's storage. Called with a plain CALL it configures the singleton itself and the Safe is unchanged.
- **Packed verifiers and the SDK.** protocol-kit 8 takes the passkey's `verifierAddress` as the full uint176 in both `configure()` and its shared-signer check. Passing the packed value at creation, and the value read on-chain after a rotation, works with the stock SDK. Older protocol-kit versions compared the stored value with a default verifier address, so a packed value never matched and needed a patch ([safe-core-sdk#1339](https://github.com/safe-global/safe-core-sdk/pull/1339)).
- **Precompile, not Solidity.** Verifying P-256 in Solidity (FCL/Daimo) costs ~200K+ gas and caused out-of-gas errors under bundler limits. With the precompile it is a few thousand.
- **Validation gas varies per signature.** The bundler estimates `verificationGasLimit` with a short dummy WebAuthn signature. Browsers may add an extra key to `clientDataJSON` (`"other_keys_can_be_added_here"`), and the longer real signature can exceed the estimate. The bundler then answers with a generic "Internal error". `src/lib/wallet.ts` adds a margin before the paymaster signs the gas limits.
- **Rotated Safes are loaded by address.** After a rotation, the counterfactual address computed from passkey B is a different Safe. The original one must be loaded with `loadExistingSafe(passkeyB, address)`.

## Roadmap

| Phase | Goal |
|---|---|
| F1 | Passkey rotation on a Safe, up to date, on Sepolia (done), plus an encrypted backup of the recovery key (done) |
| F2 | Recovery module with a pluggable recovery authority (EOA, second passkey, M-of-N guardians), a timelock and cancellation by the current signer |
| F3 | Assets and multichain: same address on several networks, module in the initial setup, rotation per network |
| F4 | Post-quantum recovery authority (hash-based and lattice verifiers) on any EVM chain |
| F5 | Native EIP-8141 account: passkey signer and post-quantum recovery in frames |

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
