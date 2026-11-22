# Formal model of the recovery module (Lean 4)

Machine-checked model of `contracts/RecoveryAuthorityModule.sol` for one Safe, with proofs of its
main safety properties. Build:

```bash
cd formal
lake build   # needs elan; the Lean version is pinned in lean-toolchain
```

A successful build means every theorem is proven (there is no `sorry`) and every executable scenario
in `RecoveryModel/Examples.lean` matches the expected outcomes. The build also prints which axioms
the main theorems use: only Lean's standard axioms (`propext`, `Quot.sound` and, for T6,
`Classical.choice`). No `sorry`, no `native_decide`.

## Files

| File | Content |
|---|---|
| `RecoveryModel/Model.lean` | State, actions (`setup`, `disable`, `request`, `cancel`, `execute`), the `step` function mirroring the Solidity checks, traces (`run`, `outcomes`, `usedNonces`) and reachable states |
| `RecoveryModel/Theorems.lean` | The theorems below |
| `RecoveryModel/WebAuthn.lean` | Model of OpenZeppelin's `WebAuthn.verify` (behind `ERC7913WebAuthnVerifier`), base64url encoder and decoder, and T6 |
| `RecoveryModel/Examples.lean` | Executable scenarios mirroring `test/RecoveryAuthorityModule.ts`, and base64url test vectors checked against Node |
| `RecoveryModel/SepoliaTraces.lean` | The end-to-end runs of the UI on Sepolia (both authority kinds), replayed from the module events: the model accepts exactly the calls that succeeded on-chain, refuses the ones the page blocked, and ends in the same nonce, pending rotation and passkey config |

## Theorems

| # | Statement | Lean name |
|---|---|---|
| T1 | In any reachable state, a call that changes the passkey is an `execute` of the pending rotation, at least `delay >= minDelay` after its request, still backed by the authority registered at that moment, which produced a valid signature over (nonce, new passkey) | `passkey_changes_only_as_authorized` |
| T2 | The nonces consumed by the successful requests of any trace are strictly increasing; with collision resistance, no signed digest is accepted twice | `usedNonces_strictly_increasing`, `distinct_nonces_distinct_digests` |
| T3 | A request only succeeds when nothing is pending | `request_needs_no_pending` |
| T4 | Replacing or disabling the authority drops the pending rotation; after a cancel, `execute` reverts | `setup_drops_pending`, `disable_drops_pending`, `cancel_blocks_execute` |
| T5 | A pending rotation whose delay has elapsed can always be executed (module enabled), and yields exactly the requested passkey; before that, `execute` reverts | `execute_succeeds`, `execute_too_early` |
| T6 | WebAuthn: base64url is injective (decode after encode is the identity); a valid assertion verifies for at most one 32-byte digest, so an assertion signed for one rotation cannot authorize another; and a valid assertion means the P-256 key signed `sha256(authenticatorData ++ sha256(clientDataJSON))` for a clientDataJSON with type `webauthn.get`, the challenge `"challenge":"` ++ base64url(digest) ++ `"` at `challengeIndex`, and flags user-present and user-verified | `decode_encode`, `encode_injective`, `assertion_binds_one_digest`, `assertion_meaning` |

## Assumptions (not proven here)

- Unforgeability of the authority's signatures: T1 proves that a *valid* signature exists; that only
  the authority can produce one is the cryptographic assumption (ECDSA on secp256k1 / P-256). In
  T6 the P-256 check and sha256 are abstract functions for the same reason.
- Collision resistance of the EIP-712 digest, abstracted as `Params.digest_inj`.
- Correct EVM semantics of `execTransactionFromModule` and of `SharedSigner.configure` through
  DelegateCall, abstracted as the `config` field.
- The model is checked against the contract by tests (same scenarios), not yet against its bytecode.
- The WebAuthn model follows OpenZeppelin 5.6.1 `WebAuthn.verify` with `requireUV = true` (the
  variant `ERC7913WebAuthnVerifier` calls). Its byte-level parsing (`tryDecodeAuth`) is not modelled.

Note from T6: the verifier requires the UV flag, so a passkey used as a recovery authority must be
asked with `userVerification: "required"`.
