/-
  Executable model of `RecoveryAuthorityModule` (contracts/RecoveryAuthorityModule.sol), for ONE Safe.

  Every Safe has its own independent slot in the contract (all mappings are keyed by the Safe), so a
  single-Safe model is enough. Calls made "by the Safe" (setupRecovery, disableRecovery, cancel) are
  actions of this Safe; calls by anyone else touch other slots and are not modelled.

  Abstractions (the assumptions of the proofs):
  * `digest n c` stands for the EIP-712 digest of `Rotate(safe, x, y, verifiers, nonce = n)`.
    `Params.digest_inj` abstracts collision resistance of keccak256.
  * `valid s h σ` stands for the ERC-7913 check (ecrecover for an address signer, a verifier for
    `verifier || key`). Unforgeability is a hypothesis on `valid`, stated where it is used.
  * A reverted call leaves the state unchanged, so `step` returns `none` and traces skip it.
-/
namespace RecoveryModel

/-- Passkey configuration stored by the SharedSigner for the Safe: (x, y, verifiers). -/
structure Config where
  x : Nat
  y : Nat
  v : Nat
deriving DecidableEq, Repr

/-- A pending rotation. `requestedAt`, `delayAt`, `nonceUsed`, `signerAt` are ghost fields: they are
  not stored by the contract, but they record facts the proofs talk about. -/
structure Pending (Signer : Type) where
  cfg : Config
  execAfter : Nat
  requestedAt : Nat
  delayAt : Nat
  nonceUsed : Nat
  signerAt : Signer
deriving Repr

/-- Module state for one Safe, plus the Safe facts it depends on. -/
structure St (Signer : Type) where
  /-- `recoverySigner[safe]` (`none` = recovery disabled). -/
  signer : Option Signer
  /-- `recoveryDelay[safe]`. -/
  delay : Nat
  /-- `nonces[safe]`. -/
  nonce : Nat
  /-- `pendingRotation[safe]` (`executeAfter = 0` in Solidity is `none` here). -/
  pending : Option (Pending Signer)
  /-- The passkey configuration of the Safe (SharedSigner storage). -/
  config : Config
  /-- Whether this module is enabled on the Safe (needed by `execTransactionFromModule`). -/
  enabled : Bool
deriving Repr

inductive Act (Signer Sig : Type) where
  | setup (s : Signer) (d : Nat)
  | disable
  | request (c : Config) (σ : Sig)
  | cancel
  | execute
deriving Repr

structure Params (Signer Sig Digest : Type) where
  minDelay : Nat
  digest : Nat → Config → Digest
  valid : Signer → Digest → Sig → Bool
  /-- Collision resistance of the EIP-712 digest, abstracted as injectivity. -/
  digest_inj : ∀ n m c d, digest n c = digest m d → n = m ∧ c = d

variable {Signer Sig Digest : Type}

/-- One transaction at time `now`. `none` = the call reverts. Mirrors the Solidity checks. -/
def step (P : Params Signer Sig Digest) (now : Nat) (st : St Signer) :
    Act Signer Sig → Option (St Signer)
  | .setup s d =>
      if P.minDelay ≤ d then some { st with signer := some s, delay := d, pending := none } else none
  | .disable => some { st with signer := none, delay := 0, pending := none }
  | .request c σ =>
      match st.signer, st.pending with
      | some s, none =>
          if P.valid s (P.digest st.nonce c) σ then
            some { st with
              nonce := st.nonce + 1
              pending := some { cfg := c, execAfter := now + st.delay, requestedAt := now,
                                delayAt := st.delay, nonceUsed := st.nonce, signerAt := s } }
          else none
      | _, _ => none
  | .cancel =>
      match st.pending with
      | some _ => some { st with pending := none }
      | none => none
  | .execute =>
      match st.pending with
      | some p => if p.execAfter ≤ now ∧ st.enabled = true then some { st with config := p.cfg, pending := none } else none
      | none => none

/-- Run a trace of timestamped calls; reverted calls leave the state unchanged (as on-chain). -/
def run (P : Params Signer Sig Digest) : St Signer → List (Nat × Act Signer Sig) → St Signer
  | st, [] => st
  | st, (now, a) :: rest =>
      match step P now st a with
      | some st' => run P st' rest
      | none => run P st rest

/-- Outcome of each call of a trace (true = success, false = revert), to compare with a chain trace. -/
def outcomes (P : Params Signer Sig Digest) : St Signer → List (Nat × Act Signer Sig) → List Bool
  | _, [] => []
  | st, (now, a) :: rest =>
      match step P now st a with
      | some st' => true :: outcomes P st' rest
      | none => false :: outcomes P st rest

/-- Nonces consumed by the successful `request`s of a trace, in order. -/
def usedNonces (P : Params Signer Sig Digest) : St Signer → List (Nat × Act Signer Sig) → List Nat
  | _, [] => []
  | st, (now, a) :: rest =>
      match step P now st a with
      | some st' =>
          match a with
          | .request _ _ => st.nonce :: usedNonces P st' rest
          | _ => usedNonces P st' rest
      | none => usedNonces P st rest

/-- Initial state of a Safe before `setupRecovery`. -/
def init (c0 : Config) (enabled : Bool) : St Signer :=
  { signer := none, delay := 0, nonce := 0, pending := none, config := c0, enabled := enabled }

/-- States reachable from some initial state through successful calls. -/
inductive Reach (P : Params Signer Sig Digest) : St Signer → Prop
  | init (c0 : Config) (e : Bool) : Reach P (init c0 e)
  | step {st st' : St Signer} (now : Nat) (a : Act Signer Sig) :
      Reach P st → step P now st a = some st' → Reach P st'

end RecoveryModel
