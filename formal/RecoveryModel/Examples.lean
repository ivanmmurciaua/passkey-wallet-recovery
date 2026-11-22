import RecoveryModel.Model
import RecoveryModel.Theorems
import RecoveryModel.WebAuthn

/-
  Executable scenarios with a toy instantiation, mirroring test/RecoveryAuthorityModule.ts.
  They are checked at build time with `#guard`. The toy signature is σ = (signer, digest), so a
  signature is valid exactly when it was "made" by that signer over that digest.
-/
namespace RecoveryModel.Examples

open RecoveryModel

abbrev Digest := Nat × Config
abbrev Sig := Nat × Digest

def toy : Params Nat Sig Digest where
  minDelay := 60
  digest n c := (n, c)
  valid s h σ := decide (σ = (s, h))
  digest_inj n m c d h := by simp only [Prod.mk.injEq] at h; exact h

def cA : Config := ⟨1, 2, 3⟩   -- passkey A
def cB : Config := ⟨11, 22, 3⟩ -- passkey B
def R : Nat := 7               -- recovery authority
def X : Nat := 9               -- someone else
def sigR (n : Nat) (c : Config) : Sig := (R, (n, c))

def s0 : St Nat := init cA true

-- Request at t=1000 with Δ = 3600; execute at 1001 reverts, at 4600 succeeds.
def happy : List (Nat × Act Nat Sig) :=
  [(0, .setup R 3600), (1000, .request cB (sigR 0 cB)), (1001, .execute), (4600, .execute)]
#guard outcomes toy s0 happy == [true, true, false, true]
#guard (run toy s0 happy).config == cB
#guard usedNonces toy s0 happy == [0]

-- Delay below minDelay is rejected.
#guard outcomes toy s0 [(0, .setup R 59)] == [false]

-- A signature is single-use; a signature by someone else is rejected.
def replay : List (Nat × Act Nat Sig) :=
  [(0, .setup R 3600), (10, .request cB (sigR 0 cB)), (4000, .execute),
   (4001, .request cB (sigR 0 cB)), (4002, .request cA (X, (1, cA)))]
#guard outcomes toy s0 replay == [true, true, true, false, false]

-- Cancel blocks execute, even after the delay.
def cancelled : List (Nat × Act Nat Sig) :=
  [(0, .setup R 3600), (10, .request cB (sigR 0 cB)), (20, .cancel), (9999, .execute)]
#guard outcomes toy s0 cancelled == [true, true, true, false]
#guard (run toy s0 cancelled).config == cA

-- One pending at a time; replacing the authority drops it; after disable, requests revert.
def oneAtATime : List (Nat × Act Nat Sig) :=
  [(0, .setup R 3600), (10, .request cB (sigR 0 cB)), (11, .request cA (sigR 1 cA)),
   (12, .setup X 3600), (9999, .execute), (10000, .disable), (10001, .request cB (X, (1, cB)))]
#guard outcomes toy s0 oneAtATime == [true, true, false, true, false, true, false]

-- Module not enabled: execute reverts.
#guard outcomes toy (init cA false) [(0, .setup R 3600), (10, .request cB (sigR 0 cB)), (9999, .execute)]
  == [true, true, false]

end RecoveryModel.Examples

-- Which axioms the main theorems rely on (only Lean's standard ones are expected).
#print axioms RecoveryModel.passkey_changes_only_as_authorized
#print axioms RecoveryModel.usedNonces_strictly_increasing
#print axioms RecoveryModel.execute_succeeds
#print axioms RecoveryModel.cancel_blocks_execute

-- base64url vectors computed with Node (Buffer.toString("base64url"), RFC 4648 §5, no padding).
#guard RecoveryModel.WebAuthn.encode [] == RecoveryModel.WebAuthn.ascii ""
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode []) == []
#guard RecoveryModel.WebAuthn.encode [0] == RecoveryModel.WebAuthn.ascii "AA"
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode [0]) == [0]
#guard RecoveryModel.WebAuthn.encode [255,254] == RecoveryModel.WebAuthn.ascii "__4"
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode [255,254]) == [255,254]
#guard RecoveryModel.WebAuthn.encode [1,2,3] == RecoveryModel.WebAuthn.ascii "AQID"
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode [1,2,3]) == [1,2,3]
#guard RecoveryModel.WebAuthn.encode [251,255,191] == RecoveryModel.WebAuthn.ascii "-_-_"
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode [251,255,191]) == [251,255,191]
#guard RecoveryModel.WebAuthn.encode [11,48,85,122,159,196,233,14,51,88,125,162,199,236,17,54,91,128,165,202,239,20,57,94,131,168,205,242,23,60,97,134] == RecoveryModel.WebAuthn.ascii "CzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYY"
#guard RecoveryModel.WebAuthn.decode (RecoveryModel.WebAuthn.encode [11,48,85,122,159,196,233,14,51,88,125,162,199,236,17,54,91,128,165,202,239,20,57,94,131,168,205,242,23,60,97,134]) == [11,48,85,122,159,196,233,14,51,88,125,162,199,236,17,54,91,128,165,202,239,20,57,94,131,168,205,242,23,60,97,134]

#print axioms RecoveryModel.WebAuthn.assertion_binds_one_digest
#print axioms RecoveryModel.WebAuthn.assertion_meaning
#print axioms RecoveryModel.WebAuthn.decode_encode
