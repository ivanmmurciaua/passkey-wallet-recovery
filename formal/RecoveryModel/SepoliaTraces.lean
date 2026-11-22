import RecoveryModel.Model

/-
  The end-to-end runs of the F2b UI on Sepolia, replayed in the model.

  Each trace below is the sequence of `RecoveryAuthorityModule` events of one Safe, read from the
  chain, with the timestamp of the block that included it. The model must accept exactly the calls
  that succeeded on-chain, and its final state (nonce, pending `executeAfter`, passkey config) must
  match what the chain reports.

  Module: 0x7876874cbe72a016b34e3116aebf052fea2f4373 (MIN_DELAY = 60), Sepolia.

  Calls marked "UI-blocked" never reached the chain: the page checked the chain time or the pending
  rotation first and refused to send them. They are included because the model must predict the
  same refusal (a revert). Their timestamp is the chain time the page read, which is approximate.

  Signatures are not modelled byte by byte: a signature is the pair (signer, digest), as in
  `Examples.lean`. A request that succeeded on-chain is encoded with the authority's signature over
  the digest of the nonce it consumed (`RotationRequested.nonce`).
-/
namespace RecoveryModel.SepoliaTraces

open RecoveryModel

abbrev Digest := Nat × Config
abbrev Sig := Nat × Digest

/-- Toy instantiation with the deployed MIN_DELAY. -/
def sepolia : Params Nat Sig Digest where
  minDelay := 60
  digest n c := (n, c)
  valid s h σ := decide (σ = (s, h))
  digest_inj n m c d h := by simp only [Prod.mk.injEq] at h; exact h

/-- Packed verifiers used by every passkey: P256VERIFY precompile (0x0100) + Daimo fallback. -/
def V : Nat := 0x100c2b78104907f722dabac4c69f826a522b2754de4

def sig (signer n : Nat) (c : Config) : Sig := (signer, (n, c))

/-! ### Test A, first Safe: request, cancel by passkey A, request again (left pending) -/

def safe1A  : Config := ⟨0x131b894c7623ef1d3b438ccc8b308d4a7e36c5ae6485f52a24301f90f923a03e,
                         0xf716d0c3d555315bbfb38e289079c642a698f5b07f98932426e560e21413cf48, V⟩
def safe1B1 : Config := ⟨0x503181df7bdef23f01d51d34915f8124d44bdb2912bac5f0f4869e3595893a14,
                         0x014cb1926974d6662aad6855548fae36a83343cfbcb055106970b2341418d60a, V⟩
def safe1B2 : Config := ⟨0x0156008b3fbf6df69d0109a7e9cc3a4783362b905a5e72f7dfd9381a9af851b9,
                         0x72957fd892bb30632d1ff6bb09ff35efdc6f1b41b4af8f931da37bf6f4f1628c, V⟩
/-- Recovery key (address signer). -/
def safe1K : Nat := 0xFC933fcC3EeeD06653Ad098a6C9C869a4Cc9d40B

/-- Safe 0x1A3eCb2c592dFe257636cb7841310B9b72aB611F. -/
def safe1 : List (Nat × Act Nat Sig) :=
  [ (1795375260, .setup safe1K 120)                          -- RecoverySetup
  , (1795375572, .request safe1B1 (sig safe1K 0 safe1B1))    -- RotationRequested nonce 0
  , (1795375608, .cancel)                                    -- RotationCancelled
  , (1795376088, .request safe1B2 (sig safe1K 1 safe1B2))    -- RotationRequested nonce 1
  , (1795376088, .execute)                                   -- UI-blocked: "Too early: 120s left"
  , (1795376614, .request safe1B2 (sig safe1K 2 safe1B2)) ]  -- UI-blocked: rotation already pending
#guard outcomes sepolia (init safe1A true) safe1 == [true, true, true, true, false, false]
#guard usedNonces sepolia (init safe1A true) safe1 == [0, 1]
#guard (run sepolia (init safe1A true) safe1).nonce == 2
#guard (run sepolia (init safe1A true) safe1).pending.map (·.execAfter) == some 1795376208
#guard (run sepolia (init safe1A true) safe1).config == safe1A

/-! ### Test A: recovery key, rotated and executed -/

def safe2A : Config := ⟨0x0653035260e97f093c4aa3d7f2056f2ed11aa2329df5595a7c53c020faa3041f,
                        0xf04efe615e717f386bb0d12b0065702cc9ecfa36d99d92155d3f47a8a27ebaed, V⟩
def safe2B : Config := ⟨0xaefe9ca192a4ac33d4311acd6fa39fea233ee7d60f3fb763f8e081dc56095046,
                        0x2274a44fb536e0ef47a7f2dee1c5e0dab84e44c7fad4ed23c945a736a85b5633, V⟩
def safe2K : Nat := 0x78B919942c3bB97B281235556471B3121EEaDB0B

/-- Safe 0x259C923Caa701464B2c227404003b4075B4876ec. -/
def safe2 : List (Nat × Act Nat Sig) :=
  [ (1795376688, .setup safe2K 120)                        -- RecoverySetup
  , (1795376736, .request safe2B (sig safe2K 0 safe2B))    -- RotationRequested nonce 0
  , (1795376964, .execute) ]                               -- RotationExecuted
#guard outcomes sepolia (init safe2A true) safe2 == [true, true, true]
#guard (run sepolia (init safe2A true) safe2).config == safe2B
#guard (run sepolia (init safe2A true) safe2).pending.isNone
#guard (run sepolia (init safe2A true) safe2).nonce == 1

/-! ### Test B: passkey authority (ERC-7913 `verifier || qx || qy`), first Safe (left pending) -/

def safe3A : Config := ⟨0x24e2e86b5d18cf2b1a91088bb505b811cfecac220d9dc97ba6e910538dc53afc,
                        0x27083f55645c11c624b96e91dc209eacfd894fca4e745ad9b60c2132d52bf009, V⟩
def safe3B : Config := ⟨0x5600c4d61949db2037a11642ce583d874f7f3c3b0b4f139bba12d7a3e0e4a2f9,
                        0x80b71aebd2b451d70fa922906bc72010bf50e308267a6bc95e63ce37e45e8052, V⟩
/-- `recoverySigner` bytes (WebAuthnVerifier || qx || qy) read as a number. -/
def safe3R : Nat := 0xc252126da97330a30ec434ab5023f8c1efc065221683d248b1ae84a8b59dbd5d5b82002dfbdbda79958e4ce30f32f7845ce38e431fbf08ec6efc59bb5ca75af19051e767290c15a788049bdcc02b411a7ac84be9

/-- Safe 0xD7F80ef614cC1e96bEa88b77A380A6833Ee062Fe. -/
def safe3 : List (Nat × Act Nat Sig) :=
  [ (1795377228, .setup safe3R 120)                        -- RecoverySetup
  , (1795377348, .request safe3B (sig safe3R 0 safe3B)) ]  -- RotationRequested nonce 0
#guard outcomes sepolia (init safe3A true) safe3 == [true, true]
#guard (run sepolia (init safe3A true) safe3).pending.map (·.execAfter) == some 1795377468
#guard (run sepolia (init safe3A true) safe3).config == safe3A

/-! ### Test B: passkey authority, rotated and executed -/

def safe4A : Config := ⟨0xa1676c1f589a3018be48b60305944d7e462b009cb77ea8fb1c2f92b756753e2d,
                        0xf6ed7671be8ee757fce8c11adbcc260c9722896f112002d112234e91f48980f1, V⟩
def safe4B : Config := ⟨0x0c5e5173a514528d452c6a6da9afabf4ab24ed98a02f0fb4ddb0664fe370303f,
                        0x29d27816b622189f1891f121f6d36d9baff3b3f71fe9d60588e4f9d931d05ea5, V⟩
def safe4R : Nat := 0xc252126da97330a30ec434ab5023f8c1efc0652223931ef5a12b30ffeaea17fdc403b80b3c6f3c038b5f36d5d8b0dbcb23a9cd9e17af90e03f074cda70ee70868d735e25730ef86b137728d1f01f71fdbc6cd0e3

/-- Safe 0xb9A4Dd666dFa50EE5C7D47880564dFE087BCf0a5. -/
def safe4 : List (Nat × Act Nat Sig) :=
  [ (1795377528, .setup safe4R 120)                        -- RecoverySetup
  , (1795377576, .request safe4B (sig safe4R 0 safe4B))    -- RotationRequested nonce 0
  , (1795377660, .execute)                                 -- UI-blocked: "Too early: 36s left"
  , (1795377708, .execute) ]                               -- RotationExecuted
#guard outcomes sepolia (init safe4A true) safe4 == [true, true, false, true]
#guard (run sepolia (init safe4A true) safe4).config == safe4B
#guard (run sepolia (init safe4A true) safe4).pending.isNone

/-! ### Negative: a signature for the wrong nonce or by the other authority is rejected -/

#guard outcomes sepolia (init safe2A true)
  [(1795376688, .setup safe2K 120), (1795376736, .request safe2B (sig safe2K 1 safe2B))] == [true, false]
#guard outcomes sepolia (init safe4A true)
  [(1795377528, .setup safe4R 120), (1795377576, .request safe4B (sig safe3R 0 safe4B))] == [true, false]

end RecoveryModel.SepoliaTraces
