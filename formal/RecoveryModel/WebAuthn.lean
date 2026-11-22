/-
  T6: model of OpenZeppelin's `WebAuthn.verify` (utils/cryptography/WebAuthn.sol, v5.6.1), the check
  behind `ERC7913WebAuthnVerifier`, and the proof that a valid assertion is bound to exactly one digest.

  Bytes and ASCII strings are `List Nat` (each element < 256). The P-256 check and sha256 are kept
  abstract (`p256` and `sha256` parameters): their security is the cryptographic assumption.

  The verifier calls `WebAuthn.verify(abi.encodePacked(hash), auth, qx, qy)`, i.e. with
  `requireUV = true`, so the checks are:
    authenticatorData.length > 36,
    clientDataJSON[typeIndex .. +21] = `"type":"webauthn.get"`,
    clientDataJSON[challengeIndex .. +|e|] = e, with e = `"challenge":"` ++ base64url(hash) ++ `"`,
    flags (authenticatorData[32]) has UP and UV, and not (BS without BE),
    p256(sha256(authenticatorData ++ sha256(clientDataJSON)), r, s, qx, qy).
-/
namespace RecoveryModel.WebAuthn

/-! ## base64url (RFC 4648 §5, no padding), as in OpenZeppelin's `Base64.encodeURL` -/

/-- 6-bit value to ASCII: A-Z a-z 0-9 - _ -/
def alpha (v : Nat) : Nat :=
  if v < 26 then 65 + v
  else if v < 52 then 97 + (v - 26)
  else if v < 62 then 48 + (v - 52)
  else if v = 62 then 45 else 95

/-- ASCII to 6-bit value (inverse of `alpha` on its image). -/
def unalpha (c : Nat) : Nat :=
  if 65 ≤ c ∧ c < 91 then c - 65
  else if 97 ≤ c ∧ c < 123 then c - 97 + 26
  else if 48 ≤ c ∧ c < 58 then c - 48 + 52
  else if c = 45 then 62 else 63

theorem unalpha_alpha_fin : ∀ v : Fin 64, unalpha (alpha v.val) = v.val := by decide

theorem unalpha_alpha (v : Nat) (hv : v < 64) : unalpha (alpha v) = v :=
  unalpha_alpha_fin ⟨v, hv⟩

/-- Arithmetic core of one 3-byte group: splitting into four 6-bit digits and joining them back
  recovers the three bytes. -/
theorem group3 (a b c : Nat) (ha : a < 256) (hb : b < 256) (hc : c < 256) :
    let n := a * 65536 + b * 256 + c
    let m := n / 262144 % 64 * 262144 + n / 4096 % 64 * 4096 + n / 64 % 64 * 64 + n % 64
    m / 65536 = a ∧ m / 256 % 256 = b ∧ m % 256 = c := by
  intro n m
  have hm : m = n := by omega
  rw [hm]; omega

theorem group2 (a b : Nat) (ha : a < 256) (hb : b < 256) :
    let n := a * 65536 + b * 256
    let m := n / 262144 % 64 * 262144 + n / 4096 % 64 * 4096 + n / 64 % 64 * 64
    m / 65536 = a ∧ m / 256 % 256 = b := by
  intro n m
  have hm : m = n := by omega
  rw [hm]; omega

theorem group1 (a : Nat) (ha : a < 256) :
    let n := a * 65536
    let m := n / 262144 % 64 * 262144 + n / 4096 % 64 * 4096
    m / 65536 = a := by
  intro n m
  have hm : m = n := by omega
  rw [hm]; omega

/-- Encode bytes, 3 at a time; a final group of 2 or 1 bytes gives 3 or 2 characters (no padding). -/
def encode : List Nat → List Nat
  | a :: b :: c :: rest =>
      let n := a * 65536 + b * 256 + c
      alpha (n / 262144 % 64) :: alpha (n / 4096 % 64) :: alpha (n / 64 % 64) :: alpha (n % 64) :: encode rest
  | [a, b] =>
      let n := a * 65536 + b * 256
      [alpha (n / 262144 % 64), alpha (n / 4096 % 64), alpha (n / 64 % 64)]
  | [a] =>
      let n := a * 65536
      [alpha (n / 262144 % 64), alpha (n / 4096 % 64)]
  | [] => []

def decode : List Nat → List Nat
  | c0 :: c1 :: c2 :: c3 :: rest =>
      let n := unalpha c0 * 262144 + unalpha c1 * 4096 + unalpha c2 * 64 + unalpha c3
      n / 65536 :: n / 256 % 256 :: n % 256 :: decode rest
  | [c0, c1, c2] =>
      let n := unalpha c0 * 262144 + unalpha c1 * 4096 + unalpha c2 * 64
      [n / 65536, n / 256 % 256]
  | [c0, c1] =>
      let n := unalpha c0 * 262144 + unalpha c1 * 4096
      [n / 65536]
  | _ => []

def Bytes (l : List Nat) : Prop := ∀ x ∈ l, x < 256

theorem decode_encode : ∀ l : List Nat, Bytes l → decode (encode l) = l
  | a :: b :: c :: rest, hb => by
      have ha : a < 256 := hb a (by simp)
      have hb' : b < 256 := hb b (by simp)
      have hc : c < 256 := hb c (by simp)
      have hr : Bytes rest := fun x hx => hb x (by simp [hx])
      have ⟨g1, g2, g3⟩ := group3 a b c ha hb' hc
      simp only [encode, decode]
      rw [unalpha_alpha _ (Nat.mod_lt _ (by decide)), unalpha_alpha _ (Nat.mod_lt _ (by decide)),
        unalpha_alpha _ (Nat.mod_lt _ (by decide)), unalpha_alpha _ (Nat.mod_lt _ (by decide)),
        decode_encode rest hr, g1, g2, g3]
  | [a, b], hb => by
      have ha : a < 256 := hb a (by simp)
      have hb' : b < 256 := hb b (by simp)
      have ⟨g1, g2⟩ := group2 a b ha hb'
      simp only [encode, decode]
      rw [unalpha_alpha _ (Nat.mod_lt _ (by decide)), unalpha_alpha _ (Nat.mod_lt _ (by decide)),
        unalpha_alpha _ (Nat.mod_lt _ (by decide)), g1, g2]
  | [a], hb => by
      have ha : a < 256 := hb a (by simp)
      have g1 := group1 a ha
      simp only [encode, decode]
      rw [unalpha_alpha _ (Nat.mod_lt _ (by decide)), unalpha_alpha _ (Nat.mod_lt _ (by decide)), g1]
  | [], _ => rfl

/-- base64url is injective on byte strings. -/
theorem encode_injective {l₁ l₂ : List Nat} (h₁ : Bytes l₁) (h₂ : Bytes l₂)
    (h : encode l₁ = encode l₂) : l₁ = l₂ := by
  rw [← decode_encode l₁ h₁, ← decode_encode l₂ h₂, h]

/-- Length of the encoding as a function of the input length. -/
def encLen : Nat → Nat
  | n + 3 => 4 + encLen n
  | 2 => 3
  | 1 => 2
  | 0 => 0

theorem encode_length_eq : ∀ l : List Nat, (encode l).length = encLen l.length
  | _ :: _ :: _ :: r => by
      simp only [encode, List.length_cons, encode_length_eq r, encLen]; omega
  | [_, _] => rfl
  | [_] => rfl
  | [] => rfl

/-- The length of the encoding only depends on the length of the input. -/
theorem encode_length (l₁ l₂ : List Nat) (h : l₁.length = l₂.length) :
    (encode l₁).length = (encode l₂).length := by
  rw [encode_length_eq, encode_length_eq, h]

/-! ## The WebAuthn check -/

/-- ASCII codes of a string literal. -/
def ascii (s : String) : List Nat := s.toList.map Char.toNat

def slice (l : List Nat) (i n : Nat) : List Nat := (l.drop i).take n

/-- `"challenge":"` ++ base64url(challenge) ++ `"` -/
def expectedChallenge (challenge : List Nat) : List Nat :=
  ascii "\"challenge\":\"" ++ encode challenge ++ ascii "\""

structure Auth where
  r : Nat
  s : Nat
  challengeIndex : Nat
  typeIndex : Nat
  authenticatorData : List Nat
  clientDataJSON : List Nat

def typeOk (cdj : List Nat) (i : Nat) : Bool :=
  slice cdj i 21 == ascii "\"type\":\"webauthn.get\""

def challengeOk (cdj : List Nat) (i : Nat) (challenge : List Nat) : Bool :=
  let e := expectedChallenge challenge
  slice cdj i e.length == e

def flagsOk (flags : Nat) : Bool :=
  flags % 2 == 1 &&                                   -- UP
  flags / 4 % 2 == 1 &&                               -- UV (requireUV = true)
  (flags / 8 % 2 == 1 || flags / 16 % 2 == 0)          -- BS implies BE

/-- `ERC7913WebAuthnVerifier.verify(key = qx || qy, hash, auth)`, with the P-256 check and sha256
  abstract. -/
def verify (p256 : List Nat → Nat → Nat → Nat → Nat → Bool) (sha256 : List Nat → List Nat)
    (qx qy : Nat) (hash : List Nat) (a : Auth) : Bool :=
  decide (36 < a.authenticatorData.length) &&
  typeOk a.clientDataJSON a.typeIndex &&
  challengeOk a.clientDataJSON a.challengeIndex hash &&
  flagsOk (a.authenticatorData.getD 32 0) &&
  p256 (sha256 (a.authenticatorData ++ sha256 a.clientDataJSON)) a.r a.s qx qy

/-! ## T6 -/

variable {p256 : List Nat → Nat → Nat → Nat → Nat → Bool} {sha256 : List Nat → List Nat}

theorem challenge_binding {cdj : List Nat} {i : Nat} {h₁ h₂ : List Nat}
    (hb₁ : Bytes h₁) (hb₂ : Bytes h₂) (hl : h₁.length = h₂.length)
    (c₁ : challengeOk cdj i h₁ = true) (c₂ : challengeOk cdj i h₂ = true) : h₁ = h₂ := by
  simp only [challengeOk, beq_iff_eq] at c₁ c₂
  have hlen : (expectedChallenge h₁).length = (expectedChallenge h₂).length := by
    simp only [expectedChallenge, List.length_append, encode_length h₁ h₂ hl]
  rw [hlen] at c₁
  have he : expectedChallenge h₁ = expectedChallenge h₂ := c₁.symm.trans c₂
  simp only [expectedChallenge, List.append_assoc, List.append_cancel_left_eq,
    List.append_cancel_right_eq] at he
  exact encode_injective hb₁ hb₂ he

/-- T6 (binding). One WebAuthn assertion is valid for at most one digest: if the same `auth`
  verifies for two 32-byte digests, they are equal. So an assertion signed for one rotation cannot
  authorize another one (other passkey coordinates or another nonce give another digest). -/
theorem assertion_binds_one_digest {qx qy : Nat} {a : Auth} {h₁ h₂ : List Nat}
    (hb₁ : Bytes h₁) (hb₂ : Bytes h₂) (l₁ : h₁.length = 32) (l₂ : h₂.length = 32)
    (v₁ : verify p256 sha256 qx qy h₁ a = true) (v₂ : verify p256 sha256 qx qy h₂ a = true) :
    h₁ = h₂ := by
  simp only [verify, Bool.and_eq_true] at v₁ v₂
  exact challenge_binding hb₁ hb₂ (by omega) v₁.1.1.2 v₂.1.1.2

/-- T6 (what a valid assertion means). If it verifies for `hash`, then the P-256 key signed
  sha256(authenticatorData ++ sha256(clientDataJSON)) for a clientDataJSON that contains, at
  `challengeIndex`, exactly `"challenge":"` ++ base64url(hash) ++ `"`, declares type
  `webauthn.get`, and whose authenticator flags have the user present and user verified. With the
  unforgeability of P-256 and the collision resistance of sha256 (assumptions), only the holder of
  the passkey can have produced it, and it commits to `hash`. -/
theorem assertion_meaning {qx qy : Nat} {a : Auth} {hash : List Nat}
    (v : verify p256 sha256 qx qy hash a = true) :
    p256 (sha256 (a.authenticatorData ++ sha256 a.clientDataJSON)) a.r a.s qx qy = true ∧
    slice a.clientDataJSON a.challengeIndex (expectedChallenge hash).length = expectedChallenge hash ∧
    slice a.clientDataJSON a.typeIndex 21 = ascii "\"type\":\"webauthn.get\"" ∧
    (a.authenticatorData.getD 32 0) % 2 = 1 ∧ (a.authenticatorData.getD 32 0) / 4 % 2 = 1 := by
  simp only [verify, Bool.and_eq_true, typeOk, challengeOk, flagsOk, beq_iff_eq] at v
  obtain ⟨⟨⟨⟨_, ht⟩, hc⟩, ⟨⟨hup, huv⟩, _⟩⟩, hp⟩ := v
  exact ⟨hp, hc, ht, hup, huv⟩

end RecoveryModel.WebAuthn
