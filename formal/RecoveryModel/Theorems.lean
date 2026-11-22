import RecoveryModel.Model

/-
  Theorems T1 to T5 about the model in `Model.lean` (one Safe). Notation used in the docs:
  Δ = per-Safe delay, t_req = time of the request, R = recovery authority (`signer`).
-/
namespace RecoveryModel

variable {Signer Sig Digest : Type} {P : Params Signer Sig Digest}

/-! ## Unfolding `step`, one lemma per action -/

theorem step_setup {now : Nat} {st st' : St Signer} {s : Signer} {d : Nat}
    (h : step P now st (Act.setup s d : Act Signer Sig) = some st') :
    P.minDelay ≤ d ∧ st' = { st with signer := some s, delay := d, pending := none } := by
  simp only [step] at h
  by_cases hd : P.minDelay ≤ d
  · simp [hd] at h; exact ⟨hd, h.symm⟩
  · simp [hd] at h

theorem step_disable {now : Nat} {st st' : St Signer}
    (h : step P now st (Act.disable : Act Signer Sig) = some st') :
    st' = { st with signer := none, delay := 0, pending := none } := by
  simp only [step] at h; simp at h; exact h.symm

theorem step_request {now : Nat} {st st' : St Signer} {c : Config} {σ : Sig}
    (h : step P now st (.request c σ) = some st') :
    ∃ s, st.signer = some s ∧ st.pending = none ∧ P.valid s (P.digest st.nonce c) σ = true ∧
      st' = { st with
        nonce := st.nonce + 1
        pending := some { cfg := c, execAfter := now + st.delay, requestedAt := now,
                          delayAt := st.delay, nonceUsed := st.nonce, signerAt := s } } := by
  simp only [step] at h
  cases hsg : st.signer with
  | none => simp [hsg] at h
  | some s =>
      cases hpd : st.pending with
      | some _ => simp [hsg, hpd] at h
      | none =>
          by_cases hv : P.valid s (P.digest st.nonce c) σ = true
          · simp [hsg, hpd, hv] at h; exact ⟨s, rfl, rfl, hv, h.symm⟩
          · simp [hsg, hpd, hv] at h

theorem step_cancel {now : Nat} {st st' : St Signer}
    (h : step P now st (Act.cancel : Act Signer Sig) = some st') :
    st.pending ≠ none ∧ st' = { st with pending := none } := by
  simp only [step] at h
  cases hpd : st.pending with
  | none => simp [hpd] at h
  | some _ => simp [hpd] at h; exact ⟨by simp, h.symm⟩

theorem step_execute {now : Nat} {st st' : St Signer}
    (h : step P now st (Act.execute : Act Signer Sig) = some st') :
    ∃ p, st.pending = some p ∧ p.execAfter ≤ now ∧ st.enabled = true ∧
      st' = { st with config := p.cfg, pending := none } := by
  simp only [step] at h
  cases hpd : st.pending with
  | none => simp [hpd] at h
  | some p =>
      by_cases hc : p.execAfter ≤ now ∧ st.enabled = true
      · simp [hpd, hc] at h
        refine ⟨p, rfl, hc.1, hc.2, ?_⟩
        rw [← h, hc.2]
      · simp [hpd, hc] at h

/-! ## Single-step properties -/

/-- Only `execute` can change the passkey configuration. -/
theorem config_changes_only_by_execute {now : Nat} {st st' : St Signer} {a : Act Signer Sig}
    (h : step P now st a = some st') (hc : st'.config ≠ st.config) : a = .execute := by
  cases a with
  | setup s d => obtain ⟨_, rfl⟩ := step_setup h; exact absurd rfl hc
  | disable => obtain rfl := step_disable h; exact absurd rfl hc
  | request c σ => obtain ⟨_, _, _, _, rfl⟩ := step_request h; exact absurd rfl hc
  | cancel => obtain ⟨_, rfl⟩ := step_cancel h; exact absurd rfl hc
  | execute => rfl

/-- T3: a `request` only succeeds when nothing is pending (at most one pending rotation). -/
theorem request_needs_no_pending {now : Nat} {st st' : St Signer} {c : Config} {σ : Sig}
    (h : step P now st (.request c σ) = some st') : st.pending = none := by
  obtain ⟨_, _, hp, _⟩ := step_request h; exact hp

/-- T4: replacing or disabling the authority drops the pending rotation. -/
theorem setup_drops_pending {now : Nat} {st st' : St Signer} {s : Signer} {d : Nat}
    (h : step P now st (Act.setup s d : Act Signer Sig) = some st') : st'.pending = none := by
  obtain ⟨_, rfl⟩ := step_setup h; rfl

theorem disable_drops_pending {now : Nat} {st st' : St Signer}
    (h : step P now st (Act.disable : Act Signer Sig) = some st') : st'.pending = none := by
  obtain rfl := step_disable h; rfl

/-- After a successful `cancel` nothing is pending, so `execute` reverts at any time. -/
theorem cancel_blocks_execute {now now' : Nat} {st st' : St Signer}
    (h : step P now st (Act.cancel : Act Signer Sig) = some st') :
    step P now' st' (Act.execute : Act Signer Sig) = none := by
  obtain ⟨_, rfl⟩ := step_cancel h; simp [step]

/-- `execute` before `execAfter` reverts. -/
theorem execute_too_early {now : Nat} {st : St Signer} {p : Pending Signer}
    (hp : st.pending = some p) (ht : now < p.execAfter) :
    step P now st (Act.execute : Act Signer Sig) = none := by
  simp [step, hp]; omega

/-- T2 (local): a successful `request` checks the authority over the digest with the CURRENT nonce
  and consumes it. -/
theorem request_consumes_nonce {now : Nat} {st st' : St Signer} {c : Config} {σ : Sig}
    (h : step P now st (.request c σ) = some st') :
    st'.nonce = st.nonce + 1 ∧ ∃ s, st.signer = some s ∧ P.valid s (P.digest st.nonce c) σ = true := by
  obtain ⟨s, hs, _, hv, rfl⟩ := step_request h
  exact ⟨rfl, s, hs, hv⟩

/-- The nonce never decreases. -/
theorem nonce_mono {now : Nat} {st st' : St Signer} {a : Act Signer Sig}
    (h : step P now st a = some st') : st.nonce ≤ st'.nonce := by
  cases a with
  | setup s d => obtain ⟨_, rfl⟩ := step_setup h; exact Nat.le_refl _
  | disable => obtain rfl := step_disable h; exact Nat.le_refl _
  | request c σ => obtain ⟨_, _, _, _, rfl⟩ := step_request h; exact Nat.le_succ _
  | cancel => obtain ⟨_, rfl⟩ := step_cancel h; exact Nat.le_refl _
  | execute => obtain ⟨_, _, _, _, rfl⟩ := step_execute h; exact Nat.le_refl _

/-- T5 (liveness): a pending rotation whose delay has elapsed can always be executed, by anyone,
  as long as the module is enabled; the result is exactly the requested configuration. -/
theorem execute_succeeds {now : Nat} {st : St Signer} {p : Pending Signer}
    (hp : st.pending = some p) (ht : p.execAfter ≤ now) (he : st.enabled = true) :
    ∃ st', step P now st (Act.execute : Act Signer Sig) = some st' ∧
      st'.config = p.cfg ∧ st'.pending = none :=
  ⟨{ st with config := p.cfg, pending := none }, by simp [step, hp, ht, he], rfl, rfl⟩

/-! ## Invariant of reachable states -/

/-- What every reachable state satisfies:
  1. an active authority comes with a delay of at least `minDelay`;
  2. a pending rotation was requested `delayAt ≥ minDelay` before its `execAfter`, by the authority
     that is STILL registered, over the digest of a nonce that is already consumed. -/
def Inv (P : Params Signer Sig Digest) (st : St Signer) : Prop :=
  (∀ s, st.signer = some s → P.minDelay ≤ st.delay) ∧
  (∀ p, st.pending = some p →
      p.execAfter = p.requestedAt + p.delayAt ∧ P.minDelay ≤ p.delayAt ∧
      st.signer = some p.signerAt ∧ p.nonceUsed < st.nonce ∧
      ∃ σ, P.valid p.signerAt (P.digest p.nonceUsed p.cfg) σ = true)

theorem inv_init (c0 : Config) (e : Bool) : Inv P (init c0 e : St Signer) :=
  ⟨fun _ h => by simp [init] at h, fun _ h => by simp [init] at h⟩

theorem inv_step {now : Nat} {st st' : St Signer} {a : Act Signer Sig}
    (hi : Inv P st) (h : step P now st a = some st') : Inv P st' := by
  obtain ⟨h1, h2⟩ := hi
  cases a with
  | setup s d =>
      obtain ⟨hd, rfl⟩ := step_setup h
      exact ⟨fun _ _ => hd, fun _ hp => by simp at hp⟩
  | disable =>
      obtain rfl := step_disable h
      exact ⟨fun _ hs => by simp at hs, fun _ hp => by simp at hp⟩
  | request c σ =>
      obtain ⟨s, hs, _, hv, rfl⟩ := step_request h
      refine ⟨fun _ _ => h1 s hs, fun p hp => ?_⟩
      simp at hp; subst hp
      exact ⟨rfl, h1 s hs, hs, Nat.lt_succ_self _, σ, hv⟩
  | cancel =>
      obtain ⟨_, rfl⟩ := step_cancel h
      exact ⟨h1, fun _ hp => by simp at hp⟩
  | execute =>
      obtain ⟨_, _, _, _, rfl⟩ := step_execute h
      exact ⟨h1, fun _ hp => by simp at hp⟩

theorem reach_inv {st : St Signer} (h : Reach P st) : Inv P st := by
  induction h with
  | init c0 e => exact inv_init c0 e
  | step now a _ hs ih => exact inv_step ih hs

/-! ## T1: the passkey only changes as the authority signed, and only after the delay -/

/-- T1. In any reachable state, if a call changes the passkey configuration, then:
  * the call is `execute`,
  * the new configuration is the one of the pending rotation,
  * at least `delayAt ≥ minDelay` has elapsed since that rotation was requested,
  * the rotation is still backed by the authority registered NOW (replacing or disabling the
    authority, or cancelling, would have dropped it),
  * that authority produced a valid signature over the digest of (nonce used, new configuration). -/
theorem passkey_changes_only_as_authorized {now : Nat} {st st' : St Signer} {a : Act Signer Sig}
    (hr : Reach P st) (h : step P now st a = some st') (hc : st'.config ≠ st.config) :
    a = .execute ∧ ∃ p, st.pending = some p ∧ st'.config = p.cfg ∧
      p.requestedAt + p.delayAt ≤ now ∧ P.minDelay ≤ p.delayAt ∧
      st.signer = some p.signerAt ∧
      ∃ σ, P.valid p.signerAt (P.digest p.nonceUsed p.cfg) σ = true := by
  have ha := config_changes_only_by_execute h hc
  subst ha
  refine ⟨rfl, ?_⟩
  obtain ⟨_, h2⟩ := reach_inv hr
  obtain ⟨p, hp, ht, _, rfl⟩ := step_execute h
  obtain ⟨he, hmin, hs, _, σ, hv⟩ := h2 p hp
  exact ⟨p, hp, rfl, by omega, hmin, hs, σ, hv⟩

/-! ## T2: each authority signature is consumed at most once -/

theorem run_nonce_mono (P : Params Signer Sig Digest) :
    ∀ (st : St Signer) (tr : List (Nat × Act Signer Sig)), st.nonce ≤ (run P st tr).nonce
  | _, [] => Nat.le_refl _
  | st, (now, a) :: rest => by
      unfold run
      cases hs : step P now st a with
      | none => exact run_nonce_mono P st rest
      | some st' => exact Nat.le_trans (nonce_mono hs) (run_nonce_mono P st' rest)

/-- Every nonce consumed later in a trace is at least the current nonce. -/
theorem usedNonces_ge (P : Params Signer Sig Digest) :
    ∀ (st : St Signer) (tr : List (Nat × Act Signer Sig)), ∀ n ∈ usedNonces P st tr, st.nonce ≤ n
  | _, [], n, hn => by simp [usedNonces] at hn
  | st, (now, a) :: rest, n, hn => by
      unfold usedNonces at hn
      cases hs : step P now st a with
      | none => rw [hs] at hn; exact usedNonces_ge P st rest n hn
      | some st' =>
          rw [hs] at hn
          have hge : ∀ m ∈ usedNonces P st' rest, st.nonce ≤ m :=
            fun m hm => Nat.le_trans (nonce_mono hs) (usedNonces_ge P st' rest m hm)
          cases a with
          | request c σ =>
              simp only [List.mem_cons] at hn
              rcases hn with rfl | hn
              · exact Nat.le_refl _
              · exact hge n hn
          | setup _ _ => exact hge n hn
          | disable => exact hge n hn
          | cancel => exact hge n hn
          | execute => exact hge n hn

/-- T2. The nonces consumed by the successful requests of any trace are strictly increasing, so no
  nonce (hence, by `digest_inj`, no signed digest) is ever accepted twice. -/
theorem usedNonces_strictly_increasing (P : Params Signer Sig Digest) :
    ∀ (st : St Signer) (tr : List (Nat × Act Signer Sig)), (usedNonces P st tr).Pairwise (· < ·)
  | _, [] => by simp [usedNonces]
  | st, (now, a) :: rest => by
      unfold usedNonces
      cases hs : step P now st a with
      | none => exact usedNonces_strictly_increasing P st rest
      | some st' =>
          have ih := usedNonces_strictly_increasing P st' rest
          cases a with
          | request c σ =>
              refine List.Pairwise.cons (fun m hm => ?_) ih
              have h1 := (request_consumes_nonce hs).1
              have h2 := usedNonces_ge P st' rest m hm
              omega
          | setup _ _ => exact ih
          | disable => exact ih
          | cancel => exact ih
          | execute => exact ih

/-- Consequence of T2 with collision resistance: requests that consumed different nonces never
  verified the same digest. -/
theorem distinct_nonces_distinct_digests {n m : Nat} {c d : Config} (hnm : n ≠ m) :
    P.digest n c ≠ P.digest m d := by
  intro heq; exact hnm (P.digest_inj n m c d heq).1

end RecoveryModel
