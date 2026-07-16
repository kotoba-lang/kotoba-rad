(ns nekko.push-gate
  "The sovereign push-authorization check: a reimplementation, as a pure
   predicate, of what the deleted Rust kotoba-git's push_gate/RadRegistry
   used to enforce server-side. Anyone (client or server) can call this
   before adopting a proposed ref update."
  (:require [nekko.delegate :as delegate]
            [nekko.sigref :as sigref]
            [nekko.cacao-delegate :as cacao-delegate]))

(defn- sigref-matches?
  [sigref-map rid ref-name commit-cid]
  (and (= (get sigref-map "rid") rid)
       (= (get sigref-map "ref") ref-name)
       (= (get sigref-map "commit") commit-cid)
       (sigref/valid? sigref-map)))

(defn authorize-push?
  "Would this RID's current delegate set (folded from its journal at
   head-cid) authorize moving ref-name to commit-cid, given a signed
   sigref claiming to attest exactly that?

   Requires all of:
   - the sigref's own (rid, ref, commit) fields match what's being proposed
   - the sigref's signature verifies against its own claimed signer
   - that signer is a currently-authorized delegate (or the owner)"
  [get-fn head-cid owner-did rid ref-name commit-cid sigref-map]
  (and (sigref-matches? sigref-map rid ref-name commit-cid)
       (delegate/authorized? get-fn head-cid owner-did (get sigref-map "signer"))))

(defn authorize-push-cacao?
  "Like authorize-push?, but authorization comes from a self-contained
   CACAO delegation chain (nekko.cacao-delegate/authorized-by-chain?,
   root-first/leaf-last, rooted at owner-did) instead of consulting a
   journal. The sigref still proves THIS specific ref update was attested
   by the chain's holder; the chain proves that holder was ever allowed to
   do so -- a portable, journal-free alternative to authorize-push?."
  ([chain owner-did rid ref-name commit-cid sigref-map]
   (authorize-push-cacao? chain owner-did rid ref-name commit-cid sigref-map nil))
  ([chain owner-did rid ref-name commit-cid sigref-map cacao-opts]
   (and (sigref-matches? sigref-map rid ref-name commit-cid)
        (cacao-delegate/authorized-by-chain? chain owner-did rid ref-name
                                              (get sigref-map "signer") cacao-opts))))

(defn authorized-signers-cacao
  "The set of DISTINCT signer dids among approvals that each independently
   pass authorize-push-cacao? for this exact (rid, ref-name, commit-cid)
   update. approvals: a seq of {:sigref <sigref-map> :chain [cacao-b64 ...]}.
   opts:
     :exclude-dids  a set of dids whose approvals never count -- the
                    separation-of-duties hook (e.g. the proposer of the
                    change being merged, so self-approval cannot satisfy a
                    quorum)
     :cacao-opts    passed through to the chain check (e.g. {:now <ISO>}
                    to enforce iat/exp bounds on every link)"
  ([approvals owner-did rid ref-name commit-cid]
   (authorized-signers-cacao approvals owner-did rid ref-name commit-cid nil))
  ([approvals owner-did rid ref-name commit-cid {:keys [exclude-dids cacao-opts]}]
   (into #{}
         (comp (filter (fn [{:keys [sigref chain]}]
                         (authorize-push-cacao? chain owner-did rid ref-name
                                                commit-cid sigref cacao-opts)))
               (map #(get-in % [:sigref "signer"]))
               (remove (or exclude-dids #{})))
         approvals)))

(defn authorize-push-multi-cacao?
  "Quorum form of authorize-push-cacao?: do at least min-signers DISTINCT
   authorized signers each attest this exact ref update? Distinctness is by
   the sigref's signer did, so the same delegate presenting two sigrefs (or
   a client retry duplicating one approval) still counts once. min-signers
   of 0 is authorized with no approvals at all -- the auto-merge tier a
   caller's own pre-checks (e.g. a machine governor) may grant to its
   lowest-risk ref namespace. Same opts as authorized-signers-cacao;
   :exclude-dids is how a caller bans self-approval (proposer's did never
   counts toward the quorum)."
  ([approvals min-signers owner-did rid ref-name commit-cid]
   (authorize-push-multi-cacao? approvals min-signers owner-did rid ref-name commit-cid nil))
  ([approvals min-signers owner-did rid ref-name commit-cid opts]
   (>= (count (authorized-signers-cacao approvals owner-did rid ref-name commit-cid opts))
       min-signers)))
