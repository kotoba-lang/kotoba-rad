(ns kotoba-rad.push-gate
  "The sovereign push-authorization check: a reimplementation, as a pure
   predicate, of what the deleted Rust kotoba-git's push_gate/RadRegistry
   used to enforce server-side. Anyone (client or server) can call this
   before adopting a proposed ref update."
  (:require [kotoba-rad.delegate :as delegate]
            [kotoba-rad.sigref :as sigref]
            [kotoba-rad.cacao-delegate :as cacao-delegate]))

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
   CACAO delegation chain (kotoba-rad.cacao-delegate/authorized-by-chain?,
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
