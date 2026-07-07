(ns kotoba-rad.push-gate
  "The sovereign push-authorization check: a reimplementation, as a pure
   predicate, of what the deleted Rust kotoba-git's push_gate/RadRegistry
   used to enforce server-side. Anyone (client or server) can call this
   before adopting a proposed ref update."
  (:require [kotoba-rad.delegate :as delegate]
            [kotoba-rad.sigref :as sigref]))

(defn authorize-push?
  "Would this RID's current delegate set (folded from its journal at
   head-cid) authorize moving ref-name to commit-cid, given a signed
   sigref claiming to attest exactly that?

   Requires all of:
   - the sigref's own (rid, ref, commit) fields match what's being proposed
   - the sigref's signature verifies against its own claimed signer
   - that signer is a currently-authorized delegate (or the owner)"
  [get-fn head-cid owner-did rid ref-name commit-cid sigref-map]
  (and (= (get sigref-map "rid") rid)
       (= (get sigref-map "ref") ref-name)
       (= (get sigref-map "commit") commit-cid)
       (sigref/valid? sigref-map)
       (delegate/authorized? get-fn head-cid owner-did (get sigref-map "signer"))))
