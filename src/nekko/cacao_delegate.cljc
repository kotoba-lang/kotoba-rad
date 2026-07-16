(ns nekko.cacao-delegate
  "An alternative to nekko.delegate's append-only journal: authorization
   via a self-contained, portable CACAO delegation chain (root-first,
   leaf-last, cacao.core/verify-chain) rather than consulting a shared
   journal. The owner mints a CACAO granting a capability resource
   (push-resource/push-resource-wildcard) to a delegate's did:key (as that
   CACAO's `aud`); the delegate can present the chain -- or mint a further
   sub-delegated link on top of it, re-issued from their own did -- to
   prove authorization without the verifier ever fetching/replaying a
   journal. This is a different trust model from nekko.delegate, not
   a replacement: the journal is a shared, queryable ledger of who's
   currently authorized; a CACAO chain is a bearer capability the holder
   carries themselves.

   NOTE: org-chainagnostic-cacao (cacao.core) is JVM-only today (it
   requires ed25519.core and cbor.core, both JVM-only upstream) -- see
   nekko.delegate's note."
  (:require [cacao.core :as cacao]))

(defn push-resource
  "The capability resource string this scheme uses for authorizing a push
   to ref-name under rid."
  [rid ref-name]
  (str "kotoba-rad://" rid "/push/" ref-name))

(defn push-resource-wildcard
  "A resource granting push authorization for every ref under rid (a
   trailing '*' is cacao.core/covers?'s wildcard convention)."
  [rid]
  (str "kotoba-rad://" rid "/push/*"))

(defn authorized-by-chain?
  "Does chain (a vector of base64 CACAO strings, root-first / leaf-last)
   prove signer-did is authorized by owner-did to push to ref-name under
   rid? True iff the chain verifies (cacao.core/verify-chain), its root
   issuer is owner-did, its final holder (the leaf link's :aud) is
   signer-did, and its effective resource set covers push-resource (an
   exact match, or a wildcard grant per cacao.core/covers?).

   opts (optional): {:now <ISO-8601 instant string>} to also enforce
   iat/exp bounds on every link (see cacao.core/verify-chain)."
  ([chain owner-did rid ref-name signer-did]
   (authorized-by-chain? chain owner-did rid ref-name signer-did nil))
  ([chain owner-did rid ref-name signer-did {:keys [now] :as _opts}]
   (let [{:chain/keys [valid? root-iss holder resources]}
         (cacao/verify-chain chain (when now {:now now}))
         wanted (push-resource rid ref-name)]
     (boolean
      (and valid?
           (= root-iss owner-did)
           (= holder signer-did)
           (some #(cacao/covers? % wanted) resources))))))
