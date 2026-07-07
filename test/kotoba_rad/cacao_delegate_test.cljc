(ns kotoba-rad.cacao-delegate-test
  (:require [clojure.test :refer [deftest is testing]]
            [cacao.core :as cacao]
            [ed25519.core :as ed]
            [kotoba-rad.cacao-delegate :as cd]))

(def owner-seed (byte-array (range 32)))
(def delegate-a-seed (byte-array (map #(mod (+ % 1) 256) (range 32))))
(def delegate-b-seed (byte-array (map #(mod (+ % 2) 256) (range 32))))
(def outsider-seed (byte-array (map #(mod (+ % 3) 256) (range 32))))

(def owner-did (ed/did-key-from-seed owner-seed))
(def delegate-a-did (ed/did-key-from-seed delegate-a-seed))
(def delegate-b-did (ed/did-key-from-seed delegate-b-seed))
(def outsider-did (ed/did-key-from-seed outsider-seed))

(def rid "rid-1")

(defn- mint [seed aud resources]
  (:cacao-b64 (cacao/mint {:seed seed :aud aud :nonce "n1"
                            :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                            :resources resources})))

(deftest single-link-wildcard-grant-authorizes-any-ref
  (let [chain [(mint owner-seed delegate-a-did [(cd/push-resource-wildcard rid)])]]
    (is (true? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-a-did)))
    (is (true? (cd/authorized-by-chain? chain owner-did rid "refs/heads/other" delegate-a-did)))))

(deftest single-link-exact-grant-only-authorizes-that-ref
  (let [chain [(mint owner-seed delegate-a-did [(cd/push-resource rid "refs/heads/main")])]]
    (is (true? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-a-did)))
    (is (false? (cd/authorized-by-chain? chain owner-did rid "refs/heads/other" delegate-a-did)))))

(deftest two-link-chain-sub-delegates-to-a-third-party
  (testing "delegate-a re-issues (re-mints, iss derived from their own seed) to delegate-b"
    (let [link1 (mint owner-seed delegate-a-did [(cd/push-resource-wildcard rid)])
          link2 (mint delegate-a-seed delegate-b-did [(cd/push-resource-wildcard rid)])
          chain [link1 link2]]
      (is (true? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-b-did)))
      (testing "but delegate-a alone (not holding the leaf) is not the proven holder for this chain"
        (is (false? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-a-did)))))))

(deftest sub-delegation-cannot-escalate-resources
  (testing "delegate-a cannot grant delegate-b MORE than they themselves hold"
    (let [link1 (mint owner-seed delegate-a-did [(cd/push-resource rid "refs/heads/main")])
          link2 (mint delegate-a-seed delegate-b-did [(cd/push-resource-wildcard rid)])
          chain [link1 link2]]
      (is (false? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-b-did))))))

(deftest a-chain-not-rooted-at-the-claimed-owner-is-rejected
  (let [chain [(mint outsider-seed delegate-a-did [(cd/push-resource-wildcard rid)])]]
    (is (false? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" delegate-a-did)))))

(deftest claiming-to-be-a-different-holder-than-the-chains-leaf-aud-is-rejected
  (let [chain [(mint owner-seed delegate-a-did [(cd/push-resource-wildcard rid)])]]
    (is (false? (cd/authorized-by-chain? chain owner-did rid "refs/heads/main" outsider-did)))))

(deftest an-expired-chain-is-rejected-when-now-is-checked
  (let [expired (:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-a-did :nonce "n1"
                                          :iat "2020-01-01T00:00:00Z" :exp "2020-06-01T00:00:00Z"
                                          :resources [(cd/push-resource-wildcard rid)]}))]
    (is (true? (cd/authorized-by-chain? [expired] owner-did rid "refs/heads/main" delegate-a-did))
        "without a :now check, expiry isn't enforced")
    (is (false? (cd/authorized-by-chain? [expired] owner-did rid "refs/heads/main" delegate-a-did
                                          {:now "2026-01-01T00:00:00Z"})))))
