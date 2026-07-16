(ns nekko.push-gate-test
  (:require [clojure.test :refer [deftest is testing]]
            [ed25519.core :as ed]
            [cacao.core :as cacao]
            [nekko.identity :as identity]
            [nekko.delegate :as delegate]
            [nekko.sigref :as sigref]
            [nekko.cacao-delegate :as cacao-delegate]
            [nekko.push-gate :as push-gate]))

(defn- new-store []
  (let [store (atom {})]
    {:put! (fn [cid bytes] (swap! store assoc cid bytes))
     :get-fn (fn [cid] (get @store cid))}))

(def owner-seed (byte-array (range 32)))
(def delegate-seed (byte-array (map #(mod (+ % 1) 256) (range 32))))
(def outsider-seed (byte-array (map #(mod (+ % 3) 256) (range 32))))

(deftest owner-signed-push-is-authorized
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        rid (identity/genesis! put! owner-did 1000)
        sr (sigref/sign owner-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (true? (push-gate/authorize-push? get-fn nil owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest delegate-signed-push-is-authorized-once-added
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        rid (identity/genesis! put! owner-did 1000)
        head (delegate/add-delegate! put! get-fn nil owner-did owner-seed delegate-did 1001)
        sr (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1002)]
    (is (true? (push-gate/authorize-push? get-fn head owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest outsider-signed-push-is-rejected
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        rid (identity/genesis! put! owner-did 1000)
        sr (sigref/sign outsider-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push? get-fn nil owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest mismatched-ref-target-is-rejected
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        rid (identity/genesis! put! owner-did 1000)
        sr (sigref/sign owner-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push? get-fn nil owner-did rid "refs/heads/main" "commit-DIFFERENT" sr)))))

(deftest revoked-delegate-push-is-rejected
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        rid (identity/genesis! put! owner-did 1000)
        head1 (delegate/add-delegate! put! get-fn nil owner-did owner-seed delegate-did 1001)
        head2 (delegate/remove-delegate! put! get-fn head1 owner-did owner-seed delegate-did 1002)
        sr (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1003)]
    (is (true? (push-gate/authorize-push? get-fn head1 owner-did rid "refs/heads/main" "commit-1" sr)))
    (is (false? (push-gate/authorize-push? get-fn head2 owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest mismatched-ref-name-is-rejected
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        rid (identity/genesis! put! owner-did 1000)
        sr (sigref/sign owner-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push? get-fn nil owner-did rid "refs/heads/other" "commit-1" sr)))))

(deftest mismatched-rid-is-rejected
  (let [{:keys [put! get-fn]} (new-store)
        owner-did (ed/did-key-from-seed owner-seed)
        rid (identity/genesis! put! owner-did 1000)
        other-rid (identity/genesis! put! owner-did 2000)
        sr (sigref/sign owner-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push? get-fn nil owner-did other-rid "refs/heads/main" "commit-1" sr)))))

;; ── authorize-push-cacao? (journal-free, self-contained delegation chain) ──

(def rid "rid-1")

(deftest cacao-chain-authorizes-a-push-without-any-journal
  (let [owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        chain [(:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-did :nonce "n1"
                                        :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                                        :resources [(cacao-delegate/push-resource-wildcard rid)]}))]
        sr (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (true? (push-gate/authorize-push-cacao? chain owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest cacao-chain-rejects-an-outsiders-signature-even-with-a-valid-chain-shape
  (let [owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        outsider-did (ed/did-key-from-seed outsider-seed)
        chain [(:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-did :nonce "n1"
                                        :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                                        :resources [(cacao-delegate/push-resource-wildcard rid)]}))]
        ;; the outsider signs a sigref but was never granted a link in the chain
        sr (sigref/sign outsider-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push-cacao? chain owner-did rid "refs/heads/main" "commit-1" sr)))))

(deftest cacao-chain-mismatched-commit-is-rejected
  (let [owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        chain [(:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-did :nonce "n1"
                                        :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                                        :resources [(cacao-delegate/push-resource-wildcard rid)]}))]
        sr (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1001)]
    (is (false? (push-gate/authorize-push-cacao? chain owner-did rid "refs/heads/main" "commit-DIFFERENT" sr)))))

(deftest cacao-chain-expiry-is-enforced-only-when-the-7-arg-now-opt-is-passed
  (testing "authorize-push-cacao?'s cacao-opts arg threads :now through to
            cacao-delegate/authorized-by-chain? -- this is the arity gap
            that was untested until now (cacao-delegate's own expiry test
            never went through push-gate at all)"
    (let [owner-did (ed/did-key-from-seed owner-seed)
          delegate-did (ed/did-key-from-seed delegate-seed)
          expired-chain [(:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-did :nonce "n1"
                                                   :iat "2020-01-01T00:00:00Z" :exp "2020-06-01T00:00:00Z"
                                                   :resources [(cacao-delegate/push-resource-wildcard rid)]}))]
          sr (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1001)]
      (is (true? (push-gate/authorize-push-cacao? expired-chain owner-did rid "refs/heads/main" "commit-1" sr))
          "6-arg arity (no cacao-opts) does not check expiry at all")
      (is (true? (push-gate/authorize-push-cacao? expired-chain owner-did rid "refs/heads/main" "commit-1" sr nil))
          "7-arg arity with an explicit nil cacao-opts behaves the same as the 6-arg one")
      (is (false? (push-gate/authorize-push-cacao? expired-chain owner-did rid "refs/heads/main" "commit-1" sr
                                                    {:now "2026-01-01T00:00:00Z"}))
          "7-arg arity with a real :now correctly rejects the expired chain"))))

;; ---------- authorize-push-multi-cacao? (quorum / separation of duties) ----------

(def second-delegate-seed (byte-array (map #(mod (+ % 5) 256) (range 32))))

(defn- wildcard-chain [aud-did]
  [(:cacao-b64 (cacao/mint {:seed owner-seed :aud aud-did :nonce "n1"
                            :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                            :resources [(cacao-delegate/push-resource-wildcard rid)]}))])

(defn- approval [seed]
  {:sigref (sigref/sign seed rid "refs/heads/main" "commit-1" 1001)
   :chain (wildcard-chain (ed/did-key-from-seed seed))})

(deftest multi-two-distinct-authorized-signers-satisfy-a-2-quorum
  (let [owner-did (ed/did-key-from-seed owner-seed)
        approvals [(approval delegate-seed) (approval second-delegate-seed)]]
    (is (true? (push-gate/authorize-push-multi-cacao?
                approvals 2 owner-did rid "refs/heads/main" "commit-1")))
    (is (= #{(ed/did-key-from-seed delegate-seed)
             (ed/did-key-from-seed second-delegate-seed)}
           (push-gate/authorized-signers-cacao
            approvals owner-did rid "refs/heads/main" "commit-1")))))

(deftest multi-the-same-signer-twice-counts-once
  (let [owner-did (ed/did-key-from-seed owner-seed)
        approvals [(approval delegate-seed) (approval delegate-seed)]]
    (is (false? (push-gate/authorize-push-multi-cacao?
                 approvals 2 owner-did rid "refs/heads/main" "commit-1")))
    (is (true? (push-gate/authorize-push-multi-cacao?
                approvals 1 owner-did rid "refs/heads/main" "commit-1")))))

(deftest multi-excluded-did-never-counts-toward-the-quorum
  (testing "separation of duties: the proposer's own approval is inert"
    (let [owner-did (ed/did-key-from-seed owner-seed)
          proposer-did (ed/did-key-from-seed delegate-seed)
          approvals [(approval delegate-seed) (approval second-delegate-seed)]]
      (is (false? (push-gate/authorize-push-multi-cacao?
                   approvals 2 owner-did rid "refs/heads/main" "commit-1"
                   {:exclude-dids #{proposer-did}})))
      (is (true? (push-gate/authorize-push-multi-cacao?
                  approvals 1 owner-did rid "refs/heads/main" "commit-1"
                  {:exclude-dids #{proposer-did}}))))))

(deftest multi-an-unauthorized-approval-does-not-count
  (testing "an outsider's approval (valid sigref, but no chain from the owner) is ignored"
    (let [owner-did (ed/did-key-from-seed owner-seed)
          bogus {:sigref (sigref/sign outsider-seed rid "refs/heads/main" "commit-1" 1001)
                 :chain [(:cacao-b64 (cacao/mint {:seed outsider-seed
                                                  :aud (ed/did-key-from-seed outsider-seed)
                                                  :nonce "n1"
                                                  :iat "2026-01-01T00:00:00Z"
                                                  :exp "2099-01-01T00:00:00Z"
                                                  :resources [(cacao-delegate/push-resource-wildcard rid)]}))]}
          approvals [(approval delegate-seed) bogus]]
      (is (false? (push-gate/authorize-push-multi-cacao?
                   approvals 2 owner-did rid "refs/heads/main" "commit-1"))))))

(deftest multi-a-sigref-for-a-different-commit-does-not-count
  (let [owner-did (ed/did-key-from-seed owner-seed)
        stale {:sigref (sigref/sign second-delegate-seed rid "refs/heads/main" "commit-OLD" 1001)
               :chain (wildcard-chain (ed/did-key-from-seed second-delegate-seed))}
        approvals [(approval delegate-seed) stale]]
    (is (false? (push-gate/authorize-push-multi-cacao?
                 approvals 2 owner-did rid "refs/heads/main" "commit-1")))))

(deftest multi-zero-quorum-is-the-auto-merge-tier
  (let [owner-did (ed/did-key-from-seed owner-seed)]
    (is (true? (push-gate/authorize-push-multi-cacao?
                [] 0 owner-did rid "refs/heads/main" "commit-1")))))

(deftest multi-expired-chains-are-rejected-when-now-is-enforced
  (let [owner-did (ed/did-key-from-seed owner-seed)
        delegate-did (ed/did-key-from-seed delegate-seed)
        expired {:sigref (sigref/sign delegate-seed rid "refs/heads/main" "commit-1" 1001)
                 :chain [(:cacao-b64 (cacao/mint {:seed owner-seed :aud delegate-did :nonce "n1"
                                                  :iat "2020-01-01T00:00:00Z"
                                                  :exp "2020-06-01T00:00:00Z"
                                                  :resources [(cacao-delegate/push-resource-wildcard rid)]}))]}]
    (is (true? (push-gate/authorize-push-multi-cacao?
                [expired] 1 owner-did rid "refs/heads/main" "commit-1")))
    (is (false? (push-gate/authorize-push-multi-cacao?
                 [expired] 1 owner-did rid "refs/heads/main" "commit-1"
                 {:cacao-opts {:now "2026-01-01T00:00:00Z"}})))))
