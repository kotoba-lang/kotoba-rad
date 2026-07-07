(ns kotoba-rad.push-gate-test
  (:require [clojure.test :refer [deftest is]]
            [ed25519.core :as ed]
            [kotoba-rad.identity :as identity]
            [kotoba-rad.delegate :as delegate]
            [kotoba-rad.sigref :as sigref]
            [kotoba-rad.push-gate :as push-gate]))

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
