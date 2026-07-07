(ns kotoba-rad.identity-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba-rad.identity :as identity]))

(defn- new-store []
  (let [store (atom {})]
    {:put! (fn [cid bytes] (swap! store assoc cid bytes))
     :get-fn (fn [cid] (get @store cid))}))

(deftest genesis-roundtrip
  (let [{:keys [put! get-fn]} (new-store)
        rid (identity/genesis! put! "did:key:zOwner" 1000)]
    (is (string? rid))
    (is (= {:did "did:key:zOwner" :created 1000} (identity/read-identity get-fn rid)))
    (is (= "did:key:zOwner" (identity/owner-did get-fn rid)))))

(deftest genesis-is-content-addressed
  (let [{:keys [put! get-fn]} (new-store)
        rid1 (identity/genesis! put! "did:key:zOwner" 1000)
        rid2 (identity/genesis! put! "did:key:zOwner" 1000)
        rid3 (identity/genesis! put! "did:key:zOther" 1000)]
    (is (= rid1 rid2) "same did+ts -> same RID")
    (is (not= rid1 rid3) "different did -> different RID")))
