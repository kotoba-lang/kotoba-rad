(ns kotoba-rad.journal-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba-rad.journal :as journal]))

(defn- new-store []
  (let [store (atom {})]
    {:store store
     :put! (fn [cid bytes] (swap! store assoc cid bytes))
     :get-fn (fn [cid] (get @store cid))}))

(deftest empty-journal
  (let [{:keys [get-fn]} (new-store)]
    (is (= [] (journal/entries get-fn nil)))
    (is (true? (journal/verify get-fn nil)))))

(deftest append-and-read-entries-in-order
  (let [{:keys [put! get-fn]} (new-store)
        head1 (journal/append! put! get-fn nil {"kind" "a"})
        head2 (journal/append! put! get-fn head1 {"kind" "b"})]
    (is (= ["a" "b"] (mapv #(get % "kind") (journal/entries get-fn head2))))
    (is (true? (journal/verify get-fn head2)))))

(deftest tampering-breaks-verification
  (let [{:keys [store put! get-fn]} (new-store)
        head1 (journal/append! put! get-fn nil {"kind" "a"})
        head2 (journal/append! put! get-fn head1 {"kind" "b"})]
    (is (true? (journal/verify get-fn head2)))
    ;; corrupt the stored bytes for an earlier link in the chain
    (swap! store assoc head1 (byte-array [1 2 3 4]))
    (is (false? (journal/verify get-fn head2)))))
