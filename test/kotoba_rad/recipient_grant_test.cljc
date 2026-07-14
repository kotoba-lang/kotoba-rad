(ns kotoba-rad.recipient-grant-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba-rad.bytes :as b]
            [kotoba-rad.recipient-grant :as rg]))

(deftest keypair-and-grant-open-roundtrip
  (let [{:keys [priv pub]} (rg/gen-recipient-keypair)
        epoch-key (b/unhex (rg/new-epoch-key))
        g (rg/grant 1 pub epoch-key)]
    (testing "a grant opens to exactly the epoch key with the recipient's priv"
      (is (b/equal? epoch-key (rg/open g priv)))
      (is (= 1 (:epoch g)))
      (is (= pub (:recipient g))))
    (testing "a different recipient cannot open it"
      (let [other (rg/gen-recipient-keypair)]
        (is (thrown? #?(:clj Exception :cljs :default) (rg/open g (:priv other))))))
    (testing "tampering with the ciphertext breaks the GCM tag"
      (is (thrown? #?(:clj Exception :cljs :default)
                   (rg/open (update g :ct #(str (subs % 0 (- (count %) 2)) "00")) priv))))))

(deftest ephemeral-per-grant-is-fresh
  (testing "granting the same key to the same recipient twice uses distinct
            ephemeral keys (fresh sender randomness), so ciphertexts differ"
    (let [{:keys [priv pub]} (rg/gen-recipient-keypair)
          k (b/unhex (rg/new-epoch-key))
          g1 (rg/grant 1 pub k) g2 (rg/grant 1 pub k)]
      (is (not= (:eph g1) (:eph g2)))
      (is (not= (:ct g1) (:ct g2)))
      (is (b/equal? (rg/open g1 priv) (rg/open g2 priv))))))

(deftest rotate-revokes-by-omission
  (let [alice (rg/gen-recipient-keypair)
        bob   (rg/gen-recipient-keypair)
        carol (rg/gen-recipient-keypair)
        e1 (rg/rotate 0 [(:pub alice) (:pub bob) (:pub carol)])]
    (testing "epoch 1: all three are granted the same epoch key"
      (is (= 1 (:epoch e1)))
      (let [k (b/unhex (:key e1))]
        (is (b/equal? k (rg/open (get-in e1 [:grants (:pub alice)]) (:priv alice))))
        (is (b/equal? k (rg/open (get-in e1 [:grants (:pub bob)]) (:priv bob))))
        (is (b/equal? k (rg/open (get-in e1 [:grants (:pub carol)]) (:priv carol))))))
    (testing "rotate to epoch 2 dropping bob: new key, bob has no grant"
      (let [e2 (rg/rotate (:epoch e1) [(:pub alice) (:pub carol)])]
        (is (= 2 (:epoch e2)))
        (is (not= (:key e1) (:key e2)))
        (is (contains? (:grants e2) (:pub alice)))
        (is (not (contains? (:grants e2) (:pub bob))))
        (testing "alice reads epoch 2; bob can still read the OLD epoch-1 key
                  he already holds (revocation is not deletion of distributed
                  ciphertext) but gets nothing new"
          (is (b/equal? (b/unhex (:key e2))
                        (rg/open (get-in e2 [:grants (:pub alice)]) (:priv alice))))
          (is (b/equal? (b/unhex (:key e1))
                        (rg/open (get-in e1 [:grants (:pub bob)]) (:priv bob)))))))))
