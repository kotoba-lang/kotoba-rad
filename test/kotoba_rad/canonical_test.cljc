(ns kotoba-rad.canonical-test
  (:require [clojure.test :refer [deftest is]]
            [ed25519.core :as ed]
            [kotoba-rad.canonical :as canonical]
            [kotoba-rad.sigref :as sigref]))

(def seeds [(byte-array (repeat 32 (byte 1)))
            (byte-array (repeat 32 (byte 2)))
            (byte-array (repeat 32 (byte 3)))])
(def delegates (set (map ed/did-key-from-seed seeds)))
(def policy {:rid "rid-ci" :ref "refs/ci/main" :delegates delegates :threshold 2})

(defn signed [seed commit ts]
  (sigref/sign seed "rid-ci" "refs/ci/main" commit ts))

(deftest threshold-requires-distinct-authorized-valid-signers
  (is (nil? (canonical/canonical-ref policy [(signed (first seeds) "c1" 1)])))
  (is (= "c1" (canonical/canonical-ref
                policy [(signed (first seeds) "c1" 1)
                        (signed (second seeds) "c1" 2)])))
  (is (nil? (canonical/canonical-ref
             policy [(signed (first seeds) "c1" 1)
                     (signed (first seeds) "c1" 2)])))
  (let [outsider (byte-array (repeat 32 (byte 9)))]
    (is (nil? (canonical/canonical-ref
               policy [(signed (first seeds) "c1" 1)
                       (signed outsider "c1" 2)])))))

(deftest matching-rid-and-ref-are-required
  (let [valid (signed (first seeds) "c1" 1)
        wrong-ref (sigref/sign (second seeds) "rid-ci" "refs/heads/main" "c1" 2)]
    (is (nil? (canonical/canonical-ref policy [valid wrong-ref])))))

(deftest split-quorum-is-explicit-conflict
  (let [four-seeds (conj seeds (byte-array (repeat 32 (byte 4))))
        p (assoc policy :delegates (set (map ed/did-key-from-seed four-seeds)))]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"conflicting commits reached quorum"
         (canonical/canonical-ref
          p [(signed (nth four-seeds 0) "a" 1)
             (signed (nth four-seeds 1) "a" 2)
             (signed (nth four-seeds 2) "b" 3)
             (signed (nth four-seeds 3) "b" 4)])))))
