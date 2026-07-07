(ns kotoba-rad.sigref-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba-rad.sigref :as sigref]))

(def signer-seed (byte-array (range 32)))

(deftest sign-and-verify-roundtrip
  (let [sr (sigref/sign signer-seed "rid-1" "refs/heads/main" "commit-1" 1000)]
    (is (true? (sigref/valid? sr)))))

(deftest tampered-commit-field-fails-verification
  (let [sr (sigref/sign signer-seed "rid-1" "refs/heads/main" "commit-1" 1000)
        tampered (assoc sr "commit" "commit-evil")]
    (is (false? (sigref/valid? tampered)))))

(deftest missing-sig-is-invalid
  (is (false? (sigref/valid? {"rid" "rid-1" "ref" "refs/heads/main" "commit" "c" "ts" 1}))))
