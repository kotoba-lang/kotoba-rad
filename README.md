# kotoba-rad

Sovereign repo identity, delegate authorization, and signed refs — the
"Radicle-equivalent" half of ADR-2607072200 (`kotoba-git-kotoba-rad-on-
kotobase-peer`, superproject `90-docs/adr/`). `kotoba-git` is the sibling
"git-equivalent" half (content-addressed blob/tree/commit objects).

## What this is

- **`kotoba-rad.identity`** — `genesis!`: an RID (repo identity) is the CID
  of its own genesis block `{did, created}`, using the same `io-ipld`
  DAG-CBOR content-addressing `kotoba-git` uses for objects (one CID scheme
  across both repos, rather than a separate ad-hoc implementation).
- **`kotoba-rad.journal`** — an append-only, hash-chained log of identity
  events, built directly on `kotoba-lang/chain`. `chain`'s single-parent,
  opaque-state design is exactly a linear identity journal (as opposed to
  `kotoba-git`'s commit DAG, which needs N parents for merges) — this repo
  does not reimplement chaining, it just instantiates one `chain` per RID.
- **`kotoba-rad.delegate`** — folds the journal into the current
  authorized-delegate set. The owner is always authorized; every
  `delegate-add`/`delegate-remove` entry must itself be signed by an
  *already*-authorized did:key (verified with real Ed25519, not assumed) —
  so authority can only be delegated forward from the genesis owner, never
  self-granted.
- **`kotoba-rad.sigref`** — signed attestations that `ref-name` currently
  points at `commit-cid` for a given `rid` (Radicle's `rad/sigrefs`
  equivalent), signed/verified with real Ed25519 over canonical CBOR.
- **`kotoba-rad.push-gate`** — `authorize-push?`, a pure predicate
  reimplementing what the deleted Rust `kotoba-git`'s `push_gate`/
  `RadRegistry` used to enforce server-side: a proposed ref update is
  authorized only if its sigref's fields match, its signature verifies, and
  its signer is currently an authorized delegate.

`kotoba-rad` only ever deals in plain CID strings for refs/commits (never a
`kotoba-git` object directly), so the two repos stay decoupled — either can
evolve independently, and `authorize-push?` can gate any content-addressed
system's ref updates, not just `kotoba-git`'s.

## What this deliberately is NOT (yet)

- **No replication/gossip.** `kotoba-lang/p2p` is the closest existing
  building block (gossip fanout + bitswap-style delta-sync +
  `chain/verify-chain`), but its `deps.edn` currently points at a
  renamed-away `commit-dag` coordinate and its `:head-announce` message has
  no signature field. Wiring `authorize-push?`/`kotoba-rad.sigref` into a
  signed head-announce is the natural next step, once `p2p` itself is
  patched — not attempted here.
- **No CACAO/SIWE delegation chains.** Delegate authorization here is
  direct Ed25519 did:key signing, not a `cacao.core/verify-chain`-style
  root-first/leaf-last delegation chain. That's a reasonable future
  enhancement (CACAO's delegation-chain shape maps naturally onto
  "authorize a sub-delegate"), deliberately deferred to keep this repo's
  crypto surface small and directly testable.
- **No ref-policy (protected branches, fast-forward-only, etc).**
  `authorize-push?` checks *who* signed, not policy about *what* ref
  updates are allowed once someone's authorized to make them.

## Usage

```clojure
(require '[kotoba-rad.identity :as identity]
         '[kotoba-rad.delegate :as delegate]
         '[kotoba-rad.sigref :as sigref]
         '[kotoba-rad.push-gate :as push-gate]
         '[ed25519.core :as ed])

(def store (atom {}))
(def put! (fn [cid bytes] (swap! store assoc cid bytes)))
(def get-fn (fn [cid] (get @store cid)))

(def owner-seed (byte-array 32 (byte 1))) ; real callers: securely-random 32 bytes
(def owner-did (ed/did-key-from-seed owner-seed))
(def rid (identity/genesis! put! owner-did (System/currentTimeMillis)))

;; delegate a collaborator
(def collab-seed (byte-array 32 (byte 2)))
(def collab-did (ed/did-key-from-seed collab-seed))
(def journal-head (delegate/add-delegate! put! get-fn nil owner-did owner-seed collab-did
                                           (System/currentTimeMillis)))

;; the collaborator signs a ref update and it's authorized
(def sr (sigref/sign collab-seed rid "refs/heads/main" "commit-cid-here"
                      (System/currentTimeMillis)))
(push-gate/authorize-push? get-fn journal-head owner-did rid "refs/heads/main"
                            "commit-cid-here" sr) ;=> true
```

## Note on ClojureScript

`ed25519.core` and (transitively) parts of this repo's crypto-touching
namespaces (`delegate`, `sigref`, `push-gate`) are Clojure/JVM-only today —
the upstream `org-ietf-ed25519` repo has no `:cljs` branch. `.cljc` file
extensions here match sibling convention, but only `clojure -M:test`
actually exercises this repo; there is no ClojureScript CI job.

## Testing

```
clojure -M:test          # against the pinned :git/sha deps
clojure -M:local:test    # against sibling checkouts in ../ (same-monorepo dev)
```
