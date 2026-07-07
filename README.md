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
- **`kotoba-rad.announce`** — `sign-announce-fn`/`verify-announce-fn`,
  adapters plugging straight into `kotoba-lang/p2p`'s pluggable
  `:sign-announce`/`:verify-announce?` `new-node` hooks. A p2p head-announce
  (`{:graph :head-cid :seq ...}`) is exactly a sigref shape (ref-name =
  graph, commit = head-cid, ts = seq), so no new signing primitive was
  needed — only this adapter. Neither repo depends on the other; they
  compose through p2p's documented plain-map message shape, the same way
  `kotoba-git`/`kotoba-rad` compose with each other.
- **`kotoba-rad.cacao-delegate`** + **`kotoba-rad.push-gate/authorize-
  push-cacao?`** — a second, journal-free authorization scheme: the owner
  mints a `cacao.core` capability (root-first/leaf-last delegation chain,
  CAIP-122/SIWE) granting a push-resource string to a delegate's did:key
  (`push-resource`/`push-resource-wildcard`); the delegate can present
  that chain — or mint a further sub-delegated link on top of it — to
  prove authorization without the verifier ever fetching or replaying
  `kotoba-rad.journal`. Sub-delegation cannot escalate resources
  (`cacao.core/verify-chain`'s own `covers?` constraint enforces this).
  This is a different trust model from `kotoba-rad.delegate`, not a
  replacement — the journal is a shared, queryable ledger of who's
  *currently* authorized (supports revocation); a CACAO chain is a bearer
  capability the holder carries themselves (no revocation without an
  expiry or a separate revocation list, but no journal lookup needed
  either). Use whichever trust model fits: `authorize-push?` for the
  journal, `authorize-push-cacao?` for a portable chain.

`kotoba-rad` only ever deals in plain CID strings for refs/commits (never a
`kotoba-git` object directly), so the two repos stay decoupled — either can
evolve independently, and `authorize-push?` can gate any content-addressed
system's ref updates, not just `kotoba-git`'s.

## What this deliberately is NOT (yet)

- **No real transport wiring for replication.** `kotoba-rad.announce` +
  `kotoba-lang/p2p`'s `:sign-announce`/`:verify-announce?` hooks now cover
  signed/verified head announces (gossip fanout + bitswap-style delta-sync
  + `chain/verify-chain` were already p2p's job) — but p2p itself still
  only ships an in-memory loopback reference transport; a real QUIC/
  WebRTC/WebTransport adapter is still a host follow-up, not attempted
  here or there. (Earlier drafts of this README claimed p2p's `deps.edn`
  pointed at a stale `commit-dag` coordinate needing a patch first — that
  was already fixed upstream, independently, before this was checked.)
- **No CACAO revocation.** `kotoba-rad.cacao-delegate` covers minting and
  verifying delegation chains (including sub-delegation and resource-
  escalation prevention), but a chain is only invalidated by its own
  `exp` — there's no equivalent of `kotoba-rad.delegate/remove-delegate!`
  for a CACAO-authorized holder (a real revocation list, or short-lived
  chains re-minted on a schedule, would be the usual fix; neither is
  built here).
- **No richer protected-branch policy beyond fast-forward.**
  `authorize-push?`/`authorize-push-cacao?` check *who* signed, not
  policy about *what* ref updates are allowed once someone's authorized —
  `kotoba-git.ref-policy/set-ref-guarded!` now composes identity + the
  fast-forward-only shape check into one call (an injected `authorized?`
  predicate, no dependency from `kotoba-git` back onto this repo), but
  nothing yet adds richer policy on top (required reviewers, branch
  naming rules, etc.).

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

;; wiring signed head-announces into a kotoba-lang/p2p node:
;; (require '[kotoba-rad.announce :as announce]
;;          '[kotoba.p2p.sync :as sync])
;; (sync/new-node "my-peer" store
;;                {:sign-announce (announce/sign-announce-fn owner-seed rid)
;;                 :verify-announce? (announce/verify-announce-fn get-fn journal-head
;;                                                                 owner-did rid)})

;; journal-free authorization via a CACAO delegation chain instead:
(require '[kotoba-rad.cacao-delegate :as cacao-delegate]
         '[cacao.core :as cacao])
(def grant (:cacao-b64 (cacao/mint {:seed owner-seed :aud collab-did :nonce "n1"
                                     :iat "2026-01-01T00:00:00Z" :exp "2099-01-01T00:00:00Z"
                                     :resources [(cacao-delegate/push-resource-wildcard rid)]})))
(def sr2 (sigref/sign collab-seed rid "refs/heads/main" "commit-cid-here" 2))
(push-gate/authorize-push-cacao? [grant] owner-did rid "refs/heads/main"
                                  "commit-cid-here" sr2) ;=> true, no journal consulted
```

## Note on ClojureScript

`ed25519.core` and (transitively) parts of this repo's crypto-touching
namespaces (`delegate`, `sigref`, `push-gate`, `announce`, `cacao-delegate`) are Clojure/JVM-only today —
the upstream `org-ietf-ed25519` repo has no `:cljs` branch. `.cljc` file
extensions here match sibling convention, but only `clojure -M:test`
actually exercises this repo; there is no ClojureScript CI job.

## Testing

```
clojure -M:test          # against the pinned :git/sha deps
clojure -M:local:test    # against sibling checkouts in ../ (same-monorepo dev)
```
