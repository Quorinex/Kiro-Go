# Cache Capacity, O(1) LRU, and Metrics — Design Spec

- **Date:** 2026-07-02
- **Status:** Approved
- **Branch:** `feat/dispatch-cache-hardening`
- **Scope:** `proxy/cache_tracker.go`, `config/config.go`, `proxy/handler.go`, plus tests

## Context

`proxy/cache_tracker.go` is a **prompt-prefix fingerprint accounting layer** (NOT a response cache). It mirrors
Anthropic's upstream prompt caching to populate `cache_creation_input_tokens` / `cache_read_input_tokens` /
5m+1h breakdown in the usage map returned to clients — the Kiro/CodeWhisperer upstream does not emit those
fields, so the proxy fabricates them. Correctness is measured against matching Anthropic's *actual* upstream
caching behavior.

Two problems:

1. **Prefix churn.** The LRU bound is `maxPromptCacheEntries = 4096` (`cache_tracker.go:27`), and eviction is an
   O(n log n) **sort-under-lock** (`evictLRULocked:342-361`). The sibling Rust project `kiro.rs`
   (`src/anthropic/cache_metering.rs`) is the **same product with the same Claude Code workload**, and it hit and
   fixed a real production churn bug at 4096: at ~90 req/min the table rotated in ~60s, evicting history prefixes
   before the next turn (often >60s apart) reused them → "cache_read always 0, cache_creation always high, full
   rebuild every turn". Rust bumped capacity to **131072** (formula: capacity ≥ write-rate × TTL). kiro-go is the
   same single-global-map topology with the same load, so it is very likely affected — just undiagnosed, and with
   no metrics to detect it.
2. **No observability.** `Compute` returns a usage value silently; there are no hit/miss/eviction counters
   (shared gap with kiro.rs). The cache's only job is accuracy, yet its behavior is unmeasurable.

## Goals

1. Stop prefix churn under load → restore accurate `cache_read` reporting.
2. Remove the O(n log n)-under-lock eviction hot spot (which Rust itself flags at 131072).
3. Add observability (hit/miss/eviction counters) so cache behavior is measurable and the fix is verifiable.

## Non-Goals

- No change to the **global cross-account sharing** philosophy (C1; `accountID` ignored).
- No change to **disk format** (version 1).
- No new response caching, no sharding, no per-session isolation.
- No live-resize of capacity (config change requires restart — YAGNI).

## Approaches Considered (LRU — the core change)

- **A (chosen): `container/list` O(1) LRU.** Doubly-linked list (front = most-recently-used) + map of
  `key → *entry`, where each entry holds a back-ref to its `*list.Element`. Hit/update move the element to the
  front in O(1); overflow pops the back in O(1). Removes the sort-under-lock Rust itself flags at 131072.
- **B: keep sort-based, bump capacity only.** One-constant change, but inherits the O(n log n)-under-lock cost
  Rust flagged (~2.2M comparisons/overflow at 131072, on every `Update` once near capacity). kiro-go is global
  (higher write-rate) → worse.
- **C: sharded LRU.** Overkill — the bottleneck is the sort, not lock contention; A resolves it. Rejected (YAGNI).

## Design

### 1. Capacity: configurable + bumped default

- **`config/config.go`**: add field `PromptCacheMaxEntries int` (`json:"promptCacheMaxEntries,omitempty"`)
  immediately after `PromptCacheMaxRatio` (`:226`); add `GetPromptCacheMaxEntries()` (default **131072**,
  clamp ≥ 256) and `UpdatePromptCacheMaxEntries(int) error`, mirroring the `PromptCacheMaxRatio` pattern
  (`:933-949`).
- **`proxy/cache_tracker.go`**: remove `const maxPromptCacheEntries = 4096` (`:27`); the tracker gains a
  `maxEntries int` field; `newPromptCacheTracker(maxTTL, maxEntries)` clamps ≥ 256.
- **`proxy/handler.go`**: pass `config.GetPromptCacheMaxEntries()` into the constructor (`:248`).

Rationale for 131072: it is the empirically measured value for the same workload (Rust). Same product, same
single global map, same Claude Code load → sizing transfers directly. Not a guess.

### 2. O(1) LRU via `container/list`

- `import "container/list"`. The tracker gains `order *list.List` (front = MRU) alongside `entries`.
- The entry becomes pointer-typed with a back-ref; `LastHit` is dropped (list position is authoritative for LRU
  order, and `LastHit` was never persisted — reset to `now` on `Load`, so post-restart order is already flat;
  behavior unchanged):

```go
entries map[[32]byte]*promptCacheEntry
order   *list.List // front = most-recent; Element.Value = fingerprint [32]byte

type promptCacheEntry struct {
    ExpiresAt time.Time
    TTL       time.Duration
    lruElem   *list.Element // back-ref into t.order; Value = fingerprint [32]byte
}
```

- `Update` (`:317-329`): for each breakpoint — if the key exists, `MoveToFront` + update expiry/TTL; else
  `PushFront(fp)` + insert entry. Then bound the map:
  `for len(t.entries) > t.maxEntries { back := t.order.Back(); fp := back.Value.([32]byte); t.order.Remove(back); delete(t.entries, fp); t.evictions++ }`.
- `Compute` hit (`:279-291`): `t.order.MoveToFront(entry.lruElem)` + update expiry.
- `pruneExpiredLocked` (`:332-338`): on delete, also `t.order.Remove(entry.lruElem)`.
- `Load` (`:106-116`): rebuild map + list (`PushFront`/`PushBack` each loaded entry; post-restart order is
  arbitrary — acceptable).
- `flush` (`:149-175`): unchanged (serializes the map; the list is not persisted). Disk format version 1
  unchanged.
- `newPromptCacheTracker`: initialize `order: list.New()`.

### 3. Metrics (atomic counters)

- The tracker gains `hits, misses, evictions, expirations int64`, updated via `atomic.AddInt64` and read via
  `atomic.LoadInt64` (matching `handler.go:44` `totalRequests` style).
  - `hits++` in `Compute` when the returned `CacheReadInputTokens > 0`; `misses++` when `== 0` (covers both the
    empty-cache early return at `:248-262` and the main return at `:297-302`; the nil-profile/empty-account guard
    at `:235` does NOT count — no cache decision is made there).
  - `evictions++` per pop-back in `Update`.
  - `expirations++` per deleted entry in `pruneExpiredLocked`.
- New method `Stats() PromptCacheStats { Entries int; Capacity int; Hits, Misses, Evictions, Expirations int64 }`.
- Exposure: fold into the `/v1/stats` JSON response (`handler.go:456-460`) as a `"cache"` object. Reuses
  `validateApiKey` auth (`:427`); zero new routes.
- `hitRate = hits / (hits + misses)` is computable client-side → directly surfaces the "cache_read always 0"
  failure mode (high misses + high evictions) versus healthy (high hitRate, low evictions).

## Invariants Preserved (do not change)

- Global cross-account sharing — `accountID` ignored (`:316`).
- `Update` runs only on the request-success path (`handler.go:1270`).
- `dirty`-on-hit + idempotent `Stop` (commit `c35e792`).
- `clampCacheBreakdownToCreation` + `splitAgainstTotal` (commits `c01dfb9`, `501443b`).
- Disk format version 1.
- Single mutex; all list ops under `t.mu`.

## Testing (TDD, RED → GREEN)

- **Churn reproduction (regression):** tracker at `cap = 131072`; feed ~5000 distinct fingerprints within the TTL;
  replay an old one → still a hit (`CacheReadInputTokens > 0`). The same scenario at `cap = 4096` → miss. Mirrors
  the Rust regression.
- **O(1) LRU correctness:** insert a, b, c (cap 3); touch a; insert d → evicted is b (not a); hit moves to front;
  eviction counter increments by exactly the overflow count.
- **Capacity config:** `GetPromptCacheMaxEntries` default 131072; clamp ≥ 256 (0 / 1 / negative → 256);
  `Update` persists.
- **Metrics:** after N hit + M miss `Compute` calls, `Stats()` reports correct counts; `expirations` increments
  when TTL elapses.
- **Load rebuild:** after `Load`, `len(order) == len(entries)`; subsequent eviction works without panic or leaked
  elements.
- **`LastHit` removal:** grep tests for `LastHit` and `maxPromptCacheEntries`; update any that reference them. The
  existing `TestPromptCacheEvictsLRUWhenOverCapacity` must be rewritten for list-order semantics (insertion +
  access order, no explicit `LastHit`).
- All existing tests stay green: cross-account sharing, billing-header drift, breakdown clamp, dirty-on-hit,
  idempotent `Stop`, implicit breakpoint.

## Risks

- **Removing `LastHit`:** any test or constructor literal referencing it breaks compilation → fix in the RED
  phase. If a test pins eviction order via `LastHit`, rewrite it for list-order semantics.
- **Constructor signature change** (`+maxEntries`): update every caller — `handler.go:248` and the test call
  sites that construct a tracker directly.
- **RAM:** ~131072 × ~56 B ≈ 7–10 MiB. Negligible (Rust measured ~10 MiB).
- **Runtime resize:** `maxEntries` is set once at construction; changing config at runtime requires a restart. A
  live-resize setter is out of scope (YAGNI).
