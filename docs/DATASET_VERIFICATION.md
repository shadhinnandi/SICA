# Independent Dataset Verification

**Date.** 2026-09-12. **Type.** Verification gate. No experiment was run; no detector code,
paper, seed or α was changed. One benchmark-construction bug was found and fixed under the
procedure of the instruction's §13 (see §13 below).

**Premise correction, stated first.** The instruction refers to `docs/DATASET_FORENSIC_AUDIT.md`,
`docs/DATASET_FREEZE.md`, a completed "Part 3" documenting upstream sources, and to the files
`apache_sample_2.log`, `web_sessions.csv`, `network_flows.csv`, `auth_events.csv`,
`historical.csv`, `evaluation.csv`. **None of these exist in this repository.** `docs/` contained
only `ARCHITECTURE_AUDIT.md`, `ARCHITECTURE_FREEZE.md`, `REPRODUCIBILITY_FREEZE.md` and
`TEST_PLAN.md`; the data tree contains exactly two files. Part 3 was never run in this session —
work stopped after Part 2.5 as instructed.

Those artifacts are not missing by accident: `AUDIT.md` records them as **v1 material, already
removed in the v1→v2 rebuild**. Finding O3 documents `web_sessions.csv` as the single synthetic
file that supplied all 803 v1 attack labels; O4 documents that `apache_sample_2.log` and
`nginx_real.log` were *byte-for-byte identical in content* — "the same 51,462 log records in two
formats" — and were wrongly counted as two independent source families. The duplication the
instruction asks me to test for was therefore a real defect, was found in Part 1, and was
resolved by deleting the duplicate. Everything below verifies the surviving corpus from scratch
rather than trusting that history.

---

## 1. Inventory of actual files

Complete data tree. There is no processed, derived, cached or intermediate dataset on disk:
every derived artifact is produced in memory at run time.

| Field | `data/raw/apache_sample_1.log` | `data/raw/nginx_real.log` |
|---|---|---|
| Class | **REAL SOURCE DATA** | **REAL SOURCE DATA** (see §2 caveat) |
| Bytes | 2,370,789 | 6,991,577 |
| SHA-256 | `f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef` | `526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df` |
| Lines | 10,000 (trailing newline) | 51,462 (trailing newline) |
| Blank lines | 0 | 0 |
| Parsed / malformed | 10,000 / **0** | 51,462 / **0** |
| Format | NCSA combined, 9 fields | NCSA combined, 9 fields |
| Fields | ip, ident, authuser, [ts], "request", status, bytes, "referer", "agent" | same |
| Timestamp format | `dd/Mon/YYYY:HH:MM:SS +0000` | same |
| First / last timestamp | 2015-05-17 10:05:00 → 2015-05-20 21:05:59 | 2015-05-17 08:05:00 → 2015-06-04 07:06:52 |
| Span | 3 days | 17 days |
| Missing values | `bytes='-'` 669; `ident`/`authuser` always `-` | `bytes='-'` 0; `ident`/`authuser` always `-` |
| Duplicate full records | 19 (0.19%) | 630 (1.22%) |
| Unique IPs | 1,753 | 2,660 |
| Unique User-Agents | 558 | 136 |
| Unique request lines | 1,733 (1,498 distinct paths) | **5** (3 distinct paths) |
| Referer present | 5,927 (59.27%) | 13 (0.025%) |
| Status mix | 200 9,126 · 304 445 · 404 213 · 301 164 · 206 45 · 500 3 | **404 33,876** · 304 13,330 · 200 4,028 · 206 186 · 403 38 · 416 4 |

**Class summary.** REAL SOURCE DATA: the two files above. SYNTHETIC DATA: none on disk.
DERIVED DATA: none on disk. INJECTED DATA: none on disk — attacks are constructed in memory
per seed and never persisted. OLD/OBSOLETE DATA: none present; the v1 files named in the
instruction were removed before this session.

## 2. Verification of the claimed upstream sources — **VERIFIED**

`raw.githubusercontent.com` was reachable, so this was verified against the upstream source
rather than asserted.

| Local file | Upstream | Upstream SHA-256 | Match |
|---|---|---|---|
| `data/raw/apache_sample_1.log` | `elastic/examples` → `Common Data Formats/apache_logs/apache_logs` | `f15c31e9…0364ef` | **byte-identical** |
| `data/raw/nginx_real.log` | `elastic/examples` → `Common Data Formats/nginx_logs/nginx_logs` | `5268324 3…6937df` | **byte-identical** |

Retrieved 2026-09-12 from `https://raw.githubusercontent.com/elastic/examples/master/…`,
HTTP 200, byte sizes identical (2,370,789 and 6,991,577).

* **Correspond to the claimed source?** Yes, exactly.
* **Format correct / record structure matches?** Yes — NCSA combined, 0 malformed records.
* **Line counts match?** Exactly: 10,000 and 51,462.
* **Timestamps plausible?** Dates yes; *intra-hour structure no* — see §6, the most important
  finding in this report.
* **IPs / agents / requests present?** Yes.
* **Complete or truncated?** Complete; byte-identical to upstream, not a local truncation.
* **Transformation before entering the project?** **None.** Only renaming:
  `apache_logs` → `apache_sample_1.log`, `nginx_logs` → `nginx_real.log`.

**Caveat on the name `nginx_real.log`.** Provenance was not inferred from the filename, and the
filename is misleading. Upstream describes both only as "sample files" for a Filebeat/Kibana
getting-started example; it makes **no claim** that either is captured production traffic.
The nginx file's entire URL universe is three placeholder paths — `/downloads/product_1`,
`product_2`, `product_3` — and 65.8% of its responses are 404. Those are demo-corpus
properties. The traffic's ultimate origin is **UNKNOWN** and upstream does not state it. The
file should not be described as "real" traffic in the manuscript.

## 3. Apache/Nginx duplication — **INDEPENDENT**

The instruction asks for `apache_sample_2.log` vs `nginx_real.log`; `apache_sample_2.log` does
not exist (removed as v1 defect O4, where it *was* byte-identical to `nginx_real.log`). The
test was therefore run on the two files that do exist, comparing normalised
(timestamp, IP, request, status, bytes, referer, agent) tuples.

| Measure | Value |
|---|---|
| Records | 10,000 vs 51,462 |
| **Exact full-record duplicates across files** | **0** |
| Normalised duplicates across files | 0 |
| Percentage overlap | **0.00%** |
| Unique records in each | 10,000 and 51,462 (all) |
| Shared IPs | 4 of 1,753 / 2,660 (0.23% of the smaller) |
| Shared User-Agents | 10 of 558 / 136 |
| Shared request lines | **0** of 1,733 / 5 |
| Shared (IP, UA) client pairs | 4 |
| Time spans | 2015-05-17→05-20 vs 2015-05-17→06-04 (overlapping period) |

**Verdict: A — independent datasets.** Different servers, disjoint URL universes, disjoint
record sets, and an IP intersection of four addresses consistent with coincidence among public
address space. They may legitimately be presented as two distinct workloads. The v1 claim that
was false (two formats of one corpus) does not apply to the surviving pair.

## 4. Privacy — **PASS, with one flagged item**

Values are not reproduced here.

| Check | W1 | W2 |
|---|---|---|
| IP addresses | 1,753, **all public** | 2,660 (2,600 public, 60 private/reserved) |
| `authuser` field populated | 0 | 0 |
| Cookies / session IDs / bearer tokens / API keys | 0 | 0 |
| Password or credential parameters | 0 | 0 |
| JWT-shaped strings | 0 | 0 |
| Query strings present | 1,701 requests | 0 |
| Lat/long parameters | 0 | 0 |
| Email-shaped strings | **198, all inside User-Agent** | 0 |

**The 198 email matches are crawler operator contact addresses embedded in bot User-Agent
strings** (the `Mozilla/5.0 (compatible; <bot>/1.0; <contact address>)` convention), 7 distinct
addresses. These are published contact points for automated agents, not end-user PII. The one
"cookie" pattern hit is the URL path `/misc/irccookie` — a false positive containing no cookie
data.

**Not sanitised upstream:** client IP addresses are real and unmasked. That is the material
privacy exposure and it is personal data in most jurisdictions. The existing obligation in
`DATASET.md` §8 stands. **FLAGGED:** the manuscript and repository must not present these logs
as anonymised.

## 5. License and redistribution — **PASS**

| Item | Finding |
|---|---|
| Source repository | `github.com/elastic/examples` |
| Exact paths | `Common Data Formats/apache_logs/apache_logs`, `Common Data Formats/nginx_logs/nginx_logs` |
| License | **Apache License 2.0** — retrieved from the repository root `LICENSE` (HTTP 200, 11,324 bytes, verified text) |
| Evidence | Repository-root `LICENSE` is the full Apache-2.0 text; no per-directory or per-file license overrides it; no `NOTICE` file exists (HTTP 404) |
| Redistribution status | **Permitted** |
| Attribution requirement | **Yes** — Apache-2.0 §4 requires retaining the license, a copy of it, and a statement of changes |
| Raw files committable to our repository | **Yes**, provided the conditions below are met |

**Conditions that are currently unmet.** `CITATION_OF_INPUTS.txt` describes these as "public
sample web-server access logs redistributed unmodified" and names **no source, no URL and no
license**. `DATASET.md` §1 says only "public sample logs redistributed with log-tooling
documentation". Under Apache-2.0 that is insufficient. Required before release: name
`elastic/examples`, the exact upstream paths, Apache-2.0, include a copy of the license text,
and state the change made (renamed only, contents unmodified — with the SHA-256 of each file as
evidence).

**UNKNOWN, and must be marked so:** the license covers the repository's contents as
distributed by Elastic. It does not establish the provenance or collection consent of the
*underlying traffic*, which upstream never documents. Do not claim the traffic is licensed,
consented, or anonymised.

## 6. Sessionization — **CONCERN (critical finding)**

Mechanism as implemented in `sica/sessionize.py`: parse → sort by timestamp (stable) → group by
**(remote address, User-Agent)** → cut wherever the inter-arrival gap exceeds `IDLE_SECONDS`
(1800 s) → discard sessions below `MIN_REQUESTS` (7). Grouping is ground-truth construction
only; the detector receives a session identifier and never the grouping key.

| Stage | W1_web | W2_apt |
|---|---|---|
| Distinct (IP, UA) clients | 1,862 | 2,797 |
| Sessions at ≥1 request | 3,224 | 7,489 |
| Sessions at ≥7 requests | **254** | **3,126** |
| Requests retained | 3,874 (38.7%) | 43,307 (84.2%) |
| Session length min/med/mean/p90/max | 7 / 9 / 15.3 / 33 / 108 | 7 / 12 / 13.9 / 21 / 83 |
| Session duration median / **max** | 52 s / **59 s** | 52 s / **59 s** |
| Cross-day sessions | **0** | **0** |
| Out-of-order timestamps | 0 | 0 |
| Sessions containing tied timestamps | 140 | 2,038 |
| Empty sessions | 0 | 0 |
| Session identifiers unique | yes (254/254) | yes (3,126/3,126) |

### The critical finding: the source timestamps are degenerate

No session anywhere in either corpus lasts longer than **59 seconds**, and none crosses a day
boundary — over logs spanning 3 and 17 days with a 30-minute idle timeout. The cause:

* **W1: the minute field is `05` in all 10,000 records.** One distinct value.
* **W2: the minute field is `05` or `06` and nothing else** (42,040 / 9,422).
* Hours (24 distinct) and seconds (60 distinct) are spread normally.

The upstream generator evidently produced timestamps as
`<date>:<hour>:05:<second>`. Consequences, all verified:

1. **Inter-arrival times carry no behavioural information.** Every gap is a difference between
   two seconds drawn inside one fixed minute. They are generator artifacts.
2. **A "session" here is a one-minute burst**, not a browsing session. Successive activity by
   one client is ≥1 hour away and is always cut by the idle timeout, which is why the
   1800 s timeout, cross-day handling and maximum-duration logic are all untested by this data.
3. **The documented rationale for rejecting `v5` is wrong.** `sica/invariants.py` and the
   manuscript attribute its 12–19% benign firing rate to "ordinary page loads are bursty". The
   real cause is that the timestamps are synthetic. The rejection decision stands; the stated
   reason must be corrected.
4. **`v4` (transition velocity) is untestable here.** Its `t_settle` is 300 s and no session
   exceeds 59 s, so every scope transition looks instantaneous by construction.
5. **Detection latency in seconds is meaningless** and must not be reported as a real-world
   quantity. Latency in *requests* remains valid.

**Why this does not invalidate the study.** The locked invariant set reads no clock. Verified
mechanically: `v1(current, pinned, p)`, `v2(current, pinned, p)` and `v3(is_revisit)` take no
timestamp, gap or duration argument; only the rejected `v4` and `v5` do. The leakage report's
structural check "the final invariant set consumes no timing or volume feature" is therefore
far more load-bearing than it appeared — it is precisely what makes this corpus usable.

### Grouping by (IP, UA) rather than by IP alone

The instruction asks specifically about grouping only by IP. This project does **not** do that:
the key is (address, User-Agent). That is the right choice for this threat model, because
grouping by IP alone would merge distinct clients behind one NAT into a single "session",
which would manufacture binding forks in benign traffic and fabricate the exact signal `v3`
exists to detect. The cost of the stricter key is the opposite and is already documented: a
session cannot contain a benign binding change by construction, which is why `sica/churn.py`
exists. The remaining limitation is unchanged — session identity is *reconstructed*, not
observed, because these logs carry no authentication state.

**No label leakage arises from sessionisation itself**: the grouping key is computed before any
label exists, identically for every session, and is never passed to the detector.

## 7. Real vs synthetic content — **PASS**

The five CSVs named in the instruction do not exist and cannot be mistaken for real
observations. Tracing what a final benchmark record is made of:

| Component | Origin |
|---|---|
| Every request's path, status, bytes, referer | **REAL** — verbatim from the source log |
| Benign session boundaries | **DERIVED** — deterministic sessionisation |
| Benign binding churn (address/agent changes) | **SYNTHETIC** — `sica/churn.py`, declared rates; agent updates now drawn from real corpus strings |
| Attacker request *content* | **REAL** — verbatim from a different real client (donor) in the same log |
| Attacker binding (address/agent) | **SYNTHETIC** for L2/L3; real donor values for L0/L1; victim's own for L4/L5 |
| Attacker timestamps | **SYNTHETIC** — donor gaps, anchored and compressed |
| Labels (`Session.label`, `Request.injected`, `scenario`) | **SYNTHETIC** — ground truth only |
| Timestamps generally | **SYNTHETIC UPSTREAM** — see §6 |

Labels are read at exactly one point: metric computation, after every decision exists. Verified
by inspection (`sica/calibrate.py` and `sica/monitor.py` contain no reference to `.label` or
`injected`) and adversarially by `test_calibration_ignores_labels_entirely`.

## 8. Attack injection provenance — **PASS**

| Element | Implementation |
|---|---|
| Victim session | drawn from the evaluation partition at `attack_rate` = 0.20 |
| Theft point | drawn from `[earliest_takeover, latest_takeover]`, **never moved** (fixed in Part 2.5 / M2) |
| Donor | a different real client of the same server; must satisfy the level's constraints and supply the required run length |
| Splice position | takeover replaces the whole tail; concurrent displaces `k` post-theft requests and never the final one |
| Timestamps | donor's own gaps, anchored at the theft point, compressed to fit the victim's window |
| Binding | per masquerade level, relative to the victim's binding **at the theft point** (fixed in Part 2 / H1) |
| Scenario assignment | uniform over the level × mode grid |
| Label creation | `label=1` on the session, `injected=1` on each attacker request |
| Length matching | exact — injected sessions keep the victim's request count |

**The detector receives none of:** attack label, scenario label, donor identity, injection
marker, or any future information. `ContinuityMonitor.observe` accepts exactly
`(session_id, ip, user_agent, ts, path, referrer)`.

## 9. Leakage audit — **PASS with one documented shortcut**

Marginal single-feature session-level ROC AUC, computed on the current post-fix code
(seeds 0–2, verification only — not reported results):

| Feature | W1_web | W2_apt |
|---|---|---|
| `distinct_paths` | 0.599 | **0.733** |
| `median_gap_s` | **0.322** | 0.419 |
| `n_requests` | 0.615 | 0.519 |
| `total_bytes` | 0.613 | 0.521 |
| `distinct_status` | 0.585 | 0.536 |
| `mean_bytes` | 0.580 | 0.522 |
| `min_gap_s` | 0.425 | 0.489 |
| `error_rate` | 0.534 | 0.522 |
| `n_404` | 0.528 | 0.520 |
| `duration_s` | 0.475 | 0.478 |

Two features deviate materially from chance, and both are **construction artifacts, not
legitimate signal**:

* **`distinct_paths` on W2 (0.733).** W2's entire URL universe is three paths, so "how many
  distinct paths did this session touch" is a 3-valued feature; splicing a donor's requests
  shifts it. It is an artifact of a degenerate corpus, not a property of hijacking.
* **`median_gap_s` on W1 (0.322, i.e. attacks have *shorter* median gaps).** A direct
  consequence of §6: the injection compresses donor gaps to fit inside the victim's window,
  and since all real gaps are artifacts of a single-minute timestamp field, the compression is
  visible.

Neither is removed. Per the instruction, a feature is not deleted for making the detector look
good — and neither represents legitimate session-hijacking signal, so neither should be
*added* either. What matters is that **neither can reach the detector**: the three retained
invariants read no path count, no gap, no byte count, no request count and no duration. That
structural property is asserted mechanically in `pipeline/exp05_leakage.py` and is what makes
the residual shortcuts harmless here.

Not separable: source file (workloads are never mixed), missing-value pattern, status-code
pattern, session identifier (now a deterministic digest, §M1), donor identity and scenario
identity (never exposed to the detector).

## 10. Train/test and source overlap — **PASS**

Seed 0, both workloads:

| Check | W1_web | W2_apt |
|---|---|---|
| Calibration / evaluation sessions | 127 / 127 | 1,563 / 1,563 |
| Shared session identifiers | **0** | **0** |
| Attack-labelled sessions in calibration | **0** | **0** |
| Injected requests in calibration | **0** | **0** |
| Shared benign requests (ip, ua, ts, path) across partitions | **0** | **0** |
| Reporting seeds {0…29} ∩ development seeds {100…119} | **∅** | **∅** |

**Known by-design coupling, documented not fixed:** the donor pool is drawn from the evaluation
partition, so a session can be both a victim and a donor of content for another victim
(18 victims of 127 evaluation sessions on W1; 322 of 1,563 on W2). This does not leak labels —
only request content is copied, and the donor's own label is unaffected — but it does mean
attacker content is not statistically independent of the benign population it is measured
against. That is deliberate: it is what prevents the attacker's content being separable from
benign content.

## 11. Provenance chain with exact counts

```
                                   W1_web              W2_apt
RAW FILE                           10,000 lines        51,462 lines
  |  parse (0 malformed)
PARSED REQUESTS                    10,000              51,462
  |  group by (address, User-Agent) -> 1,862 / 2,797 clients
  |  cut on 1800 s idle gap
SESSIONS (>=1 request)              3,224               7,489
  |  discard < 7 requests
BENIGN CORPUS                         254               3,126   sessions
                                    3,874              43,307   requests
  |  temporal 50/50 split
CALIBRATION / EVALUATION          127 / 127         1,563 / 1,563  sessions
  |  benign churn on BOTH partitions (15% monotone, 5% flapping)
  |  attack injection into EVALUATION ONLY, attack_rate 0.20
FINAL EVALUATION CORPUS               127               1,563   sessions
  of which attacks (seed 0)            18                 322
  refused (condition unrealisable)      2                   8
```

Counts were recomputed from the files; none is copied from earlier documentation. The
`e0_corpus.csv` figures from the abandoned run agree (254 / 3,874 and 3,126 / 43,307).

## 12. Final dataset classification

| Dataset | Classification | Justification |
|---|---|---|
| `data/raw/apache_sample_1.log` | **PRIMARY** | Verified upstream, 1,498 distinct paths, 558 agents, 59% referer coverage, diverse client population |
| `data/raw/nginx_real.log` | **SECONDARY / AUXILIARY** | Verified upstream and independent of W1; retained because it is adversarial to the method (one agent family, no referers). But it is a *demo corpus with placeholder URLs*, not real mirror traffic, and must be described as such |
| `apache_sample_2.log` | **OBSOLETE — absent** | v1 file, byte-identical to `nginx_real.log` (AUDIT.md O4); correctly deleted. Must never be reinstated as an independent source |
| `web_sessions.csv` | **OBSOLETE — absent** | v1 synthetic file that supplied all 803 v1 attack labels (AUDIT.md O3) |
| `network_flows.csv` | **OBSOLETE — absent** | v1 port-scan flows, wrong phenomenon (AUDIT.md O3/O4) |
| `auth_events.csv`, `historical.csv`, `evaluation.csv` | **UNKNOWN — absent** | Named in the instruction; no trace in this repository or its history. Cannot be classified |

None of the absent files should be reintroduced. The benchmark uses exactly two source files.

## 13. Code change made under this gate

One genuine benchmark-construction bug was found while verifying §6, and was corrected under
the instruction's §13 procedure.

**Why.** E4 sweeps `theft_delay_s` over 0, 1, 60 and 600 seconds. No session in either corpus
lasts longer than 59 seconds (§6). At 60 s and above, `inject_session` placed the attacker's
first request *after the victim's session had already ended*, so every surviving victim request
preceded the attacker's and the session became a takeover carrying a `concurrent` label. The
delay was bounded only indirectly, through a gap-span compression branch that did not fire
when the delay alone exceeded the window. The sweep was therefore varying the **scenario
type**, not the delay it claimed to vary — the same class of defect as v2 finding R2, which the
existing `test_concurrent_hijack_actually_interleaves` could not catch because it only
exercises the default delay.

**Evidence before the fix** — fraction of `concurrent` injections that actually interleave:

| `theft_delay_s` | default | 0 s | 1 s | 60 s | 600 s |
|---|---|---|---|---|---|
| before | 100% | 100% | 100% | **34.2%** | **34.2%** |
| after | 100% | 100% | 100% | **100%** | **100%** |

**Regression test (written first, confirmed failing):**
`test_concurrent_interleaves_at_every_swept_theft_delay`, parameterised over
`{None, 0, 1, 60, 600}`, asserting every produced concurrent session contains a victim request
after the theft.

**Correction (minimal):** in concurrent mode the delay is now clamped to 5% of the victim's
remaining window whenever that window is positive, independently of the gap-span compression.

**Before/after on the sweep itself** (W1, seeds 0–2, verification only):

| | delay 0 s | 1 s | 60 s | 600 s |
|---|---|---|---|---|
| before, seed 0 | recall 0.333 | 0.333 | 0.278 | 0.278 |
| after, seed 0 | 0.333 | 0.333 | **0.333** | **0.333** |

The sweep is now **fully inert** — identical metrics at every delay, on all three seeds tested.
That is the honest outcome: on a corpus whose sessions span at most 59 seconds, "how long the
attacker waits before acting" is not a variable that can be expressed. The apparent effect
previously measured was the concurrent→takeover degeneration, not a delay effect.

**Recommendation (not acted on):** `theft_delay_s` should be reported as an inert condition
with this explanation, or dropped from E4 with the reason recorded. Removing an experiment is a
decision for review, not for this gate.

**Tests:** `pytest -q` → **50 passed, 0 failed** (was 45). Collected: `tests/test_sica.py` 24,
`tests/test_regressions.py` 26.

## 14. Required documentation corrections — **CLOSED in Part 3.6**

These were the statements found to be wrong or unsupported. All five have since been
corrected; the record of what was wrong is kept deliberately.

| # | Correction | Status | Where |
|---|---|---|---|
| 1 | `v5` rejection rationale — "bursty page loads" was wrong; the cause is degenerate timestamps | **DONE** | `sica/invariants.py` docstring, `AUDIT.md` §R4 |
| 2 | W2 described as package-manager traffic; it is sample/demo data with three placeholder URLs | **DONE** | `DATASET.md` §1, `README.md`, `CHECKPOINT.md` §4 |
| 3 | Attribution — repository, exact paths, URLs, Apache-2.0, SHA-256, license copy | **DONE** | `CITATION_OF_INPUTS.txt`, `LICENSE-APACHE-2.0.txt`, `DATASET.md` |
| 4 | Latency-in-seconds withdrawn as a real-world quantity | **DONE** | `sica/metrics.py` docstring, `DATASET.md`, `docs/DATASET_FREEZE.md` §11 |
| 5 | Record that no session exceeds 59 s and that the idle timeout / cross-day / max-duration paths are unexercised | **DONE** | `DATASET.md`, `docs/DATASET_FREEZE.md` §9 |

**Still open, blocking publication rather than experimentation:** `paper/paper.tex` carries
the superseded `v5` rationale at line ~304 and must be corrected in the paper pass, along
with the frozen terminology (`docs/DATASET_FREEZE.md` §10) and the timing restrictions
(§11). `paper/` was not modified by either gate, by instruction.

### Original finding list (retained for the record)

These are statements that were known to be wrong or unsupported when this report was
written. `paper/` was not modified.

1. **`sica/invariants.py` and the manuscript** attribute `v5`'s benign firing rate to bursty
   page loads. The real cause is degenerate upstream timestamps (§6).
2. **`DATASET.md` §1** describes W2 as package-manager clients "fetching packages". The agents
   are genuine; the URLs are three placeholders. It should not be called real mirror traffic,
   and the file name `nginx_real.log` is itself misleading.
3. **`CITATION_OF_INPUTS.txt` and `DATASET.md`** must name `elastic/examples`, the exact
   upstream paths, Apache-2.0, and the SHA-256 of each file, and must include the license text
   (§5).
4. **Any latency-in-seconds figure** must be withdrawn or explicitly marked as an artifact of
   synthetic timestamps (§6).
5. **`DATASET.md`** should record that no session exceeds 59 s and that the 1800 s idle
   timeout, cross-day handling and maximum-duration behaviour are consequently unexercised.
