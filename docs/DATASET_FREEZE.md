# Dataset Freeze

**Date.** 2026-09-12. Created after the independent verification recorded in
`docs/DATASET_VERIFICATION.md`. This file did not previously exist.

**Status: FROZEN, with the qualifications in §9 and §10.** The corpus is suitable for the
SICA benchmark as it is actually constructed — a binding-based, clock-free detector — and is
**not** suitable for any timing-based claim. Nothing here may change without the
`CHECKPOINT.md` §9 change-control procedure.

---

## 1. Approved raw sources

Exactly two files. No other dataset is part of this benchmark.

| ID | Path | SHA-256 | Bytes | Records |
|---|---|---|---|---|
| W1 | `data/raw/apache_sample_1.log` | `f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef` | 2,370,789 | 10,000 |
| W2 | `data/raw/nginx_real.log` | `526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df` | 6,991,577 | 51,462 |

Both hashes were verified byte-identical against upstream on 2026-09-12.

## 2. Provenance — VERIFIED

| | W1 | W2 |
|---|---|---|
| Repository | `github.com/elastic/examples` | same |
| Path | `Common Data Formats/apache_logs/apache_logs` | `Common Data Formats/nginx_logs/nginx_logs` |
| Retrieved | `https://raw.githubusercontent.com/elastic/examples/master/…`, HTTP 200 | same |
| Transformation applied | **none** — renamed only | **none** — renamed only |
| Verification | byte-identical (SHA-256 and size) | byte-identical (SHA-256 and size) |

**Ultimate origin of the traffic: UNKNOWN.** Upstream describes both only as "sample files"
for a getting-started example and makes no claim that either is captured production traffic.
W2's URL universe is three placeholder paths (`/downloads/product_1|2|3`) with a 65.8% 404
rate; it is a demo corpus. The filename `nginx_real.log` is misleading and the word "real"
must not be used for it in the manuscript.

## 3. Licensing — VERIFIED for redistribution, with an unmet obligation

* **License: Apache License 2.0**, from the `elastic/examples` repository-root `LICENSE`
  (retrieved 2026-09-12, HTTP 200, full Apache-2.0 text). No `NOTICE` file exists; no
  per-directory override.
* **Redistribution of the raw files in this repository: PERMITTED.**
* **Attribution: REQUIRED** — Apache-2.0 §4 obliges retaining the license, including a copy of
  it, and stating the changes made.
* **OUTSTANDING:** `CITATION_OF_INPUTS.txt` and `DATASET.md` currently name no source, no URL
  and no license. Before release they must state the repository, both exact upstream paths,
  Apache-2.0, the SHA-256 of each file, and that the only change was renaming. A copy of the
  Apache-2.0 text must be included.
* **UNKNOWN, and marked so:** the license governs Elastic's distribution of these files. It
  establishes nothing about the collection, consent or anonymisation of the underlying
  traffic.

## 4. Privacy status

* No credentials, cookies, session identifiers, bearer tokens, API keys or JWTs in either file.
  `authuser` is empty in all 61,462 records.
* **Client IP addresses are real, public and unmasked** (1,753 in W1; 2,660 in W2, of which 60
  are private/reserved). This is personal data in most jurisdictions and is the material
  exposure. The data is **not anonymised** and must not be described as such.
* 198 email-shaped strings occur in W1, all inside bot User-Agent strings as crawler operator
  contact addresses (7 distinct). Not end-user PII.
* No query-parameter secrets; no location parameters.

## 5. Sessionization rules — FROZEN

* Grouping key: **(remote address, User-Agent)**. Ground-truth construction only; the detector
  receives a session identifier and never the key.
* Idle timeout: **1800 s**. Minimum session length: **7 requests**. No maximum duration.
* Ordering: stable sort by timestamp; 0 out-of-order records in either corpus.
* Session identifier: `"{address}|{blake2s(ua, 6 bytes)}|{index}"` — deterministic across
  processes, unique on both corpora.
* Malformed records: 0 in both files; the parser drops unparseable lines and none occur.
* Empty sessions: impossible by construction; 0 observed.

## 6. Injection rules — FROZEN

* Attacker request **content** is real, taken verbatim from a different real client of the same
  server. Nothing is fabricated.
* Sessions are **length-matched exactly**.
* Theft point is drawn from `[earliest_takeover, latest_takeover]` and is **never moved**;
  unrealisable requests are refused and counted.
* Masquerade levels are defined relative to the victim's binding **at the theft point**.
* Reported envelope: **L0–L5** (L0–L3 address-visible; L4/L5 co-located). Modes: takeover,
  concurrent. A concurrent injection must genuinely interleave at every swept delay.
* Benign churn is applied to **both** partitions; attacks are injected into the **evaluation
  partition only**.

## 7. Excluded datasets

| File | Status | Reason |
|---|---|---|
| `apache_sample_2.log` | **EXCLUDED / OBSOLETE — absent** | v1 file; byte-identical in content to `nginx_real.log` (AUDIT.md O4). Must never be reinstated, and the pair must never be presented as two source families |
| `web_sessions.csv` | **EXCLUDED / OBSOLETE — absent** | v1 synthetic file that supplied all 803 v1 attack labels (AUDIT.md O3) |
| `network_flows.csv` | **EXCLUDED / OBSOLETE — absent** | v1 network port-scan flows; wrong phenomenon |
| `auth_events.csv`, `historical.csv`, `evaluation.csv` | **UNKNOWN — absent** | No trace in this repository; cannot be classified |

No derived, processed or cached dataset is stored on disk. Every benchmark artifact is
constructed in memory per seed and is reproducible from the two raw files plus the seed.

## 8. Exact final benchmark composition

**The contract.** The benchmark uses **real public observations as the traffic substrate**
and **controlled session-hijacking injection** as the attack condition. There is no third
ingredient.

| Role | Source | Raw requests | Sessions (≥7 requests) |
|---|---|---|---|
| **PRIMARY** | W1 — `data/raw/apache_sample_1.log` (Apache sample) | **10,000** | **254** |
| **SECONDARY** | W2 — `data/raw/nginx_real.log` (Nginx sample/demo) | **51,462** | **3,126** |

**Synthetic attack datasets are NOT part of the primary benchmark**, and none exists in this
repository. Attack *content* is always real traffic copied verbatim from a different real
client of the same server; only the binding, the placement and the labels are constructed.
The v1 synthetic files (`web_sessions.csv`, `network_flows.csv`) are excluded permanently —
see §7. No file may be added to this benchmark without the `CHECKPOINT.md` §9 procedure.


| Stage | W1_web | W2_apt |
|---|---|---|
| Raw lines | 10,000 | 51,462 |
| Parsed requests (0 malformed) | 10,000 | 51,462 |
| Distinct (IP, UA) clients | 1,862 | 2,797 |
| Sessions ≥1 request | 3,224 | 7,489 |
| **Benign corpus** (≥7 requests) | **254 sessions / 3,874 requests** | **3,126 sessions / 43,307 requests** |
| Calibration / evaluation (temporal 50/50) | 127 / 127 | 1,563 / 1,563 |
| Attack rate | 0.20 of evaluation sessions | 0.20 |
| Injected attacks (seed 0) | 18 | 322 |
| Refused as unrealisable (seed 0) | 2 | 8 |

Benign churn: 15% monotone, 5% flapping, applied to both partitions.
Seeds: reporting 0–29 (E1/E2) and 0–19 (E3/E4/E5); development 100–119; bootstrap seed 0.
α = 0.01. None of these changed.

## 9. Known limitations — binding on how results may be described

1. **Upstream timestamps are degenerate.** The minute field is `05` in all 10,000 W1 records
   and `05|06` in W2. Consequently **no session exceeds 59 seconds**, none crosses a day
   boundary, and all inter-arrival times are generator artifacts.
   * No timing-based claim may be made from this corpus.
   * Detection latency **in seconds** must not be reported as a real-world quantity; latency
     in requests remains valid.
   * The 1800 s idle timeout, cross-day handling and maximum-duration behaviour are
     **unexercised** by this data.
   * The stated reason for rejecting `v5` ("bursty page loads") is wrong and must be corrected
     to the real one.
   * `theft_delay_s` is an **inert** experimental condition here and must be reported as such
     or dropped with the reason recorded.
2. **The study survives this only because the locked invariant set reads no clock.** Verified
   mechanically: `v1`, `v2` and `v3` take no timestamp, gap or duration argument.
3. **W2 is a demo corpus**, not real mirror traffic: three URL paths, 65.8% 404s, 0.025%
   referer coverage.
4. **Two residual marginal shortcuts** exist and are documented, not removed: `distinct_paths`
   on W2 (AUC 0.733, an artifact of a 3-path universe) and `median_gap_s` on W1 (AUC 0.322, an
   artifact of gap compression over synthetic timestamps). Neither is legitimate hijacking
   signal; neither can reach the detector.
5. **Session identity is reconstructed, not observed** — these logs carry no authentication
   state. This is the foundational limitation of the whole benchmark.
6. **W1 is small** (254 sessions); its intervals are wide and it must not carry a claim alone.
7. **Donors are drawn from the evaluation partition**, so attacker content is not statistically
   independent of the benign population. Deliberate: it is what makes attacker content
   inseparable from benign content.
8. **Client IPs are real and unmasked** (§4).

## 10. Frozen terminology

The distinction between a public sample log with injected attacks and a real-world attack
dataset is the single claim most likely to be overstated, so the vocabulary is frozen here.

**Allowed:**

* "controlled session-hijacking injection"
* "attack requests drawn from real observed traffic"
* "evaluation on public real web-log traffic with injected attacks"
* "public sample log" / "sample/demo log data from the Elastic Examples repository"

**Not allowed**, unless later evidence independently supports them:

* "real-world attack dataset"
* "production attack validation"
* "production traffic validation"
* "real-world attack detection"
* any description of W2 as production or package-mirror traffic
* any description of either log as anonymised

The substrate is real observed traffic; the attacks are constructed. Both halves of that
sentence must survive into every description of the benchmark.

## 11. Timing and efficiency metrics

Because the source timestamps are degenerate (§9.1), the two kinds of "latency" in this
project must never be conflated.

**Not permitted — traffic-derived timing:**

* wall-clock detection latency in seconds
* any claim about realistic temporal behaviour, session duration, or user cadence
* timestamp distributions as evidence of realistic client behaviour
* `latency_seconds_median` as a real-world result (the field is still computed; it is
  marked in `sica/metrics.py` as not reportable)

**Permitted — detector-derived computation cost**, which is measured on this machine and is
independent of the traffic's timestamps:

* processing time per request
* throughput (requests/second)
* p50 / p95 / p99 computational latency
* per-session state footprint
* `latency_requests_*` — how many attacker requests elapse before the alert, which is a
  count, not a clock reading

No experiment may be designed that claims realistic wall-clock detection delay on this
corpus.

## 12. Status of this freeze

The three obligations that were open when this file was first written are now **closed**:

| Obligation | Status | Where |
|---|---|---|
| Licensing attribution — repository, paths, URLs, Apache-2.0, SHA-256 | **DONE** | `CITATION_OF_INPUTS.txt`, `LICENSE-APACHE-2.0.txt` (full license text added), `DATASET.md` |
| W2 described accurately as sample/demo data with placeholder URLs | **DONE** | `DATASET.md`, `README.md`, `CHECKPOINT.md`, §2 and §9 above |
| `v5` rejection rationale corrected; latency-in-seconds qualified | **DONE** | `sica/invariants.py` (docstring), `AUDIT.md`, `sica/metrics.py` (docstring), §9 and §11 above |

**One obligation remains open and blocks publication, not experimentation:**
`paper/paper.tex` still carries the superseded `v5` rationale ("ordinary page loads are
bursty", line ~304) and must be corrected during the paper pass, together with the
terminology of §10 and the timing restrictions of §11. `paper/` was not modified by this
gate, by instruction.

`results/` was not modified. `data/raw/` was not modified — both SHA-256 values still match
upstream. Seeds, α and the locked invariant set are unchanged.
