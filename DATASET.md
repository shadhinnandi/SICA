# Datasets

This study uses two real web-server access logs as its **benign** substrate and
constructs its **attack** condition on top of them. This document states exactly
what is real, what is constructed, where each part comes from, and what it may
and may not be claimed to show.

> **The one-line summary.** The background traffic is real. The hijacks are
> injected and are described as injected everywhere in this repository and in the
> manuscript. The attacker's *requests* are nevertheless real requests, taken
> verbatim from other real clients of the same server, so the attack class is not
> a different traffic distribution wearing an attack label.

---

## 1. Source data

| ID | File | Server | Format | Bytes | Requests |
|---|---|---|---|---|---|
| W1 | `data/raw/apache_sample_1.log` | Apache | NCSA combined | 2.4 MB | 10,000 |
| W2 | `data/raw/nginx_real.log` | Nginx | NCSA combined | 7.0 MB | 51,462 |

**W1 — human web browsing.** A public sample access log distributed with
log-processing tutorials and widely reused as a demonstration corpus. It records
requests to a personal/technical website over 2015-05-17 to 2015-05-20:
mixed human browsing, feed readers and crawlers, 1,753 distinct client addresses
and 558 distinct `User-Agent` strings. It is the primary workload because its
client population is diverse, which is the regime a real application sees.

**W2 — Nginx sample/demo log.** Public Nginx **sample/demo log data from the
Elastic Examples repository**, covering 2015-05-17 to 2015-06-04. Its
`User-Agent` population is almost entirely Debian/Ubuntu APT clients: 2,660
addresses but only 136 `User-Agent` strings and 22 distinct agent cores, and
effectively no `Referer` values (13 records, 0.025%). It is included **because it
is adversarial to the method**: agent-based evidence is nearly useless on it, and
the referrer invariant cannot fire at all, so it tests whether the detector
degrades gracefully rather than silently.

> **This is sample/demo data, not production traffic.** Independent verification
> (`docs/DATASET_VERIFICATION.md`) established that the file's entire URL universe
> is three placeholder paths — `/downloads/product_1`, `product_2`, `product_3` —
> and that 65.8% of its responses are 404. The upstream repository describes it
> only as a sample file for a getting-started example and makes no claim that it
> is captured production traffic. It must not be described as a real package
> mirror's logs, and the filename `nginx_real.log` is misleading: the word "real"
> refers to nothing verified. The low path diversity is a corpus limitation and is
> the direct cause of the residual `distinct_paths` shortcut reported in §7.

### Degenerate timestamps — a corpus limitation that bounds what may be claimed

Independent verification (`docs/DATASET_VERIFICATION.md` §6) established that the
**minute field of both source logs is degenerate**:

* W1: the minute is `05` in **all 10,000** records — one distinct value.
* W2: the minute is `05` or `06` and nothing else (42,040 / 9,422).

Hours and seconds are spread normally, so the upstream generator evidently
produced timestamps as `<date>:<hour>:05:<second>`. The consequences are
mechanical and were measured, not assumed:

* **No sessionised session exceeds 59 seconds**, and none crosses a day boundary,
  in either corpus. A "session" here is a one-minute burst.
* Every inter-arrival gap is an artefact of the generator, not an observation of
  client behaviour.
* The 1800 s idle timeout, cross-day handling and maximum-session-duration
  behaviour are therefore **unexercised** by this data.

What follows, and is binding on how results may be described:

1. **No claim about realistic temporal behaviour** may be made from this corpus,
   and timestamp distributions may **not** be cited as evidence of realistic user
   behaviour.
2. **Detection latency in seconds must not be reported as a real-world timing
   result.** Latency in *attacker requests* is unaffected and is the latency
   measure this study quotes. Computational latency and throughput from E6 are
   also unaffected — they time the detector, not the traffic.
3. **`v5` must not be used as a primary invariant** on this benchmark, and `v4`
   cannot be assessed here at all (its 300 s settle time exceeds the longest
   session fivefold).
4. **The detector is unaffected.** The locked invariant set — `v1`, `v2`, `v3` —
   consumes no timestamp, no inter-arrival gap and no session duration. This was
   verified mechanically, and it is the reason this corpus remains usable for the
   study as designed.

### Provenance and redistribution

Both files are **public sample logs from the Elastic Examples repository**
(`github.com/elastic/examples`), redistributed unmodified under the Apache
License 2.0. Each was verified byte-identical to its upstream original by
SHA-256; exact paths, URLs and hashes are recorded in `CITATION_OF_INPUTS.txt`
and `docs/DATASET_FREEZE.md` §2. They are included so that the study is
reproducible without a download step.

The license governs Elastic's distribution of these files. It establishes
**nothing** about the collection, consent or anonymisation of the underlying
traffic, and upstream documents neither. Nothing beyond "public sample log" is
claimed about their origin.

Neither log carries authentication data, cookies, session identifiers,
credentials or tokens. Both carry **client IP addresses**, which are personal
data in most jurisdictions; see §8.

If these files must be removed for a redistribution, `run_all.sh` will stop in
its preflight stage with a message naming the missing files rather than failing
obscurely later. The study can then be re-run against any pair of NCSA
combined-format access logs by editing the `WORKLOADS` entry in
`pipeline/common.py`; nothing in the code is specific to these two files.

### What these logs are *not*

* They are **not** a session-hijacking dataset. They contain no attacks and no
  labels, and none is claimed for them.
* They are **not** authenticated-application traffic. They are public web and
  package traffic, so "session" here means a client's request run, not a
  logged-in application session. This is stated as a limitation in the
  manuscript rather than glossed.
* They are a decade old. Client-population statistics (agent mix, address
  churn) have moved since.

---

## 2. Processing chain

```
data/raw/*.log
    │  sica/sessionize.py :: parse_log
    ▼
request table   (address, agent, timestamp, path, referrer, status, bytes)
    │  sica/sessionize.py :: sessionize    idle 1800 s, ≥7 requests
    ▼
benign session corpus                       ← real traffic ends here
    │  sica/harness.py :: split_sessions    temporal | client | random
    ├──────────────► calibration partition  (never injected; attack-free)
    ▼
evaluation partition
    │  sica/churn.py  :: apply_churn        benign mobility, declared rates
    │  sica/inject.py :: inject_mixture     hijack injection, seeded
    ▼
labelled evaluation corpus
```

No intermediate file is written: every stage runs in-process and is a
deterministic function of the raw log and the seed. There is therefore no
possibility of a stale derived dataset disagreeing with the code that produced
it — the failure mode that produced several of the invalid results in the
previous version of this project.

### 2.1 Parsing

`parse_log` applies one regular expression for the NCSA combined format and
discards lines that do not match or whose timestamp will not parse. Request
paths keep their query string in the raw table; the monitor normalises them (see
§2.5). No other filtering is applied — bots, crawlers and error responses are
all retained, because they are part of the false-alarm surface a real detector
faces.

### 2.2 Sessionisation

Requests are grouped by the pair `(remote address, User-Agent)` and cut wherever
the inter-arrival gap exceeds **1800 s**, the standard idle-timeout convention in
web-log analysis (Catledge & Pitkow 1995 measured 25.5 min; Cooley et al. 1999
established the 30 min convention). Sessions with fewer than **7 requests** are
discarded so that every retained session can admit a theft point with requests on
both sides.

**The grouping key is ground truth, not a detector input.** It defines which
requests genuinely came from one client, which is what makes it possible to label
an injected request as *not* belonging to that client. The detector never sees
the grouping: it sees only a session identifier. In a real deployment the
identifier would be the application's own session cookie, which is a cleaner
signal than this reconstruction.

Sensitivity of the session yield to both parameters is reported in
`results/tables/e0_sessionisation_sensitivity.csv`, and the minimum-length
parameter is swept in E4.

### 2.3 Benign churn — mobility in the negative class

Grouping by `(address, agent)` gives clean ground truth but has a consequence
that must be corrected: **within such a session the address and agent are
constant by construction**, so benign binding changes are impossible. Evaluating
a continuity detector against that negative class would be vacuous — every
binding change would be an attack, and the false-alarm rate of the binding
invariants would be zero for a reason having nothing to do with the detector. It
would also hand an unearned victory to IP-pinning baselines.

`sica/churn.py` therefore injects *legitimate* mobility into a declared share of
benign sessions:

| Class | What changes | Shape | Rate |
|---|---|---|---|
| `M1_handover` | address changes mid-session | monotone | ⅓ of 0.15 |
| `M2_agent_update` | browser major version increments | monotone | ⅓ of 0.15 |
| `M3_combined` | both at the same point | monotone | ⅓ of 0.15 |
| `M4_flapping` | client alternates between two addresses | **interleaved** | 0.05 |

Address changes occur at one of three granularities, because conflating them is
exactly the pinning defect: **50%** a new address inside the same `/24` (DHCP
lease renewal, carrier-NAT pool rotation — the common case), **30%** a new `/24`
inside the same `/16`, **20%** a new `/16`.

`M4_flapping` is included deliberately: it is the one benign phenomenon that
produces an interleaved binding sequence and therefore mimics a live hijack. Its
cost is measured rather than assumed, and it turns out to be the detector's only
structural false-alarm source.

**These rates are assumptions about a deployment, not measurements.** No number
in this repository is presented as an estimate of how often real clients move.
Each rate is swept across its plausible range in E4 and the corresponding results
are reported as curves; the address-churn sweep is the one that decides the
comparison against address pinning.

Churn is applied to **both** partitions with the same rates, because the
calibration traffic an operator would actually use is itself subject to
legitimate mobility, and a budget that only holds on artificially clean
calibration data is not a budget.

### 2.4 Attack injection

`sica/inject.py`. For a targeted session: a theft point is drawn between 25% and
50% of its length, a donor is chosen, and attacker requests are inserted.

**Three properties make the construction resistant to shortcut learning.**

1. **The attacker's requests are real.** Each is taken verbatim — path,
   referrer, status code, response size, inter-arrival gap — from a *different
   real client of the same server*. Only the binding (address, agent) is
   substituted. Identical request content therefore appears in both classes, and
   the attack class is not a different traffic distribution.
2. **The construction is length-matched.** Attacker requests *replace* an equal
   number of the victim's, so an injected session has exactly the request count
   of the original. Without this, request count alone predicts the label.
3. **The negative class contains mobility** (§2.3), so binding change is not
   synonymous with attack.

**Masquerade level** — how much of the victim's binding the attacker reproduces:

| Level | Attacker address | Attacker agent |
|---|---|---|
| `L0` | donor's own (forced to a different `/16`) | donor's own |
| `L1` | donor's own (different `/16`) | **victim's** (cloned) |
| `L2` | synthetic, in victim's `/16`, different `/24` | donor's own |
| `L3` | synthetic, in victim's `/24` | **victim's** (cloned) |
| `L4` | **the victim's own address** (shared NAT/proxy) | **victim's** (cloned) |
| `L5` | **the victim's own address** (shared NAT/proxy) | donor's own |

**`L0`–`L5` form the reported envelope.** `L0`–`L3` are *address-visible*; `L4`
and `L5` are *co-located*, presenting the victim's own address. `L4` also clones
the agent, so no binding-based server-side signal can separate it — reported
rather than excluded. `L5` is the co-located attacker on a different client
program, which carries no address signal but does break agent continuity.
Evaluating on `L0`–`L3` alone would make address pinning perfect by construction.

**Concurrency** — whether the victim keeps using the session:

* `takeover` — the victim falls silent at the theft point and issues nothing
  further; the attacker replaces the whole remaining tail. The attacker's share
  is therefore fixed by the theft position.
* `concurrent` — the victim keeps browsing. `attack_fraction` (0.40) of the
  session's requests are the attacker's, an equal number of the victim's
  post-theft requests are displaced, and **the final request of the session is
  never displaced**, so the interleaving is real. Attacker timestamps preserve
  the donor's gap *pattern*, compressed where necessary to fit inside the
  victim's remaining window; only compression is applied. This alters
  inter-arrival magnitudes, which is admissible because no retained invariant
  reads a timestamp difference (see §5).

Both of these definitions were corrected during the audit: an earlier revision
derived the theft point and the attacker's share independently, so "takeover"
silently contained victim traffic after the theft, and "concurrent" produced no
interleaving in 40% of cases. `tests/test_sica.py` now asserts both properties.

### 2.5 Normalisation seen by the detector

The monitor derives, per request:

* `/24` prefix and `/16` scope of the address, plus the full address;
* a fixed-rule parse of `User-Agent` into (browser family, major version, OS
  family, device class); absent or unparseable agents map to an explicit
  `unknown` identity rather than to a missing value;
* the request path with query string and fragment stripped, so that it is
  comparable with a normalised `Referer`.

---

## 3. Labels

| Level | Label | Source |
|---|---|---|
| Request | `injected ∈ {0,1}` | ground truth of the injection |
| Session | `label ∈ {0,1}` | 1 iff the session contains ≥1 injected request |
| Session | `scenario` | `benign`, `M*` churn class, or `L*_{mode}` |

Labels are read **only** to compute metrics, after every decision has been
produced. They never enter calibration, weighting, thresholding or invariant
selection. `tests/test_sica.py::test_calibration_ignores_labels_entirely`
asserts that adversarially relabelling the calibration partition changes neither
the weights nor the threshold.

---

## 4. Splits

| Split | Definition | Role |
|---|---|---|
| `temporal` (default) | earliest 50% of sessions calibrate, latest 50% evaluate | reported |
| `client` | clients partitioned; no client in both | leakage control |
| `random` | sessions partitioned uniformly | leakage control |

Attacks are injected **only** into the evaluation partition, so the calibration
partition is attack-free by construction rather than by filtering.

Separately from the calibration/evaluation split, the study uses **disjoint seed
blocks**: seeds 0–29 for reported results, seeds 100–119 for the two development
studies that chose the evidence rule, reference migration and the composition of
the invariant set. Nothing was selected on the reporting seeds.

---

## 5. Why residual marginal signal cannot help the detector

The leakage audit (E5) scores each per-session summary feature alone against the
injected label. Two retain a small deviation from chance: session `duration_s`,
because displacing tail requests shortens the span, and `distinct_paths` on W2.

The retained invariants are `v1` (agent), `v2` (network scope) and `v3` (binding
fork). **None of them reads an inter-arrival gap, a byte count, a request count,
a session duration or a request path.** The invariants that did — `v4`
(velocity), `v5` (rate) and `v6` (which reads paths and referrers) — were all
rejected on development data before the reported experiments were run. Residual marginal signal in those quantities
therefore cannot reach the detector, and the leakage report asserts this
mechanically.

---

## 6. Class distribution

The benchmark targets 20% of evaluation sessions for injection; the realised
attack prevalence is recorded per run in `results/tables/e1_main_runs.csv`
(`attack_prevalence`) and is slightly lower, because a session with no admissible
donor is left benign rather than being weakened. The realised figure is what is
reported.

**20% is a benchmark prevalence, not a deployment prevalence.** Precision
measured at it does not transfer. `results/tables/e7_base_rate.csv` recomputes
precision and alert volume from the measured true- and false-positive rates
across prevalences from 10⁻⁵ to 0.2, and the manuscript uses those figures when
discussing deployability. The test set is never rebalanced.

---

## 7. Known limitations

1. **W1 is small** — 254 sessions at the reported parameters, so its intervals
   are wide. Thirty repetitions of the benchmark draw mitigate but do not remove
   this.
2. **Both logs are unauthenticated public traffic**, so session identity is
   reconstructed rather than observed.
3. **Both logs are from 2015.**
4. **The benign mobility model's shape is ours.** Its rates are swept, but real
   clients may move in ways it does not generate. In particular it assigns zero
   probability to a mid-session agent-*core* change; real causes exist
   (desktop-site toggles, in-app browser hand-off, proxy rewriting), so the 0%
   false-alarm rate measured for agent-core pinning is an upper bound on that
   baseline rather than a measurement.
5. **The attacker's timing is a real client's timing**, which deliberately denies
   the evaluation any rate-based signal. Against a scripted adversary the
   rejected `v5` would carry information this evaluation cannot credit it with.
6. **No NAT ground truth.** `L4` models the co-located adversary, but the logs do
   not tell us which real clients were behind shared NAT, so the prevalence of
   that case in practice is not estimated here.

---

## 8. Ethics and personal data

The logs contain client IP addresses. They are public sample logs redistributed
unmodified for reproducibility. No attempt is made to identify any client; no
address appears in the manuscript, in any generated figure, or in any generated
table; and the detector stores no request content. Anyone redistributing this
repository inherits the retention and minimisation obligations that already apply
to web access logs.

The injection code operates only on these static files. It presupposes a stolen
session identifier rather than providing one, and contains nothing that attacks a
live system: it is a benchmark generator for evaluating detectors.
