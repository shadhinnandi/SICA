# SICA Explained: The Whole Project in Simple Words

This guide explains everything about SICA in plain language: the problem, the
idea, the architecture, the workflow, the calculations, how the results are
produced and what they mean, and how the project is tested. You can read it top
to bottom, or jump to a section.

For a pen-and-paper example, see [`docs/WORKED_EXAMPLE.md`](docs/WORKED_EXAMPLE.md).
For the datasets and every file, see [`docs/DATASET_AND_FILES.md`](docs/DATASET_AND_FILES.md).

## Contents

1. [SICA in one minute](#1-sica-in-one-minute)
2. [The problem](#2-the-problem)
3. [The idea](#3-the-idea)
4. [Architecture](#4-architecture)
5. [Workflow, step by step](#5-workflow-step-by-step)
6. [The calculations](#6-the-calculations)
7. [How the evaluation is built](#7-how-the-evaluation-is-built)
8. [How the results are calculated](#8-how-the-results-are-calculated)
9. [The results and what they mean](#9-the-results-and-what-they-mean)
10. [How the project is tested](#10-how-the-project-is-tested)
11. [Limitations](#11-limitations)
12. [Quick questions and answers](#12-quick-questions-and-answers)
13. [Glossary](#13-glossary)

---

## 1. SICA in One Minute

- **What:** SICA (Session Integrity and Continuity Analysis) detects **HTTP
  session hijacking** in the middle of a session.
- **Input:** only the web server's access log. Detection uses just two columns,
  the **IP address** and the **User-Agent**.
- **How:** it describes each request by a *client binding*, runs three checks
  (V1, V2, V3), adds them up into a risk score, and compares the session's
  highest risk with a threshold.
- **Output:** **ALLOW** or **ALERT** for each session, plus the reason.
- **No machine learning:** three fixed checks, three weights and one threshold.
- **Main result:** fewer than 1 in 100 normal sessions raise an alert and more
  than 9 in 10 alerts are real attacks. It catches about a third (W1) and a
  quarter (W2) of the injected attacks.

---

## 2. The Problem

**How a web session works.** HTTP forgets everything between requests. So after
you log in, the website gives your browser a **session cookie**. Your browser
sends it with every request, and the server treats whoever sends it as you.

**What session hijacking is.** If an attacker steals that cookie (through
cross-site scripting, network sniffing, malware or a leaked log), they can send
it too. The server sees a valid cookie and serves them as if they were you.

**Why it is hard to detect.** The attacker never logs in. There is no wrong
password and no strange login to notice. Every request carries a valid cookie
and can look completely normal.

**Why the usual fix fails.** A common rule is "end the session if the IP address
changes" (**IP pinning**). But honest users change IP all the time: home Wi-Fi to
mobile data, a router renewing its address, a phone moving between towers. IP
pinning treats all of these as attacks. In our tests it wrongly flagged about
**15% of normal sessions**. Because real attacks are rare, that means almost all
of its alerts would be false.

**The question SICA answers:** can a server catch visible session hijacking
using only the logs it already has, while keeping false alarms low and every
alert easy to explain?

---

## 3. The Idea

### The client binding

For every request, SICA builds a seven-part description of the client:

```
IP address | /24 network | /16 network | browser | version | OS | device
\___________ network part ___________/   \_________ agent part ________/
```

Example: `203.0.113.25 | 203.0.113 | 203.0 | Chrome | 120 | Windows | Desktop`

Different levels mean different things:

| Change | Usual meaning | How suspicious |
|---|---|---|
| New host in the same /24 | router renewed the address | very weak |
| New /24 in the same /16 | another network of the same provider | weak |
| New /16 | left the original network | stronger |
| Browser version changed | software update | weak |
| Browser, OS or device changed | a different machine | strong |

### The binding fork (the key idea)

When an honest user moves, they move **one way** and do not come back:

```
Legitimate:   A A A A B B B B
```

When an attacker uses the session **while the victim is still browsing**, their
requests mix, and the old binding keeps **coming back**:

```
Hijacking:    A A A B A B A
```

One person who moves once cannot keep jumping back and forth. Two people sharing
one session cannot avoid it. SICA calls the return of an earlier binding a
**binding fork**.

---

## 4. Architecture

```
          WEB SERVER ACCESS LOGS
                    |
                    v
          SESSION RECONSTRUCTION
   group by (IP, User-Agent), 30-minute idle timeout
                    |
                    v
         CLIENT BINDING EXTRACTION
   IP | /24 | /16 | Browser | Version | OS | Device
                    |
                    v
      +------------------------------+
      |  V1  Agent mutation          |
      |  V2  Network discontinuity   |
      |  V3  Binding fork            |
      +------------------------------+
                    |
                    v
           WEIGHTED RISK SCORE        <----  weights w1, w2, w3
        R = w1*V1 + w2*V2 + w3*V3             (from attack-free
                    |                          calibration)
                    v
          CALIBRATED THRESHOLD        <----  threshold tau
          is the session peak >= tau?          (1% alert budget)
                    |
             +------+------+
             |             |
           ALLOW         ALERT
                           |
                    Reason: V1 / V2 / V3
```

| Block | What it does | Code |
|---|---|---|
| Access logs | the normal Apache/Nginx log lines | `data/` |
| Session reconstruction | groups requests into sessions | `sica/sessionize.py` |
| Client binding | turns IP + User-Agent into seven fields | `sica/fingerprint.py` |
| V1, V2, V3 | the three checks | `sica/invariants.py` |
| Risk, threshold, decision | adds up, compares, decides | `sica/detector.py` |
| Calibration | computes weights and threshold from attack-free sessions | `sica/detector.py` |

**Two phases:**

1. **Calibration (once per dataset).** Replay attack-free sessions to learn how
   often each check fires normally (gives the weights), then replay again to
   pick the threshold.
2. **Detection (every request).** Weights and threshold are frozen. Each request
   is processed in constant time.

---

## 5. Workflow, Step by Step

For each session, SICA remembers a small **state**:

- the **reference binding** (what V1 and V2 compare with),
- the **previous request's binding**,
- a **recent list** of up to 4 different bindings (for V3),
- the session's **peak risk** so far.

When a request arrives:

1. **First request of a session?** Save its binding as the reference and put it
   in the recent list. Risk = 0. Done.
2. **Build the binding** from the IP and User-Agent.
3. **Run V1:** compare the agent part with the reference.
4. **Run V2:** compare the network part with the reference.
5. **Run V3:** is this binding different from the previous one **and** already
   in the recent list? Then it is a return (fork).
6. **Compute the risk** `R = w1*V1 + w2*V2 + w3*V3`.
7. **Update the peak:** `peak = max(peak, R)`.
8. **Decide:** if `peak >= tau`, the session is **ALERT** (and the request number
   is recorded). Otherwise it stays **ALLOW**.
9. **Update the state:**
   - new binding: add it to the recent list and move the reference to it
     (a one-way move is only charged once);
   - returning binding: leave the reference where it is (with two clients
     alternating, there is no way to know which one is the owner).
10. **Explain:** list the checks with a value above 0, for example
    `V2_scope_discontinuity=1.00|V3_binding_fork=1.00`.

---

## 6. The Calculations

### The three checks

```
V1 (agent mutation)
  = 1.00  if browser, OS or device differs from the reference
  = 0.35  else if only the browser major version differs
  = 0     otherwise

V2 (network discontinuity)
  = 1.00  if the /16 differs from the reference
  = 0.45  else if the /24 differs
  = 0.15  else if the exact IP differs
  = 0     otherwise

V3 (binding fork)
  = 1.00  if the binding differs from the previous request's
          AND it is already in the recent list
  = 0     otherwise
```

### The weights

A check that rarely fires on normal traffic is stronger evidence, so it gets a
bigger weight. On attack-free sessions SICA measures `eps`, the average value of
each check, and then:

```
q_i = ln( 1 / (eps_i + 0.01) )        w_i = q_i / (q1 + q2 + q3)
```

The `0.01` stops a check that never fires from getting a huge weight. The weights
add up to 1, so the risk is always between 0 and 1.

Real values (W1, seed 0):

| Check | eps | q | weight |
|---|--:|--:|--:|
| V1 | 0.001397 | 4.4744 | **0.3718** |
| V2 | 0.008837 | 3.9719 | **0.3301** |
| V3 | 0.017674 | 3.5873 | **0.2981** |

### The risk and the peak

```
R    = w1*V1 + w2*V2 + w3*V3           (for every request)
peak = the largest R in the session
```

The decision uses the **peak**, not an average, so one strongly suspicious
request is enough.

### The threshold

The threshold `tau` is chosen from attack-free sessions so that **at most about
1%** of them would alert:

1. Replay the calibration sessions with the final weights.
2. Write down each session's peak.
3. Pick the **smallest** peak value that keeps at most 1% of sessions at or
   above it.

Why not just take the 99th percentile? Many sessions have exactly the same peak
(the risk only takes a few values). A percentile could land on a value shared by
many sessions and let too many through. Scanning the real values avoids this.

With 127 calibration sessions on W1, 1% of 127 is 1.27, so at most **1** session
may alert. With 1,563 on W2, at most **15** may. In W1 seed 0, `tau = 0.6282`.

For a full hand calculation, see
[`docs/WORKED_EXAMPLE.md`](docs/WORKED_EXAMPLE.md): a legitimate move gives a peak
of 0.3301 (ALLOW) and a concurrent hijack gives 0.6282 (ALERT).

---

## 7. How the Evaluation Is Built

No public dataset contains labelled HTTP session hijacks, so the project builds
test cases on real traffic.

1. **Real traffic.** Two public access logs: W1 (Apache, 10,000 requests, 254
   sessions) and W2 (Nginx, 51,462 requests, 3,126 sessions).
2. **Split.** Sessions are sorted by start time. The earlier half is for
   calibration, the later half for evaluation.
3. **Add honest mobility** to both halves: 15% of normal sessions get a one-way
   change (new IP, browser update, or both), and 5% get **flapping** (the IP
   keeps switching between two networks).
4. **Add attacks** to the evaluation half only. Each session becomes a victim
   with probability 0.2. The attacker's requests are **real requests from
   another client**, with the IP and User-Agent set according to the attacker
   level (L0 to L5), in takeover or concurrent mode.
5. **Calibrate** on the attack-free half, **detect** on the evaluation half.
6. **Compare** the decisions with the true labels (the detector never sees
   them).
7. **Repeat** with 30 different random seeds and average.

### The experiments

| ID | Question |
|---|---|
| E0 | What is inside the datasets? |
| E1 | How well does SICA work at the 1% budget? (main result, 30 seeds) |
| E1b | What happens if the budget changes from 0.1% to 10%? |
| E2 | How does SICA compare with IP pinning and other simple rules? |
| E3 | Which parts of SICA matter? (remove or add checks) |
| E4 | Which attackers are caught or missed? (each level and mode alone) |
| E5 | Could the benchmark leak the answer by accident? (leakage audit) |
| E6 | How fast is it and how much memory does it use? |
| E7 | Are the differences statistically consistent? What about rare attacks? |

---

## 8. How the Results Are Calculated

Every result is **per session**, because a security team acts on sessions.

### The four counts

| | SICA says ALERT | SICA says ALLOW |
|---|---|---|
| **Really hijacked** | True Positive (TP) | False Negative (FN) |
| **Really normal** | False Positive (FP) | True Negative (TN) |

### The metrics

| Metric | Formula | Meaning |
|---|---|---|
| Recall | TP / (TP + FN) | share of attacks caught |
| FPR (false-positive rate) | FP / (FP + TN) | share of normal sessions wrongly flagged |
| Precision | TP / (TP + FP) | share of alerts that are real attacks |
| F1 | 2 x Precision x Recall / (Precision + Recall) | balance of precision and recall |
| ROC AUC | area under the ROC curve | chance that a random attacked session gets a higher peak than a random normal one (0.5 = guessing, 1.0 = perfect) |
| PR AUC | area under the precision-recall curve | how precise SICA stays as it catches more attacks |
| Delay | attacker requests until the alert | how fast SICA reacts |

### A rough example with the W1 numbers

In one W1 run there are 127 evaluation sessions, and on average about 21.7 are
hijacked and 105.3 are normal.

```
TP = 0.358 x 21.7     = about 7.8 attacks caught
FN = 21.7 - 7.8       = about 13.9 attacks missed
FP = 0.0085 x 105.3   = about 0.9 false alarms
TN = 105.3 - 0.9      = about 104.4 normal sessions allowed

Precision = 7.8 / (7.8 + 0.9) = about 0.90
```

This matches the reported precision of 0.906. (The reported values are averages
of the per-seed results, so a calculation from averages differs slightly.)

### Averaging and confidence

Each metric is computed for each of the 30 seeds, then averaged. The 95%
confidence interval comes from bootstrapping: resampling the 30 seed values
10,000 times and taking the middle 95% of the resampled means.

---

## 9. The Results and What They Mean

### Main result (E1, 1% budget, 30 seeds)

| Dataset | ROC AUC | Recall | FPR | Precision | F1 | PR AUC | Delay |
|---|---|---|---|---|---|---|---|
| W1 | 0.884 | 0.358 | 0.85% | 0.906 | 0.497 | 0.742 | 1.4 requests |
| W2 | 0.851 | 0.229 | 0.56% | 0.920 | 0.362 | 0.667 | 2.5 requests |

- **Low false alarms:** below 1% of normal sessions on both datasets.
- **High precision:** more than 9 of 10 alerts are real attacks.
- **Fast reaction:** alerts usually come within 1 to 3 attacker requests.
- **Limited recall:** about a third (W1) and a quarter (W2) of attacks are caught.

SICA deliberately chooses **few false alarms over catching everything**.

### SICA versus IP pinning (E2)

| Detector | W1 recall | W1 FPR | W2 recall | W2 FPR |
|---|---|---|---|---|
| **SICA** | 0.358 | **0.85%** | 0.229 | **0.56%** |
| Pin IP address | 0.711 | 15.3% | 0.695 | 15.0% |

IP pinning catches more attacks, but flags about 15% of honest users. SICA's
false-alarm rate is more than ten times lower, chosen in advance, and every
alert is explained. Some pinning rules reach a higher F1, so SICA is not better
at everything; its strength is controlled, explainable alerts.

### Which attackers are caught (E4, recall)

| Level | Attacker | W1 concurrent | W2 concurrent | W1 takeover |
|---|---|---|---|---|
| L0 | other network, own browser | 0.993 | 0.893 | 0.882 |
| L1 | other network, copied browser | 0.700 | 0.718 | 0.002 |
| L2 | same /16, own browser | 0.886 | 0.405 | 0.173 |
| L5 | victim's IP, own browser | 0.891 | 0.485 | 0.002 |
| L3 | same /24, copied browser | 0.015 | 0.005 | 0.002 |
| L4 | exact copy of the victim | 0.015 | 0.007 | 0.002 |

- The **binding fork** catches 70% of L1 concurrent attacks even though the
  attacker copied the browser, because the victim's binding keeps returning.
- **Silent takeovers** with a copied browser look like a normal move, so they
  are missed.
- **L4** is an exact copy of the victim's binding: nothing in the log differs.

### Where false alarms come from

Normal sessions with no change, browser updates, and IP changes inside a /16
**never** caused an alert. Almost all false alarms come from **flapping across
two networks** (about 58% of those sessions), which looks exactly like a fork.

### Changing the budget (E1b)

At a 5% budget, recall rises to **0.646** (W1) and **0.445** (W2), with FPR of
4.4% and 3.9%. The operator can choose the balance.

### Real-world attack rates (E7)

In the tests about 17% to 19% of sessions are attacked. In real life attacks are
much rarer. If only 1 in 100 sessions is attacked, precision drops to about 30%;
at 1 in 1,000, to about 4%. This is why keeping the false-alarm rate low matters
so much.

### Speed (E6)

About **55,000 requests per second** in Python, about **16 microseconds** per
request, and a few kilobytes of memory per live session. The cost per request
stays flat as the number of sessions grows.

---

## 10. How the Project Is Tested

The project is checked at four levels.

### 1. Unit and regression tests: 50 tests

```bash
python run.py --test
```

- `tests/test_sica.py` checks each part: IP prefixes and User-Agent parsing,
  the grading of V1 and V2, that V3 fires only on a return, that a one-way move
  is charged once, bounded state, weights, the threshold budget, attack
  injection, attack-free calibration and reproducibility.
- `tests/test_regressions.py` locks in bugs that were fixed during development
  (tied thresholds, attacker levels, session IDs, AUC calculations), so they
  cannot come back.

### 2. Result validation: 56 checks

Run automatically at the end of `python run.py`, or alone with:

```bash
python run.py --report
```

It confirms, among other things, that:

- every expected table and figure exists,
- both datasets and all 30 seeds are present,
- every run met its 1% budget on the calibration sessions,
- the attacker grid covers L0 to L5 in both modes,
- the pinning baselines do not report a ranking score they cannot have,
- the ablation covers every check,
- the detector code imports **no machine-learning library**.

### 3. Leakage audit (E5): is the test fair?

A built benchmark could accidentally give away the answer (for example, attacked
sessions being longer). E5 checks this:

- No simple session feature (length, bytes, timing, errors) separates attacked
  from normal sessions well.
- A detector built only on those features performs very poorly (F1 about 0.02).
- Different ways of splitting the data give similar results.
- All **26 structural checks** pass (calibration is attack-free, the halves do
  not overlap, attacked sessions keep their length).

### 4. Fair design choices

- The final checks (V1, V2, V3) were chosen on **separate development seeds**
  (100 to 119), never on the reported seeds (0 to 29).
- Weights and threshold use **only attack-free sessions**, never attack labels.
- Every result is **deterministic**: the same seeds give the same numbers.

### Running everything

```bash
pip install -r requirements.txt
python run.py --test      # code tests
python run.py --all       # all experiments, figures, summary, validation
cat results/summary/summary.md
```

---

## 11. Limitations

- **Attacks are simulated.** They are injected into real traffic using real
  requests, but they are not recorded real incidents.
- **Honest mobility is modelled.** The rates are assumptions (E4 tests other
  rates).
- **Small, sample datasets.** W1 has only 254 sessions; W2 is demo traffic with
  three URLs.
- **Broken timestamps.** The minute field is almost always the same, so no
  timing claims are made.
- **Sessions are rebuilt** from (IP, User-Agent), because logs contain no cookies.
- **Blind spots.** An exact copy of the victim's binding (L4) is invisible, and
  silent takeovers with a copied browser look like normal moves.
- **Low recall** at the 1% budget.

---

## 12. Quick Questions and Answers

**Is SICA machine learning?**
No. The checks and their values are fixed. Only three weights and one threshold
are computed, with simple formulas, from attack-free traffic.

**Why use the peak risk and not the total?**
One clearly suspicious request should be enough. A total would also punish long
normal sessions.

**Why does a legitimate network change not alert?**
It gives at most one request with V2 = 1 (risk 0.3301), and then the reference
moves to the new network. That is below the threshold.

**Why is the binding fork so important?**
It catches an attacker who copies the victim's browser: V1 stays silent, but as
soon as the victim's next request arrives, the old binding returns and V3 fires.

**What is SICA's main weakness?**
Low recall. Silent takeovers and exact copies of the victim's binding are not
visible in the IP and User-Agent alone.

**Why is a 1% false-alarm rate so important?**
Attacks are rare. With many false alarms, the security team would mostly chase
honest users.

**Can the budget be changed?**
Yes. At 5%, SICA catches about 65% (W1) and 45% (W2) of attacks.

---

## 13. Glossary

| Term | Meaning |
|---|---|
| Session | the requests that share one login cookie |
| Session hijacking | an attacker using someone else's stolen session cookie |
| Access log | the text file a web server writes, one line per request |
| User-Agent | the text a browser sends to describe itself |
| /24, /16 | the first three or first two parts of an IPv4 address |
| Client binding | the seven-part description of the client for one request |
| Reference binding | the binding that V1 and V2 compare with |
| Binding fork | an earlier binding coming back after a different one |
| Risk (R) | weighted sum of V1, V2 and V3 for one request |
| Peak | the highest risk in a session |
| Threshold (tau) | the peak value at which a session alerts |
| Alert budget (alpha) | the target share of normal sessions allowed to alert (1%) |
| Calibration | computing weights and threshold from attack-free sessions |
| Takeover | the victim stops and only the attacker continues |
| Concurrent | the victim and the attacker both keep using the session |
| Flapping | a device switching back and forth between two networks |
| Seed | a random-number setting that fixes one version of the experiment |
