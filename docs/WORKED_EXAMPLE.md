# SICA by Hand: Two Sessions, One Calculator

This page walks through two short sessions with pen and paper:

1. **Scenario 1:** Rafi, a legitimate user, switches from home Wi-Fi to mobile
   data. SICA says **ALLOW**.
2. **Scenario 2:** an attacker steals Rafi's session cookie and uses it while
   Rafi is still browsing. SICA says **ALERT**.

All the numbers are real. The weights and threshold are the calibrated values
from the stored W1 run (seed 0), and every risk below was also checked by
running the project's own detector on the same requests.

---

## Step 0: The Numbers You Need

Write these on the top of your page:

```
w1 = 0.3718    (weight of V1, agent mutation)
w2 = 0.3301    (weight of V2, network discontinuity)
w3 = 0.2981    (weight of V3, binding fork)
tau = 0.6282   (the threshold)
```

**The only formula:**

```
Risk of one request:   R = w1 x V1  +  w2 x V2  +  w3 x V3
Session peak:          P = the largest R in the session
Decision:              P >= tau  ->  ALERT
                       P <  tau  ->  ALLOW
```

**The check values:**

| Check | Question | Value |
|---|---|---|
| V1 | Did the browser, OS or device change? | 1.00 |
| | Only the browser version changed? | 0.35 |
| | Nothing changed? | 0 |
| V2 | New /16 network? (first two parts of the IP differ) | 1.00 |
| | New /24 inside the same /16? (third part differs) | 0.45 |
| | New host inside the same /24? (only the last part differs) | 0.15 |
| | Same IP? | 0 |
| V3 | Did an **earlier** binding come back right after a different one? | 1.00 |
| | Otherwise | 0 |

**Two rules SICA keeps in its head** for each session:

- **Reference binding.** V1 and V2 compare each request with this. It starts as
  the first request. After a one-way move to a *new* binding, the reference
  moves too. When an *old* binding comes back, the reference stays where it is.
- **Recent list.** The last four different bindings seen. V3 looks here.

The first request of every session only sets things up, so its risk is 0.

<details>
<summary><b>Optional: where do the weights come from?</b></summary>

On attack-free sessions, SICA measured how often each check fires on normal
traffic (the average value, called eps):

```
eps1 = 0.001397    eps2 = 0.008837    eps3 = 0.017674
```

Each raw weight is `ln(1 / (eps + 0.01))`:

```
q1 = ln(1 / 0.011397) = 4.4744
q2 = ln(1 / 0.018837) = 3.9719
q3 = ln(1 / 0.027674) = 3.5873
sum               = 12.0336
```

Divide each by the sum:

```
w1 = 4.4744 / 12.0336 = 0.3718
w2 = 3.9719 / 12.0336 = 0.3301
w3 = 3.5873 / 12.0336 = 0.2981
```

Rare on normal traffic means stronger evidence, so V1 gets the largest weight.
The threshold 0.6282 is the smallest peak that kept at most 1% of the
attack-free calibration sessions at or above it.

</details>

---

## The Two Bindings

Rafi uses Chrome 120 on a Windows laptop the whole time.

```
A = Rafi at home      IP 203.0.113.25    /24 = 203.0.113    /16 = 203.0
B = Rafi on mobile    IP 198.51.100.40   /24 = 198.51.100   /16 = 198.51
X = the attacker      IP 192.0.2.77      /24 = 192.0.2      /16 = 192.0
```

All three use the same browser string, because the attacker copied Rafi's
User-Agent. So **V1 = 0 everywhere** in both scenarios. The attacker's IP is in a
different /16 from Rafi's.

(These IPs are from the ranges reserved for documentation examples.)

---

## Scenario 1: Rafi Changes Network (Legitimate)

Rafi browses at home, walks out the door, and his phone hotspot takes over.

```
Log:   A  A  A  B  B  B
```

| Req | Binding | Reference before | Recent list before | V1 | V2 | V3 | Risk R |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|--:|
| 1 | A | (none) | (empty) | - | - | - | 0 |
| 2 | A | A | A | 0 | 0 | 0 | 0 |
| 3 | A | A | A | 0 | 0 | 0 | 0 |
| 4 | B | A | A | 0 | **1.00** | 0 | **0.3301** |
| 5 | B | B | A, B | 0 | 0 | 0 | 0 |
| 6 | B | B | A, B | 0 | 0 | 0 | 0 |

**Request 4, step by step:**

1. V1: same browser, same OS, same device. **V1 = 0**
2. V2: compare B with the reference A. /16 `198.51` is not `203.0`. **V2 = 1.00**
3. V3: B is new (not in the list), so this is not a return. **V3 = 0**
4. Risk:
   ```
   R = 0.3718 x 0  +  0.3301 x 1.00  +  0.2981 x 0
     = 0.3301
   ```
5. B is added to the list, and since B was new, the reference moves to B.

**Requests 5 and 6:** B matches the reference and the previous request, so
everything is 0.

**Decision:**

```
P = max(0, 0, 0, 0.3301, 0, 0) = 0.3301

0.3301  <  0.6282   ->   ALLOW
```

Rafi keeps his session. SICA noticed the move (it is logged as
`V2_scope_discontinuity=1.00`), but one honest move is not enough to alert.

---

## Scenario 2: The Attacker Is Caught (Concurrent Hijack)

The attacker stole Rafi's cookie and starts using it after request 2. Rafi is
still browsing, so their requests mix together.

```
Log:   A  A  X  A  X  A
       R  R  At R  At R      (R = Rafi, At = attacker)
```

| Req | Who | Binding | Reference before | Recent list before | V1 | V2 | V3 | Risk R |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|--:|
| 1 | Rafi | A | (none) | (empty) | - | - | - | 0 |
| 2 | Rafi | A | A | A | 0 | 0 | 0 | 0 |
| 3 | attacker | X | A | A | 0 | **1.00** | 0 | 0.3301 |
| 4 | Rafi | A | X | A, X | 0 | **1.00** | **1.00** | **0.6282** |
| 5 | attacker | X | X | A, X | 0 | 0 | **1.00** | 0.2981 |
| 6 | Rafi | A | X | A, X | 0 | **1.00** | **1.00** | **0.6282** |

**Request 3 (the attacker's first request):**

It looks exactly like Rafi's move in Scenario 1. The /16 changed (V2 = 1.00) and
X is new (V3 = 0):

```
R = 0.3718 x 0  +  0.3301 x 1.00  +  0.2981 x 0  =  0.3301
```

X joins the list and becomes the reference. So far SICA cannot tell this apart
from Rafi changing network.

**Request 4 (Rafi comes back, and this is the catch):**

1. V1: same browser. **V1 = 0**
2. V2: compare A with the reference X. /16 `203.0` is not `192.0`. **V2 = 1.00**
3. V3: A is different from the previous request (X), **and A is already in the
   recent list**. An earlier binding came back. **V3 = 1.00**
4. Risk:
   ```
   R = 0.3718 x 0  +  0.3301 x 1.00  +  0.2981 x 1.00
     = 0.3301 + 0.2981
     = 0.6282
   ```
5. Because A is a *returning* binding, the reference does **not** move (it stays X).

**Request 5 (attacker again):** X matches the reference (V2 = 0), but X is a
return from the list (V3 = 1.00):

```
R = 0.2981 x 1.00 = 0.2981
```

**Request 6 (Rafi again):** same as request 4, `R = 0.6282`.

**Decision:**

```
P = max(0, 0, 0.3301, 0.6282, 0.2981, 0.6282) = 0.6282

0.6282  >=  0.6282   ->   ALERT  (at request 4)

Reason: V2_scope_discontinuity=1.00 | V3_binding_fork=1.00
```

The session is flagged at request 4, right after the attacker's first request.
SICA itself only makes the decision; the server can then end the session or ask
the user to log in again.

**Why the peak equals the threshold exactly:** in this run, some attack-free
calibration sessions had a device switching back and forth between two networks
(interface flapping). That produces the same "V2 = 1 and V3 = 1" request, so the
threshold landed exactly on 0.3301 + 0.2981. The rule is "greater than **or
equal**", so the session alerts.

---

## Side by Side

| | Scenario 1: Rafi moves | Scenario 2: attacker joins |
|---|---|---|
| Log pattern | `A A A B B B` | `A A X A X A` |
| Does an old binding return? | No | Yes, at request 4 |
| Highest risk | 0.3301 | 0.6282 |
| Compared with tau = 0.6282 | lower | equal |
| Decision | **ALLOW** | **ALERT** |

Requests 1 to 3 look the same in both. The only difference is that A comes back.
That return is the **binding fork**, and it is what SICA is built to notice.

---

## Try It Yourself (answers included)

Same weights and threshold. Each case starts from Rafi at binding A.

| Case | What changes | Working | Risk | Decision |
|---|---|---|--:|:-:|
| Browser update | Chrome 120 to 121, same IP | 0.3718 x 0.35 | 0.1301 | ALLOW |
| Same /24, new host | 203.0.113.25 to 203.0.113.99 | 0.3301 x 0.15 | 0.0495 | ALLOW |
| Same /16, new /24 | 203.0.113.25 to 203.0.7.9 | 0.3301 x 0.45 | 0.1485 | ALLOW |
| Attacker with own browser (L0) | Firefox 121 from 192.0.2.77 | 0.3718 x 1 + 0.3301 x 1 | 0.7019 | **ALERT** on the attacker's first request |
| Silent takeover | `A A X X X X` (Rafi stops) | only request 3: 0.3301 x 1 | 0.3301 | ALLOW (missed) |

The last row is SICA's honest limit: if Rafi stops browsing and the attacker
copied his browser, the log looks exactly like Rafi changing network, so there
is nothing to catch.
