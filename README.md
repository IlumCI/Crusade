# Crusade

A self-hosted, no-API-key service search engine in the spirit of Shodan/Censys.
Crusade scans reachable hosts on the public internet, grabs and fingerprints
service banners, enriches results with geo/ASN, DNS and TLS-certificate data,
tags known vulnerabilities, and makes everything searchable through a
Shodan-style query language and a web UI — all from free, public data sources.

It **catalogues** services (connect-and-read only). It does not exploit,
brute-force, or attempt authentication against anything.

## Build

```
cargo build --release
cargo test        # unit tests across all crates
```

## Quick start (local test rig)

```
cd docker && docker compose up -d && cd ..
crusade update-data                      # fetch free GeoIP/ASN + CVE/KEV feeds
crusade scan 127.0.0.1 --allow-private   # scan your own test rig
crusade search 'product:nginx'
crusade serve                            # web UI at http://127.0.0.1:8088

# v2: deep probes, UDP, operations
crusade scan 203.0.113.0/24 --udp                 # + read-only UDP protocol probes
crusade scan 10.0.0.0/16 --discovery-masscan      # masscan front-end (blocklist-enforced)
crusade stats 'product:nginx'                     # faceted breakdown for a query
crusade export 'country:DE' --out de.jsonl        # JSON Lines, like `shodan download`
crusade monitor --interval 3600 --stale 86400     # rescan + alert on new ports/CVEs
crusade alerts                                    # recent alerts (webhook/SMTP via [alert])
crusade enqueue 10.0.0.0/24 --ics && crusade worker   # distributed scan queue
crusade scan 198.51.100.0/24 --screenshot         # capture web-UI screenshots (needs Chrome)

# v5: honeypot-aware results
crusade search 'port:22 -honeypot:true'           # hide likely honeypots
crusade search -- -honeypot:true                  # `--` when a query starts with '-'
crusade rescore                                   # recompute honeypot scores offline

# v5: semantic search (CPU-only embedded model, fetched by update-data)
crusade similar router admin login page           # services similar in meaning
crusade similar --like 203.0.113.7:8080 --filter 'country:DE'
crusade embed                                     # backfill vectors for an existing index
```

### Service lifecycle

`monitor` rescans the default ports *and* every port already known on a host,
so services that go away are noticed. A probed port that stays silent is not
deleted on the first miss: it is marked **pending**, stays visible (greyed in
the web UI, listed by `crusade host`), and is evicted only after
`[lifecycle] evict_after_hours` (default 72 h). A host left with no services
is dropped after `forget_after_days` (default 60). Eviction raises a
`service-gone` alert. Ports a run did not probe are never touched. This
mirrors the policy Censys published (SIGCOMM 2025), where a single miss is
usually loss or throttling rather than a real change.

Semantic search uses the Model2Vec static embedding model `potion-base-8M`
(~30 MB, 256 dimensions, CPU-only). Every service is embedded at ingest from
its product, title, server, certificate names and banner; vectors are stored
int8-quantised in SQLite and ranked by exact cosine similarity. Static models
match vocabulary well ("ubuntu apache", "ssh server") and paraphrases less
well. Without the model the feature is simply off.

The web UI exposes the same ranking at `/similar` (and `/api/similar`), with a
"similar services" pivot on every service of a host page.

Each probed service can carry a JARM fingerprint, favicon mmh3 hash, TLS
version/cipher, detected technologies and security headers, and (for SSH) the
HASSH, offered KEX algorithms and host-key type — all pivotable in the query
language.

## Layout

| Crate   | Responsibility |
|---------|----------------|
| `core`  | Data model + Shodan-style query language (parser → AST) |
| `store` | SQLite persistence, FTS5 search, faceting, query→SQL compiler |
| `scan`  | Blocklist/rate guardrails, TCP-connect scanner, masscan/zmap ingestion |
| `probe` | Banner grabbing, nmap-service-probes fingerprinting, TLS/HTTP parsing |
| `enrich`| GeoIP/ASN, reverse DNS, crt.sh, embeddings, screenshot perceptual hashing |
| `vuln`  | CPE→CVE matching (NVD + CISA KEV) and heuristic tags |
| `web`   | axum + askama read-only UI and JSON API |

## Query language

`port:443 country:DE product:nginx "default page" after:2026-01-01 -tag:honeypot`

Filters: `port asn org country city net product version hostname ssl.cn
transport jarm http.favicon.hash ssh.hostkey hassh tag vuln has_vuln
ics has_ics auth has_exploit has_screenshot honeypot ja4ts cluster before after`; a leading `-` negates; bare/quoted words are
full-text over banners, titles, technologies and SSH banners. Unknown keys fall
back to free text. `net:` accepts IPv4/IPv6 CIDRs; `http.favicon.hash:` takes
the signed mmh3 integer (the Shodan convention) for finding the same deployment.
`auth:open` surfaces services reachable WITHOUT credentials (databases, ICS,
VNC, admin panels) — a prime recon signal; `has_exploit:true` matches hosts
whose detected CVEs have a known public exploit (Exploit-DB / Metasploit). Auth
posture is observed from each service's own response — Crusade never submits
credentials or attempts to authenticate.

`honeypot:true|false` or `honeypot:<0-100>` filters on a passive honeypot
score. Each host is scored from data already collected: a signature pack for
default honeypot configurations (`crates/vuln/rules/honeypot-rules.toml`, overridable at
`<data dir>/honeypot-rules.toml`), SSH banners that claim an OpenSSH release
older than the key-exchange algorithms offered, implausible ICS/IT service
mixes, ICS on cloud ASNs, contradictory OS stacks, ports that accept but never
speak, and port pairs that almost never co-occur across the index. Scores and
their evidence appear in `crusade host` and the web UI; hosts at 50% or more
are tagged `honeypot`. Use `-honeypot:true` to keep honeypots out of exposure
statistics.

## Anomalies

An index of a million hosts is mostly web servers; reading it top to bottom
tells you nothing. What is worth attention is the host *unlike* its
population.

```
crusade anomalies --top 20
crusade anomalies country:DE          # unusual within German hosts
```

Hosts are scored by **surprisal**: each feature (a port, a product, a tag, an
auth posture) occurs in some fraction `p` of the population, so observing it
carries `-log2(p)` bits. A host built entirely from common parts scores low
however many parts it has; one genuinely rare feature lifts a host on its own.

Two properties matter more than raw accuracy. The score **decomposes exactly**
into per-feature contributions, so the output is "unusual because port 102
appears on 0.3% of hosts" rather than a number from a black box — an
unexplained anomaly score is not actionable. And it needs **no training**: the
population is the model, so it works from the first scan and cannot drift from
the data it describes. Below 50 hosts it declines to score rather than calling
everything unusual.

Features are deliberately coarse — CVE ids collapse to "has a vuln tag",
service counts bucket by powers of two — because features that make every host
unique would score every host as anomalous and say nothing. `anomaly::diff`
scores *changes* the same way, which is the more alertable signal: an unusual
host may always have been unusual, but an unusual change just happened.

Sarabi & Liu (IMC 2018) take the learned route, a VAE over binary tags, and
get compact embeddings — a better basis for clustering. For "show me what is
weird, and say why", surprisal is cheaper and clearer.

## Replacing the IPv6 generator

IPv6 cannot be swept, so the generator *is* the scan: whatever it proposes is
what gets probed, and the rest of a space with 2^128 addresses in it is never
looked at. That makes it the one component most worth replacing, so it is a
trait — `crusade_scan::Generator`, with the propose-then-reward contract that
6Sense (USENIX Sec 2024) and 6SEVEN (arXiv:2609.08098) both fit, and a test
that the trait alone is enough to drive the scan.

What ships behind it is the space-partitioning baseline (6Gen/6Tree-style
nybble regions with online feedback). The learned generators the plan listed —
6Vision (arXiv:2501.01683), 6Diffusion (arXiv:2412.19243) — are not
implemented, and the reason is not that they look unpromising. Neither
publishes pretrained weights, so shipping one means training it, and nothing
here can measure whether it helped: this container has no IPv6 stack, which is
already why the baseline's real-world hit rate is documented as untested. A
generator whose benefit cannot be measured is a dependency, not a capability.
The seam is ready for one.

## What to look at next

An analyst with one interesting host wants the same thing every time: what
else belongs to whoever runs this, and what else looks like it.

```
crusade pivot 203.0.113.7         # the queries worth running, best first
crusade pivot 203.0.113.7 --all   # and the ones that were discarded, with why
```

Crusade already holds every pivot that answers those - shared certificates,
host keys, favicons, JARM and HASSH fingerprints, screenshot templates, the
assigned cluster, the network, the autonomous system. The useful part is
knowing which of them is worth running, and most are not, in two distinct
ways. A pivot matching only this host is a round trip to where you started:
the identifier is unique. A pivot matching a fifth of the index is a default,
and "every host running nginx" is not a lead. What is left is ranked by
surprisal - `-log2(matches / index size)` - so the rarest pivot that still
matches something else comes first.

Every candidate is a real query and its result size is counted, not estimated,
so the ranking is a fact about this index rather than a guess. A test asserts
every pivot the planner can emit parses as a filter, because a list of
unrunnable strings would be worse than no list.

The plan called for a local language model planning these steps (ArachNet,
arXiv:2511.10611). It is not built, and the reason is measured rather than
assumed: the same model class, asked for a *single* query under a grammar that
made malformed output impossible, got 7 of 20 ordinary questions right. A
planner is a sequence of such decisions, each conditioned on the last, so the
error compounds. What the model cannot do reliably, counting does exactly.

## Infrastructure clustering

Two hosts presenting the same TLS certificate, or the same SSH host key, are
not coincidentally similar — someone installed the same key material on both.
Following those links answers the question an analyst actually has: *what else
belongs to whoever runs this?*

```
crusade cluster --dry-run     # show the largest clusters, store nothing
crusade cluster               # store them
crusade search cluster:<id>
```

The trap is that a shared identifier only means something if it is **rare**.
Two hosts sharing a self-signed certificate is a finding; two hosts sharing
nginx's default favicon is nothing, and treating it as an edge collapses the
whole index into one useless cluster. So every identifier is weighed by how
many hosts carry it, and anything on more than 10% of the index (or more than
1,000 hosts) is discarded before an edge is drawn — the reasoning behind
inverse document frequency. Ignored identifiers are *reported*, since they
explain why hosts an operator expected to be linked are not, and they make a
decent list of default installations.

Links are weighted by what they actually imply: key material (certificate,
SSH host key) means shared administration; a favicon means shared branding or
application; JARM and HASSH only mean shared software. Two weak links can
combine into one that counts. Clusters are connected components over the
surviving edges, with the evidence that joined them reported strongest-first.
Published work here is industry rather than peer-reviewed, so this stays at
the explainable baseline my survey recommended; anything learned belongs on
top of it.

## How often to come back

One revisit interval for the whole index is wrong in both directions at once.
A cloud instance can be a different machine by tomorrow, so a weekly revisit
records fiction. A colocated mail server has looked the same for three years,
so a daily revisit spends bandwidth to learn nothing.

```
crusade monitor                   # per-host intervals, earned
crusade monitor --no-adaptive     # one --stale interval for everything
crusade coverage                  # the resulting schedule
```

Each host carries its own interval, from two inputs in order of authority.
What the host *did* comes first: whether the last scan found it changed is
direct evidence about this host, and it beats any inference from its address.
What kind of network it sits in supplies the starting interval, because until
there is history there is nothing else to go on — a known cloud ASN, or the
naming conventions access providers use in generated PTR records (`dsl-…`,
`pool-…`, `cpe-…`), with the marker required to be a whole DNS label or
bounded inside one, so `research` is not read as `res`. Richter et al. (IMC
2016) and Padmanabhan et al. (IMC 2016, CoNEXT 2020) are the measurements
behind treating the class as a prior on churn.

The adaptation is deliberately asymmetric. Backing off is slow — one step of
1.5x per unchanged scan, from six hours up to three weeks — because a host
quiet for a month may still change tomorrow. Coming back is immediate: one
step straight to the floor, because the moment a host is seen changing, every
other record about it is a guess about a machine that has moved. Treating both
directions the same would mean either trusting stale records for days after a
change or never saving any bandwidth at all.

The queue is ordered by how far past due a host is *relative* to its own
interval, not by absolute age. A cloud host six hours late on a six-hour
interval has more likely changed than a colocated one six hours late on three
weeks — and sorting by last-seen alone always serves the second first, which is
exactly how a single interval spends its budget on the hosts least likely to
have moved.

"Changed" is judged on what an operator would call a change: which ports
answer, what they claim to be, and the identifiers they present. Not the whole
record — `observed_at` moves on every scan, and a schedule driven by that would
never back off at all.

## Honeypots that generate their banners

The rule pack catches a honeypot that ships a default banner. It cannot catch
one that writes a new banner for every visitor with a language model: the text
is novel, plausible and inconsistent with nothing. What such a honeypot cannot
hide is that it had to think first.

Every first exchange is now timed twice: the TCP handshake, which is one round
trip with no application in the path, and the gap from the established
connection to the first byte of the answer. A static daemon writes a banner it
already has, so the second is about the same as the first, every time.
Inference takes hundreds of milliseconds at best and a different duration
every time, because the duration follows how much text the model chose to
produce.

Both halves are needed, and both are normalised. A host in Australia answers
slowly because it is far away; the *ratio* of answer time to round-trip time
cancels the distance out, and an absolute floor stops a 30 ms reply on a 1 ms
link — process startup, not a language model — from looking like a finding
just because the ratio is large. Variance accumulates across rescans by
Welford's method and is combined by Chan's parallel formula, so the statistics
come out the same however the scans happened to be split, and five numbers per
service is all that is ever stored. A tested invariant holds the two paths
equal.

Neither signal is weighted as heavily as a rule hit, because a real service
under real load does look slow — so the evidence says what was measured
("port 22: 900 ms to answer on an 11 ms round trip (82x)") and the judgement
can be checked. Slow but *consistent* is load; slow and erratic is generation.
See arXiv:2502.20589 and the LLM-honeypot work at arXiv:2309.00155,
2409.08234, 2405.05999.

### Weighing the signals on your own index

Everything above combines signals with a noisy-OR over weights I chose from
the literature. That is a defensible way to start and a poor way to finish: a
guess that has been shipped looks exactly like a measurement.

```
crusade rescore --calibrate          # fit on this index, report, write nothing
crusade rescore --calibrate --save   # keep the weights, if the fit is usable
```

This fits a logistic regression from the *behavioural* signals to the rule
pack's own labels. A rule hit is an exact artefact of known honeypot software —
Cowrie's default SSH banner, Conpot's device identity — so it is about as close
to a label as scan data offers, and the question "do the behavioural signals
predict the hosts the rules recognise" has an answer on a real index. The
coefficients are printed largest-first and the AUC is measured on a held-out
third, so the answer can be read rather than trusted.

What that establishes, and what it does not, is worth being exact about. It
*can* show that a signal carries information and how much relative to the
others. It *cannot* find honeypots the rules miss and the signals do not
predict either. And it *will* inherit the rule pack's blind spots: a honeypot
family no rule covers contributes negative labels, pushing the weights away
from whatever makes it recognisable. The AUC is measured against the rules, not
against the truth.

So no weights ship with Crusade. There is no index here to fit them on, and a
weight file shipped from a synthetic population would be the same guess with a
more convincing filename. Saving is refused below 30 labelled hosts or an AUC
of 0.60 — and an AUC near 0.5 is itself a result worth having, because it says
these signals do not separate the honeypots this rule pack knows about. A rule
hit always keeps its own weight: it is an artefact, not an inference, and
nothing a fit says should move it.

No peer-reviewed classifier over scan records exists, so the method is
deliberately the simplest thing that can be checked: a linear model whose
coefficients can be read, not a forest whose cannot.

## Asking in English

```
crusade ask "unauthenticated redis in the netherlands"
#   auth:open country:NL port:6379
#     "unauthenticated" -> auth:open
#     "netherlands"     -> country:NL
#     "redis"           -> port:6379
crusade ask "vulnerable modbus in italy" --run
crusade ask --grammar        # the query language as GBNF
```

The query is printed with the words that produced each filter, and runs only
when asked. That is deliberate: a translator that silently runs its own guess
teaches nobody what the query language can do, and a wrong guess then looks
like an empty index rather than a mistranslation.

Two pieces make this work. The first is a GBNF grammar **generated** from the
`Field` enum and its value kinds, not written by hand — a hand-written grammar
is a second copy of the query language that stops matching the first one the
next time a field is added, and the failure is invisible because a stale
grammar still emits syntactically valid output over the wrong language. A test
asserts the grammar covers every field the parser knows, and that every key it
offers round-trips through the parser.

The second is the translator itself, which is cue phrases rather than a model:
a span that unambiguously names a filter becomes that filter, and the rest
becomes free text, which is searched against banners and so still does
something useful. Three choices in it are worth naming. A service word means
its port (`ssh servers` is `port:22`, since the *product* is OpenSSH or
Dropbear), but an explicit port in the question wins outright. Country names
map to ISO codes from a short list of unambiguous ones, because a wrong code
produces a confidently empty result. And a bare product name is only
recognised because the index has seen it — `crusade ask` reads the product
facet and passes it in, so the translator learns the vocabulary of the data it
is searching instead of carrying a list that would be endless and stale.

### Two engines, each good at what the other is not

There is a second engine: a 0.5-1.5B instruct model, running locally under the
same generated grammar, so whatever it emits parses by construction. It is
behind `--features llm`, because llama.cpp is a C++ build of several minutes
and the model is hundreds of megabytes.

Both engines are measured on the same two question sets, with `cargo run
--features llm --example nlq_score -- <model.gguf>`:

| | cue phrases (20) | paraphrases (8) |
|---|---|---|
| cue translator | **19 exact** | 0 exact |
| Qwen2.5-1.5B Q4, grammar-constrained | 7 exact, 2 partial | **4 exact** |

Neither replaces the other, and the numbers say why. The cues are nearly
perfect on the questions they were written for and helpless outside them —
"boxes in the netherlands nobody needs a password for" came back as
`country:NL nobody needs password`, and "remote desktop anywhere but the
united states" came back as `country:US`, the opposite of the question. The
model handles those (`country:NL auth:open`) and is far worse at the ordinary
phrasings, at about 12 seconds a question against microseconds. So `crusade
ask` runs the cues and falls back to the model only where they produced
nothing structured.

Three things had to be right before the model was usable at all, and each was
found by measurement rather than reasoning:

- **The grammar has to accept a leading space.** A model completing `Query:`
  wants a space-prefixed token, because that is how its tokenizer represents
  the start of a word. Forbid it and every such piece is masked at the first
  position, so generation falls to whichever unprefixed key ranks highest.
  That put a spurious `ics:modbus` in front of seven of eight otherwise
  sensible queries, and no amount of prompting removed it — the cause was
  mechanical, not semantic.
- **The prompt has to describe exactly the grammar's fields.** With a prompt
  listing 29 and a grammar allowing 18, the model aims at a field it cannot
  use, the token is refused, and generation lands somewhere else.
- **Values have to be restricted to what the index holds.** Given a free-text
  field, a small model puts the subject of the sentence in it: `ics:boxes`,
  `ics:databases`, `ics:mail` on three consecutive questions. Restricting each
  field to the values the index has actually seen makes that unrepresentable —
  the same principle as CPE resolution above, where candidates come from the
  data and never from free text. What that could not prevent was using a
  *real* value as filler (`product:nginx` on a question about web servers), so
  a vocabulary filter is dropped unless the question mentions its value.

Self-consistency is not a cure. Sampling five times and keeping what a
majority agree on does remove unstable guesses, but the errors that matter are
stable: the model returned `auth:unknown` for "nobody needs a password for" in
five samples out of five. Voting cannot outvote a consistent misreading, which
is what GenSIE 2026 calls the constraint tax and arXiv:2608.25761 finds
inference-time scaling does not recover at this size.

The benchmarks live in `crusade_core::nlq` rather than in a test file, because
a benchmark inside one engine's tests is not a benchmark.

## Matching CVEs to software NVD names differently

CVE matching is a join on `cpe:2.3:a:<vendor>:<product>:<version>`, and the
join only fires when the name Crusade saw agrees with the name NVD chose. It
often does not. nmap reports `Apache httpd`; NVD calls that software
`apache:http_server`. nmap reports `MySQL`; NVD has `mysql` under a dozen
vendors, one of which is Oracle and the rest of which are packaging projects
with two CVEs between them. Exact matching therefore finds nothing for a large
share of real services — VulCPE (arXiv:2505.13895) measures over 50% vendor-name
inconsistency between CPE and CVE data.

```
crusade resolve "Apache httpd"          # -> cpe:2.3:a:apache:http_server
crusade resolve "MySQL" --top 5         # and what it scored against
```

The candidate set is always the `(vendor, product)` pairs that appear in the
indexed CVE rules, so whatever comes out has CVEs attached; nothing is ever
free-text. Generating CPE strings is the tempting approach and the wrong one —
a generated identifier matches no NVD row, and plain fuzzy matching mislabels
anything with a non-standard name (arXiv:2412.16607). Three tiers run, each
with a bar to clear:

| tier | evidence | example |
|---|---|---|
| exact | the name is a product, possibly after stripping a vendor the banner included | `Apache Tomcat` -> `apache:tomcat` |
| lexical | IDF-weighted token F1, needing one rare shared token | `Oracle WebLogic` -> `oracle:weblogic_server` |
| fuzzy | character trigrams, blended with partial token agreement | `Apache httpd` -> `apache:http_server` |

Token F1 rather than overlap, because recall alone lets any candidate
*containing* the name win: that is how `nginx` becomes `nginx_amplify_agent`.
Where candidates fit comparably well the tie goes to the pair NVD documents
most, which is the prior doing its job — `Redis key-value store` fits
`redis-store:redis-store` marginally better token-for-token and means
`redis:redis`. That promotion is allowed only for a candidate whose whole
product name the banner contains, so `Apache httpd` cannot be pulled to
`apache:tomcat` by Tomcat's much larger CVE count.

Token coverage is not enough on its own, and neither is rarity. `nmap-service-probes`
asserts its own CPE for thousands of its rules, which is independent ground
truth for exactly this mapping, curated by people who were not thinking about
this resolver — `cargo run --release --example resolve_precision` scores
against it. Weighing by how much of the two names overlap sent `Titan ftpd` to
`netbsd:ftpd`, because a short generic name shares the common word completely
while `southrivertech:titan_ftp_server` paid for its extra words. Weighing only
by the rarest shared word answered nearly everything, dropping refusals from
157 to 17 and nearly tripling the wrong answers. Both together, with rarity
leading, is what the code does.

On 571 names whose true CPE the vocabulary contains:

| tier | answers | right product |
|---|---|---|
| exact | 124 | 84% |
| lexical | 343 | 57% |
| fuzzy | 35 | 77% |
| refused | 69 | — |

So this is useful and it is not reliable: 57% on the lexical tier, and 31% of
all answers name the wrong product. That is why every CVE found this way
carries its tier and score in the detail, why a resolved match is never
presented as an exact one, and why `resolve_min_tier` exists — set it to
`exact` for an index whose tags are acted on without being read, or
`resolve_cpe = false` to go back to exact matching alone. The default is
`lexical`, on the judgement that a 57%-correct CVE list that says how it was
arrived at beats no CVE list at all.

### Naming software from the banner alone

`nmap-service-probes` is 12,000 hand-written patterns and still a fixed list:
a banner it has no rule for yields no product, and no product means no CVE, no
`product:` filter, and a host that appears as an open port and nothing else.

The vocabulary closes part of that gap without a model. A banner usually names
its product somewhere structural — a `Server:` header, after `SSH-2.0-`, in an
FTP or SMTP greeting — so those names are extracted and put through the same
resolution, and a service that gets its product this way is tagged
`product-from-banner` with the port, tier and score.

The bar is higher here than for resolving a name a fingerprint already
produced. There, the string is known to be software and the only question is
what NVD calls it. Here the question is whether this fragment of text names
software at all, and a wrong answer attaches someone else's CVEs — so the
fuzzy tier is refused outright, only the head of a banner is read (page content
is where false positives live), and a banner naming no software is required to
produce nothing.

Whether the ~22M-parameter encoder the plan called for (arXiv:2404.00056) would
do better is untested and stays that way until there is labelled scan data to
test it on. A model shipped on the strength of a paper's F1, with no
measurement on this index's banners, is a 22M-parameter guess.

### The tier that was removed

The plan called for a fourth tier: embed the whole vocabulary, take the nearest
neighbours of the banner, accept one of them. It was built, embedded (121,603
pairs, 22 seconds, 30 MB of vectors) and measured. It was wrong four times in
five. `Microsoft IIS httpd` resolved to `microsoft:system.net.http`, `Cowboy
Erlang HTTP server` to `ibm:http_server`, and `Totally Bespoke Daemon` — which
should resolve to nothing at all — to `magzter:bespoke`.

The cause is structural, not a matter of tuning. A static embedding of
`vendor product` is a mean over a handful of tokens, so a frequent vendor word
dominates the vector, and the ranking answers "which pair mentions Microsoft"
rather than "which pair is this software". The rarity weighting in the lexical
tier asks the better question for none of the cost. The one case retrieval got
right scored *below* the guard that would have been needed to exclude the wrong
four: raising the bar removed the win, lowering it kept the losses. So there is
no embedding tier, and the negative result is recorded in the module doc and
kept as a test rather than quietly dropped.

## Screenshot templates

A sweep of the web finds the same default landing page on an enormous number of
hosts: one router firmware's login form, one appliance's setup wizard. Storing
them as unrelated screenshots makes the index unreadable, so each capture is
fingerprinted with a perceptual hash and pages that look alike are grouped.

```
crusade screenshots                 # largest templates first
crusade screenshots --members       # every host in each group
crusade search screenshot.hash:...  # one specific template
```

The hash is a dHash: the page is reduced to a 9x8 grey grid and each bit
records whether a cell is brighter than the one to its right. That measures
*layout* rather than colour, so the same application theme-shifted across
installations still groups, while a re-render at another resolution does not
split. Hamming distance 10 or less counts as the same page; VisualPhishNet
(arXiv:1909.00300) is the reference for treating a page's look as the identity
of the software behind it.

One trap is worth naming: a blank or still-loading page reduces to a uniform
grid, hashes to all zeros, and then sits within the distance threshold of every
sparse page in the index — a single group containing everything. So a capture
whose grid spans too little brightness is refused a fingerprint rather than
given a misleading one, and the long tail of pages that resemble nothing else
is reported, since that is where anything interesting is.

## Continuous coverage

A one-shot scan picks a port list and runs. A map that stays current has to
cover 65,536 ports across every host, forever, without re-probing the same
ports and without storing a per-host bitmap of what has been tried.

```
crusade monitor --tiers --background 100   # continuous, tiered
crusade coverage                           # how far the index has got
crusade coverage --ip 203.0.113.7          # and what that host gets next
```

Three tiers, following Censys (Durumeric et al., SIGCOMM 2025):

| tier | ports | when |
|---|---|---|
| hot | ~95 common and high-interest ports | every pass |
| cloud | ~55 orchestration/metadata ports | hosts on cloud and hosting ASNs |
| background | N ports from that host's own permutation | every pass |

The background tier is the interesting part. Sampling random ports
independently each pass repeats some and leaves others uncovered forever (the
coupon-collector problem), while remembering what each host has seen costs
8 KiB of bitmap per host — 8 GiB at a million hosts. Instead each host walks a
**keyed permutation** of the port space: a four-round Feistel network over the
16-bit port, keyed by the host's address and an installation salt. That is a
bijection by construction, so one cycle visits every port exactly once with no
gaps, in a different order per host. The only state is a single integer cursor
per host, and the schedule is reproducible from (address, salt, cursor) — which
is what makes it resume after a restart rather than starting a different walk,
and what would let several workers agree without coordinating.

At 100 background ports per pass a host's full port space is covered in 656
passes; at 500, in 132. The cursor advances only after the probes actually go
out, so an interrupted pass re-probes that slice instead of skipping it.
Background results are also the training data for `--predict`, so the
bandwidth earns its keep twice.

The exhaustive test asserts the property the design rests on: for several
keys, all 65,536 positions produce all 65,536 ports with no repeat.

## IPv6

IPv4 can be enumerated; IPv6 cannot. A single /64 holds 18 quintillion
addresses, so there is no sweep to run — hosts must be predicted from
addresses already known, and the prediction *is* the scan.

```
crusade ipv6 --dealias --budget 512 --rounds 5
crusade ipv6 --seeds known-v6.txt --dry-run     # plan only, probe nothing
```

Seeds come from the IPv6 hosts already in the index, plus an optional file.
The pipeline, in the order the research says matters:

1. **Seed hygiene.** Duplicates and unroutable space (link-local,
   unique-local, multicast, documentation, IPv4-mapped) are dropped and
   reported. 6SEVEN (Kanipe et al., IMC 2026, arXiv:2609.08098) ported eight
   published generators into one framework and found seed composition and
   dealiasing moved results more than the choice of algorithm — so this comes
   first, and the generator is a deliberately replaceable baseline.
2. **Aliased-prefix dealiasing.** Some networks answer on *every* address in a
   prefix, which floods a generator with worthless hits. Detection is the
   nybble sweep from Gasser et al. (*Clusters in the Expanse*, IMC 2018):
   probe one address per value of the nybble past the prefix and see whether
   all of them answer. Such a prefix is **collapsed to one representative, not
   discarded** — *Rusty Clusters* (Zirngibl et al., IMC 2022) found over 98% of
   Fastly's announced IPv6 space reads as aliased, so dropping it throws away
   real infrastructure. Verdicts persist in the index and are reused for 90
   days, since the probe costs 16 requests per prefix and the answer is stable.
   Silence is recorded as inconclusive, never as aliased: assuming otherwise
   would silently hide real space.
3. **Generation.** Seeds are grouped by shared nybble prefixes; where several
   seeds share a prefix and the next nybble varies, a provider is handing out
   addresses, and candidates fill in values not yet seen. Densest regions
   first, round-robin so one region cannot starve the budget, and never a seed
   or a duplicate.
4. **Feedback.** Every candidate is reported back, hit or miss, so the next
   round concentrates on regions that answered — the closed loop 6Sense
   (Williams et al., USENIX Security 2024) found separates a usable generator
   from a published one.

Generated candidates are dealiased too, not just seeds, so a known aliased
prefix cannot soak up a round's budget.

**Caveat on testing.** The logic above is unit-tested (address arithmetic,
probe-set construction, alias classification, seed cleaning, generation,
feedback), and the CLI is exercised end to end with `--dry-run`. It has *not*
been run against live IPv6: the development container has no IPv6 stack at
all. Treat the generator's real-world hit rate as unmeasured.

## Predictive discovery

Probing every port of every host is unaffordable — 65,535 ports across a /16
is 4.3 billion probes — but services are not independent. A host with 3306
open probably also runs 22; a host with 102 open is industrial equipment and
almost certainly runs neither. `crusade scan --predict <n>` exploits that: a
cheap seed pass finds one service, then the index says where that host's other
services are likely to be, and only those get probed.

```
crusade scan 203.0.113.0/24 --predict 16
```

The model (`crates/core/src/ports.rs`) learns port and port-pair frequencies
from *your* index, so it describes the population you actually scan. Each
observed port contributes its own conditional and they combine with a
noisy-OR, so evidence accumulates: a port predicted by several observations
outranks one predicted by a single weak signal. Nothing is suggested without
at least 20 supporting hosts, and the whole phase is skipped below 200 indexed
hosts — the model says nothing rather than guessing. `--predict` is a cap, not
a quota: asking for 32 when only 12 ports have evidence costs 12 probes.

Evaluated with a train/test split over a synthetic population of archetypes
(`cargo run --release -p crusade-core --example predict_eval`):

| strategy | probes | recall |
|---|---|---|
| 8 seed ports only | 80,000 | 62.8% |
| seed + predict 16 | 149,033 | **84.8%** |
| every port | 655,350,000 | 100% |

Prediction adds 22 points of recall for 1.9x the seed probes, reaching 84.8%
of exhaustive recall with ~4,400x less bandwidth. The honest limit is the
first phase: 8,631 of 10,000 test hosts answered on a seed port at all, and
the rest are invisible to any two-phase scan however good the prediction is.
This follows GPS (Izhikevich et al., SIGCOMM 2022, arXiv:2303.00895), which
reports 92.5% of services at 131x less bandwidth against real IPv4.

## Discovery engines

| Engine | How | Needs |
|--------|-----|-------|
| connect (default) | full TCP handshake per port | nothing |
| `--discovery-syn` | one stateless SYN per port | `CAP_NET_RAW`, IPv4 |
| `--discovery-masscan` | shells out to `masscan` | `masscan` binary |
| `crusade sweep ingest` | masscan/zmap output from elsewhere | a sanctioned sweep host |

QUIC is probed by default on UDP/443: a host can serve its whole site over
HTTP/3 and look closed to a TCP-only scan. Identification needs one datagram
and no handshake — an Initial naming a reserved version forces the server to
reply with a Version Negotiation packet listing what it supports (RFC 9000
§6, the approach QScanner took in *It's over 9000*, IMC 2021). The reply is
unauthenticated, so the connection IDs are checked against the ones sent
before it is believed.

Ingesting zmap 4.4 output also carries its newer fields: SYN RTT is summarised
(a reply much faster than a network's other hosts usually came from a
middlebox in front of them), and the JA4TS stack fingerprint is stored and
pivotable with `ja4ts:` — the TCP-stack counterpart to `jarm:` and `hassh:`.

The connect scanner is bounded by `concurrency / timeout` whenever a target
does not answer — the common case on the open internet. At Crusade's defaults
(500 concurrent, 3 s timeout) that is ~167 ports/s, and measured 166. The
stateless SYN scanner (`crates/scan/src/syn.rs`) is bounded only by the send
rate, measuring ~83,000 probes/s from one thread on a 4-core container:

```
cargo run --release -p crusade-scan --example discovery_bench -- 40000 20000 1000000 50 50
connect:  120.14s        166 ports/s     # 20k unresponsive ports, 3s timeout
syn:        0.24s      83065 ports/s
```

That is the difference between ~258 days and ~12 hours for a single port
across routable IPv4. It follows ZMap (Durumeric et al., USENIX Security
2013): the SYN's sequence number is a keyed hash of the target tuple, so a
reply is validated from the packet itself and no per-target state is kept.
Discovery only finds open ports; banner grabbing is a separate ordinary
connection to the ports found, so app-layer work happens only where something
answered.

**Running a sweep is still an operational decision, not just a flag.** A host
whose provider permits scanning, a published abuse contact, reverse DNS
identity and a working opt-out are what make wide scanning legitimate; see
*Responsible use* above.

## Archiving and retention

Three things grow without bound: the scan timeline, the alert log, and the host
table itself as sweeps reach new address space. Crusade decides what is
expendable by measuring, not guessing: every host carries `last_seen` (when it
last answered) and `last_accessed` (when it was last surfaced to someone,
through a search page, a host view or the API). A host that has neither
answered nor been looked at is the first thing to go; a host someone keeps
opening is kept however old it is.

```
crusade archive --status     # where the space is going, and what qualifies
crusade archive --dry-run    # what would be removed, changing nothing
crusade archive              # archive, delete, reclaim
```

Hosts are written to a gzipped JSON Lines file under `<data dir>/archive/`
**before** they are deleted — the same format `crusade export` produces, so an
archive can be read back with the same tools. Nothing is deleted that was not
written out first.

With `[archive] max_db_mb` set, this happens on its own once the database
passes that size, after a scan or a monitor pass. It escalates cheapest-first
and stops as soon as the database is back under the limit:

1. expired and derived rows — facet cache, old delivered alerts, finished
   jobs, timeline entries past retention (the newest entry per service is
   always kept);
2. screenshots on disk that no service references any more;
3. stale, never-visited hosts, least useful first, in bounded batches.

Undelivered alerts hold their host back, so nothing is archived out from under
an alert nobody has seen. Progress is judged by live bytes (allocated minus
free pages) rather than file size, because deletes free pages for reuse without
shrinking the file; one `VACUUM` at the end returns the space, and only if
something was actually removed. A run that cannot find anything eligible says
so instead of silently doing nothing.

Measured on 30k synthetic hosts, 75% of them stale and unvisited:

```
archive --status   102.1 MiB, 30000 hosts, 27600 never viewed, 20100 eligible
archive            20100 hosts to 11 files; 102.1 MiB -> 35.9 MiB
auto (20 MiB cap)  6000 hosts in 3 batches; 35.9 MiB -> 13.5 MiB, then stops
```

## Lazy loading and caching

Nothing is read until something needs it, and expensive derived data is built
once rather than per run.

| | before | after |
|---|---|---|
| scan that finds no open ports | 7.58 s | **0.008 s** (nothing loads) |
| CVE data ready to query | 6,029 ms (parse ~470 MB JSON) | **1 ms** (open indexed cache) |
| facets over the whole index, repeat view | 2,422 ms | **0.1 ms** |

* **Datasets load on first use.** `Datasets` holds each dataset behind a
  `OnceLock`: nmap probes load when a banner needs fingerprinting, geo/ASN when
  a host needs enrichment, the embedding model only if embedding is on. A run
  that discovers nothing loads nothing.
* **CVE data is an indexed cache, not a parse.** `update-data` parses the feeds
  once into `data/cve-cache.db` (319k CVEs, 2.6M match rules) indexed by
  product; scans open it and query per product, so memory stays flat instead of
  holding every CVE. A `meta` fingerprint of the source feeds means a newly
  downloaded feed rebuilds the cache rather than being silently ignored. Delete
  the file and it rebuilds; without it, scans fall back to parsing the feeds.
* **An in-process memo** caches product lookups, since one scan meets the same
  few products repeatedly.
* **Facets are cached against a write generation.** Every write transaction
  bumps a counter, so a cached aggregate is served only while the data behind
  it is unchanged, and is recomputed otherwise — no staleness window to reason
  about.
* **Writes are batched.** The pipeline writes hosts 200 per transaction, and
  `Store::upsert_hosts` is the bulk entry point.

## Scale and performance

`cargo run --release -p crusade-store --example ingest_bench -- <hosts> <services> <batch>`
measures ingest and query cost against synthetic hosts on a real database.
On a 4-core container, 200k hosts x 3 services:

| | |
|---|---|
| ingest (batched) | ~4,800 hosts/s, ~14,400 services/s |
| on disk | ~5.8 KiB per host |
| page of 25 results | 0.5–3 ms (80–320 ms for `net:` and free-text, which sort large match sets) |
| exact count | 1.5–290 ms depending on selectivity |
| capped count | 0.4–200 ms, and never slower than exact |
| facets over the whole index | ~2.2 s |

Use `Store::upsert_hosts` for bulk ingest: one transaction per host is
dominated by commit cost, and batching is ~8x faster. `service_history`
records *changes* rather than passes — an unchanged rescan appends nothing —
so a monitor can run continuously without the timeline growing without bound.
Search pages use `count_capped` and render "10,000+" rather than scanning the
whole index for an exact total; the JSON API still reports exact counts.
Faceting the whole index is the remaining slow path.

## Data sources (all free, no keys)

iptoasn.com ip2asn tables · DB-IP City Lite · nmap-service-probes (ships with
nmap) · NVD CVE JSON 2.0 feeds (fetched by `update-data`) · CISA KEV catalog ·
crt.sh certificate transparency.

## License

MIT. Provided for authorised security research and education.
