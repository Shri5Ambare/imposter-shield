# ImposterShield

An impersonation-detection and evidence-assembly system. It watches for accounts
impersonating a protected identity ("Source of Truth"), verifies suspects with
computer-vision + NLP, scores confidence, and assembles **review-ready evidence**
(dossier PDF + DMCA notice + official report form pre-fill) for a human to submit.

## Design principles

1. **Verification is automated. Submission is not.** The system never submits a
   report or DMCA on its own. It prepares everything and hands a human the final
   click. This is deliberate — it keeps reports high-quality, auditable, and
   inside platform Terms of Service.
2. **No anti-bot evasion.** We do not solve CAPTCHAs, rotate proxies to dodge
   rate limits, or spoof browser fingerprints. If a platform asks for human
   verification, a human provides it.
3. **Official channels first.** DMCA to the platform's registered copyright agent
   and the platform's own impersonation form are the highest-yield paths.
4. **Every decision is logged.** Scores, model versions, thresholds, and the
   evidence each decision rested on are persisted for audit and appeal.

## Architecture

```
                          ┌──────────────────────────┐
                          │   Source of Truth store   │
                          │ (verified handles, photos,│
                          │  canonical bio, watermark)│
                          └────────────┬──────────────┘
                                       │
                ┌──────────────────────▼───────────────────────┐
                │            Discovery / Ingestion              │
                │  - Official platform APIs where available     │
                │  - Search APIs (SerpApi / social-searcher)    │
                │  - Reverse-image search (stolen photos)       │
                │  - Username permutation generation            │
                │  Emits: SuspectCandidate {url, handle, imgs,  │
                │         bio, metadata}                         │
                └──────────────────────┬───────────────────────┘
                                       │ Celery task per candidate
                ┌──────────────────────▼───────────────────────┐
                │            AI Verification Engine             │
                │  - Face match  (DeepFace / Rekognition)       │
                │  - Bio/post semantic sim (SentenceTransformers)│
                │  - Watermark check (was photo stolen?)        │
                │  - Heuristic signals (age, ratios, overlap)   │
                │  → ConfidenceScore + per-signal breakdown     │
                └──────────────────────┬───────────────────────┘
                                       │
                 score ≥ review_threshold (default 0.90)
                                       │
                ┌──────────────────────▼───────────────────────┐
                │        Evidence & Remediation (assembly)      │
                │  - Dossier PDF (side-by-side, EXIF, timeline) │
                │  - DMCA notice draft (localized)              │
                │  - Link triage (sandbox URL analysis)         │
                │  - Report-form PRE-FILL (Playwright, attended)│
                │  → HUMAN REVIEW QUEUE  ← stop here            │
                └──────────────────────┬───────────────────────┘
                                       │ human approves & submits
                                       ▼
                          Platform report / DMCA email
```

## Infrastructure

| Component   | Role                                                                |
|-------------|---------------------------------------------------------------------|
| FastAPI     | API + human review dashboard backend                                |
| Celery      | Async per-candidate verification & assembly jobs                    |
| Redis       | Celery broker + rate-limit token buckets (respect platform limits)  |
| PostgreSQL  | Suspects, scores, evidence, decision/audit log                      |
| MinIO / S3  | Image + dossier PDF storage                                         |
| Playwright  | **Attended** form pre-fill (headed, hands off to human)             |
| Docker      | One container per service; compose for local, k8s for prod          |

## Module map

| Path                                   | What it does                                  |
|----------------------------------------|-----------------------------------------------|
| `imposter_shield/ingestion/discovery.py` | Candidate discovery via search/reverse-image |
| `imposter_shield/core/verification.py` | Face match + NLP similarity                   |
| `imposter_shield/core/scoring.py`      | Confidence score fusion                       |
| `imposter_shield/core/dossier.py`      | Evidence PDF generation                        |
| `imposter_shield/core/link_triage.py`  | Bio-link safety analysis (sandboxed)          |
| `imposter_shield/reporting/dmca.py`    | DMCA notice draft generator                    |
| `imposter_shield/reporting/report_assistant.py` | Attended report-form pre-fill        |
| `imposter_shield/db/models.py`         | SQLAlchemy models + audit log                  |

## Quickstart (runs with zero external services)

The app defaults to SQLite and degrades gracefully without the heavy ML stack, so
you can boot the full UI + API immediately:

```bash
# 1. install the light core (no torch/tensorflow)
pip install -r requirements-core.txt

# 2. create the DB + an admin + demo case (prints the admin password)
python seed.py

# 3. run it
uvicorn imposter_shield.api:app --reload

# 4. open http://localhost:8000/  and log in with the printed credentials
```

For real face matching + paraphrase-aware bio similarity, also
`pip install -r requirements.txt` (pulls torch/tensorflow — large). Until then
the NLP engine falls back to lexical similarity and face score comes from
ingested metadata.

For production: set `ISHLD_SECRET_KEY`, point `ISHLD_DATABASE_URL` at Postgres,
and lock `ISHLD_CORS_ORIGINS` / `ISHLD_ALLOWED_HOSTS` to your domain.

## Security model

| Control | Implementation |
|---------|----------------|
| Authentication | JWT bearer, bcrypt-hashed passwords (`security/auth.py`) |
| Authorization | Role-based (`admin`/`reviewer`/`viewer`) + per-identity ownership checks; 404 (not 403) on others' resources to avoid existence leaks |
| Input validation | Pydantic everywhere; `HttpUrl` for URLs; bounded string lengths; min-12-char passwords |
| Injection | SQLAlchemy ORM only — no string-built SQL; output HTML-escaped in the SPA |
| Rate limiting | slowapi; login throttled harder (brute-force resistance) |
| Transport/UI | Strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, HSTS, nosniff, locked CORS + TrustedHost |
| Secrets | Env-only; loud warning when running on an ephemeral key |
| Auditability | Every state change writes an immutable `ActionLog` row with actor + detail |
| Abuse prevention | No automated submission; no bot-detection bypass; submission attributed to a named human |

## Harm coverage (money + defamation)

The pieces that target the harms victims actually suffer:

- `core/classifier.py` — flags financial-solicitation and defamation language in
  captured DMs/posts, with the exact matched phrases.
- `db.HarmEvidence` — stores what the fake account *did* (scam DM, defamatory
  post), not just that it resembles you. Harm evidence forces a case into review
  regardless of resemblance score.
- `reporting/claim_router.py` — routes each case to the right channel: fraud
  report (critical) for money/phishing, defamation notice (legal review) for
  reputational attacks, DMCA for stolen photos, impersonation report as baseline.
- `reporting/notices.py` — drafts the fraud and defamation notices (DMCA lives in
  `reporting/dmca.py`). All review-required; nothing auto-sends.

## A note on scope

This tool is for protecting **your own** identity (or a client who has authorized
you in writing). Pointed at third parties it doesn't represent, an automated
reporting pipeline becomes a harassment tool — which is why submission stays
manual and every action is attributed to a named human reviewer.
