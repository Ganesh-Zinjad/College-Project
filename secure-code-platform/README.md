# AI Secure Code Vulnerability Detection Platform

A SaaS-style web application that detects vulnerabilities in (AI-generated or
any) source code using a **Triple Judge Evaluation Engine**: a project is
marked **SECURE** only if all three independent engines agree it's secure.

| Engine | What it does |
|---|---|
| **1. CodeQL** | Static analysis. Uses the real `codeql` CLI when installed; otherwise falls back automatically to a built-in AST/regex rule set covering the same vulnerability classes, so the platform works out of the box. |
| **2. AI Auditor** | Sends each file to Claude with a security-review prompt and parses back structured findings (title, severity, CWE, fix, secure example). |
| **3. ML Classifier** | A TF-IDF + Logistic Regression model (trained by `scripts/train_ml_model.py`) scores sliding windows of code for vulnerability probability. |

## Tech stack

- **Frontend**: HTML5, CSS3, vanilla ES6 modules. No frameworks, no build step.
- **Backend**: FastAPI, SQLAlchemy (SQLite by default), JWT auth, RBAC, WebSockets.

## Project structure

```
secure-code-platform/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── core/                # config, db, security (JWT/bcrypt), DI, exceptions
│   │   ├── models/               # SQLAlchemy ORM models
│   │   ├── schemas/               # Pydantic request/response schemas
│   │   ├── api/v1/                # REST routers (auth, upload, scan, results, history, profile, admin)
│   │   ├── services/
│   │   │   ├── engines/           # base_engine, codeql_engine, ai_engine, ml_engine, verdict_engine
│   │   │   ├── scan_service.py    # orchestrates upload -> scan -> persistence
│   │   │   ├── auth_service.py / email_service.py / report_service.py
│   │   ├── repositories/          # data-access layer (User/Scan repositories)
│   │   ├── utils/                 # CWE/OWASP knowledge base, file handling
│   │   └── websocket/             # live scan-progress websocket
│   ├── scripts/train_ml_model.py  # trains Engine 3's classifier
│   ├── ml_artifacts/              # trained model + vectorizer (auto-generated)
│   └── requirements.txt
└── frontend/
    ├── index.html, register.html, forgot-password.html, reset-password.html, verify-email.html
    ├── dashboard.html, upload.html, scan-progress.html, results.html, history.html, profile.html, admin.html
    ├── css/  (variables, base, layout, components, animations)
    └── js/modules/ (api, auth, shell, charts, toast, theme, utils, websocket)
```

## Running it

### Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
cp .env.example .env                                  # edit values as needed
uvicorn app.main:app --reload --port 8000
```

The first run automatically:
- creates the SQLite database and tables,
- trains the ML classifier if `ml_artifacts/*.joblib` don't exist yet.

The **first user to register becomes an admin** automatically — convenient
for a fresh database with no other way to bootstrap one.

API docs: `http://localhost:8000/docs`

### Frontend

No build step — it's static HTML/CSS/JS. Serve it with anything:

```bash
cd frontend
python3 -m http.server 5500
```

Then open `http://127.0.0.1:5500/index.html`. The frontend auto-detects it's
running on port 5500 (a common static-server port) and points API calls at
`http://127.0.0.1:8000/api/v1`. To point at a different backend, set
`window.__API_BASE__` before the page's module scripts load, or deploy the
frontend behind the same origin as the API (in which case it defaults to
same-origin `/api/v1`).

### Enabling each engine fully

- **CodeQL**: install the [CodeQL CLI](https://github.com/github/codeql-cli-binaries)
  and set `CODEQL_CLI_PATH` in `.env`. Without it, Engine 1 silently uses its
  built-in fallback analyzer — still fully functional, just not the official tool.
- **AI Auditor**: set `ANTHROPIC_API_KEY` in `.env`. Without it, this engine
  reports "did not run" rather than fabricating a verdict.
- **ML Classifier**: works immediately — trains itself on first use.

## Security notes

- Passwords are hashed with bcrypt; JWTs are short-lived access tokens (30 min)
  plus longer-lived refresh tokens (7 days).
- API keys are stored as hashes — the raw key is shown exactly once, at creation.
- All scan ownership checks happen server-side (`ForbiddenError` on cross-user access).
- File uploads are validated by extension and size; ZIP extraction skips
  `.git`, `node_modules`, `__pycache__`, etc.
