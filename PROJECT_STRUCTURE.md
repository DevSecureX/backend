# Project Structure

DevSecureX backend — a FastAPI service that orchestrates 16+ security tools behind
an async scanning pipeline with Redis-backed background workers and PostgreSQL storage.

```
backend/
├── app/                      # Application package
│   ├── main.py               # FastAPI application entrypoint (routes, middleware, lifespan)
│   ├── api/                  # API-level wiring (health, routers)
│   ├── auth/                 # Authentication: JWT sessions, GitHub/Google OAuth, RBAC
│   ├── repos/                # Repository management (connect, list, sync)
│   ├── scans/                # Core scanning engine
│   │   ├── services/         #   scan orchestration & result processing
│   │   ├── tools/            #   security tool adapters (semgrep, trivy, bandit, …)
│   │   ├── workers/          #   background worker processes
│   │   ├── unified_queue/    #   Redis queue + worker startup
│   │   ├── autofix_queue/    #   AI auto-fix queue
│   │   ├── pr_scanning/      #   pull-request scanning
│   │   ├── webhooks/         #   GitHub webhook handlers
│   │   └── integrations/     #   third-party integrations
│   ├── ai_assistant/         # AI-powered vulnerability explanations & fixes
│   ├── custom_rules/         # User-defined scanning rules engine
│   ├── rules/                # Built-in rule definitions & demo vulnerabilities
│   ├── cli_scan/             # CLI-driven scan support
│   ├── issues/               # Issue tracking for findings
│   ├── reports/              # Report generation
│   ├── analytics/            # Usage & scan analytics
│   ├── support/              # Support/contact features
│   ├── monitoring/           # In-app metrics & observability hooks
│   ├── core/                 # Shared core: config, database, task system, utilities
│   ├── config/               # Configuration helpers
│   ├── migrations/           # Alembic database migrations
│   ├── scripts/              # Database management & migration scripts
│   ├── tests/                # Test suite
│   └── requirements*.txt     # Python dependencies (core / extras / analytics)
│
├── scripts/                  # Operational & developer tooling
│   ├── entrypoint.sh         #   container entrypoints
│   ├── install-tools.sh      #   install the security scanner binaries
│   ├── generate_secrets.py   #   generate secure keys for first-time setup
│   ├── health_check.py       #   service health verification
│   ├── init_database.py      #   database initialization
│   └── db-backup/            #   backup utilities
│
├── docker/                   # Additional compose files (testing, production overrides)
├── monitoring/               # Infra-as-code: Prometheus, Grafana, Alertmanager, Logstash
├── Dockerfile                # Production container image
├── docker-compose.yml        # Local development stack
├── docker-compose.production.yml  # Production stack (API + workers + db + redis)
├── cloudbuild.yaml           # GCP Cloud Build config
├── start.py / start_fast.py  # Application startup entrypoints
├── .env.example              # Environment variable template (no secrets)
└── README.md
```

## Request flow

1. A scan is triggered via API (`POST /scans/trigger`) or a GitHub PR webhook.
2. The job is enqueued in Redis (`scans/unified_queue`).
3. A background worker claims the job and runs the relevant tool adapters
   (`scans/tools`) in parallel.
4. Findings are normalized, optionally enhanced by the AI assistant, and persisted
   to PostgreSQL with Redis caching.
5. Results are surfaced through the API and, for PRs, posted back to GitHub.
