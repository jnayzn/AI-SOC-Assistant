# IntelOwl Threat Intelligence Integration Kit

Adds a Threat Intelligence enrichment layer backed by **your already-running
IntelOwl instance** to the Enterprise AI SOC Assistant. All IntelOwl calls happen
**backend-only**; the API token never reaches React. Nothing about IntelOwl's own
install/config is changed.

## How to apply

```bash
# from the kit folder, pointing at your project checkout
python3 apply_integration.py /path/to/Enterprise-AI-SOC-Assistant
```

The script copies the new files, edits what it can safely, and prints any MANUAL
steps (also listed below). It is idempotent \u2014 safe to run again.

Then:
1. Set `INTELOWL_API_TOKEN` (and `INTELOWL_URL` if not the default) in `backend/.env`.
2. Restart the backend. The `intelowl_scans` table is auto-created on startup
   (or run `alembic stamp 0002_intelowl_scans` then `alembic upgrade head`).

## Files created

**Backend**
- `app/models/intelowl.py` \u2014 `IntelOwlScan` persistence model (correlated to `analyses`).
- `app/schemas/intelowl.py` \u2014 request/response + normalized result schemas.
- `app/services/intelowl_service.py` \u2014 reusable IntelOwl client (httpx, token backend-only, never logged).
- `app/api/v1/endpoints/intelowl.py` \u2014 endpoints + `run_analysis_enrichment_bg`.
- `alembic/versions/0002_intelowl_scans.py` \u2014 migration for the new table.

**Frontend**
- `src/types/intelowl.ts` \u2014 TypeScript types mirroring the backend schemas.
- `src/components/IntelOwlResults.tsx` \u2014 per-IOC cards, auto-scan + polling, refresh.
- `src/components/IntelOwlAnalysis.tsx` \u2014 readable details modal with [Show Raw JSON].
- (api helpers appended to `src/services/api.ts`; reference copy: `frontend_api_additions.ts`).

## Files edited

`config.py`, `router.py`, `models/__init__.py`, `alembic/env.py`, `.env(.example)`,
`services/api.ts` (auto), plus MANUAL: `analyze.py`, `copilot_service.py`,
`docker-compose.yml`, `AnalysisResult.tsx`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `INTELOWL_URL` | `http://host.docker.internal` | Base URL of your IntelOwl instance |
| `INTELOWL_API_TOKEN` | (empty) | IntelOwl API token \u2014 **backend only** |
| `INTELOWL_TIMEOUT` | `120` | Per-request timeout (seconds) |
| `INTELOWL_VERIFY_SSL` | `false` | Verify IntelOwl TLS certificate |
| `INTELOWL_CACHE_TTL_SECONDS` | `3600` | Reuse completed scans within this window |
| `INTELOWL_DEFAULT_PLAYBOOK` | (empty) | Optional default IntelOwl playbook |

When `INTELOWL_API_TOKEN` is empty the integration self-disables: endpoints return
503 and the UI panel hides itself, so the rest of the app is unaffected.

## Endpoints (prefix `/api/v1/intelowl`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Configured / reachable / authenticated probe |
| POST | `/scan` | Scan one observable |
| GET | `/jobs/{id}` | Poll one scan (refreshes from IntelOwl) |
| GET | `/results/{id}` | Normalized result for one scan |
| POST | `/scan/analysis/{analysis_id}` | Scan every IOC of an analysis (bulk) |
| GET | `/analysis/{analysis_id}` | List + refresh all scans of an analysis |

## Flow

1. `/analyze` runs as before; afterwards a **non-blocking background task**
   (`run_analysis_enrichment_bg`) submits each IOC to IntelOwl.
2. The UI panel calls `POST /scan/analysis/{id}` on mount then polls
   `GET /analysis/{id}` every 5s until every job is terminal.
3. Statuses: \u23F3 PENDING \u00b7 \uD83D\uDD04 RUNNING \u00b7 \u2713 COMPLETED \u00b7 \u2715 FAILED \u00b7 \u26A0 TIMEOUT.
   Verdicts: \uD83D\uDD34 malicious \u00b7 \uD83D\uDFE0 suspicious \u00b7 \uD83D\uDFE2 clean \u00b7 \u26AA unknown.
4. Copilot / Detailed Explanation / MITRE / Playbooks read **only real IntelOwl
   results** from the DB \u2014 never invented.

## Manual steps (exact snippets)

### analyze.py
```python
from fastapi import APIRouter, BackgroundTasks, Depends  # add BackgroundTasks
from app.core.config import get_settings
from app.api.v1.endpoints.intelowl import run_analysis_enrichment_bg

# in the analyze endpoint signature, before db=Depends(get_db):
#   background_tasks: BackgroundTasks,
# after the analysis row is created/saved (analysis.id available):
if get_settings().intelowl_configured:
    background_tasks.add_task(run_analysis_enrichment_bg, analysis.id)
```

### copilot_service.py
```python
from sqlalchemy import select
from app.models.intelowl import IntelOwlScan

# 1) In the system prompt priority list, insert IntelOwl as #7 (shift the rest):
#    "7. IntelOwl threat-intelligence enrichment results (real, from the DB)"
# 2) Add a rule near the "Do NOT invent..." line:
#    "- Cite IntelOwl verdicts/reputation only when present; never invent them."
# 3) Add this method to CopilotService:
def _intelowl_context_block(self, analysis_id: str) -> str:
    if not analysis_id:
        return ""
    rows = self.db.execute(
        select(IntelOwlScan)
        .where(IntelOwlScan.analysis_id == analysis_id)
        .order_by(IntelOwlScan.created_at.asc())
    ).scalars().all()
    if not rows:
        return ""
    lines = ["IntelOwl Threat Intelligence (real results):"]
    for r in rows:
        line = f"- {r.observable_type}:{r.observable} status={r.status}"
        if r.verdict:
            line += f" verdict={r.verdict}"
        norm = r.normalized_result or {}
        rep = (norm.get("reputation") or {}) if isinstance(norm, dict) else {}
        if rep.get("score") is not None:
            line += f" score={rep['score']}"
        srcs = norm.get("reputation_sources") if isinstance(norm, dict) else None
        if srcs:
            line += f" sources={','.join(srcs)}"
        lines.append(line)
    return "\n".join(lines)

# 4) In chat(), after context_block = self._analysis_context_block(analysis):
intelowl_block = self._intelowl_context_block(getattr(analysis, "id", None))
if intelowl_block:
    context_block = f"{context_block}\n\n{intelowl_block}"
```

### docker-compose.yml (backend service `environment:`)
```yaml
      INTELOWL_URL: ${INTELOWL_URL:-http://host.docker.internal}
      INTELOWL_API_TOKEN: ${INTELOWL_API_TOKEN:-}
      INTELOWL_TIMEOUT: ${INTELOWL_TIMEOUT:-120}
      INTELOWL_VERIFY_SSL: ${INTELOWL_VERIFY_SSL:-false}
      INTELOWL_CACHE_TTL_SECONDS: ${INTELOWL_CACHE_TTL_SECONDS:-3600}
```
Keep the existing `extra_hosts: - "host.docker.internal:host-gateway"` so the
container can reach IntelOwl running on the host.

### AnalysisResult.tsx
```tsx
import { IntelOwlResults } from "@/components/IntelOwlResults"
// ...render right after <ThreatIntelPanel .../>:
<IntelOwlResults analysisId={result.id} />
```

## Testing
See `tests/intelowl_smoke_tests.sh` for 15 curl checks (health, scan, poll,
results, bulk, cache, auth-safety, validation).
