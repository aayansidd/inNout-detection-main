# AEGIS USB — rules for Claude Code

Real-time USB malware detection, threat-intel and forensic-integrity system (IS-353 course project).
Full spec: `docs/MASTER_PROMPT.md`. Build order: §12.

## Hard safety rules (never break)
- Never execute, open with OS handlers, or import scanned files. Read bytes only.
- Never download samples from MalwareBazaar/VirusTotal (`get_file` is forbidden). Intel lookups are **hash-only**.
- Demo payloads are inert bytes. No real malware and no real EICAR file on disk. (The EICAR *hash* may be looked up.)
- Quarantine **copies** into the vault; deleting the original needs an explicit user click.
- Never use `verify=False` for TLS. Secrets only from `.env` (git-ignored).

## Conventions
- Backend: Python 3.11+ (dev venv uses 3.12 because yara-python has no 3.14 wheels), FastAPI, Pydantic v2. `ruff` clean, type hints, docstrings on public functions.
- Chunked reads only (64 KB). No blocking in the event loop: polling/traversal/hashing/YARA in threads, intel via async httpx.
- Pydantic models (`api/schemas.py`) and `frontend/src/types/telemetry.ts` must match field-for-field.
- No TODOs or stubs. Conventional commits.

## Commands
- Tests (from repo root): `backend/.venv/bin/python -m pytest`
- Lint: `cd backend && .venv/bin/ruff check .`
- Payloads: `backend/.venv/bin/python qa_demo/generate_payloads.py`
- API: `cd backend && .venv/bin/python -m app` (port = `AEGIS_PORT`, default 8000; set `VITE_BACKEND_PORT` in `frontend/.env` to match)
- UI: `cd frontend && npm run dev`
