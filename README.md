# cxscan — hybrid scan orchestrator (SAST · SCA · KICS · 2ms)

One git URL in → clone once → run four engines against the local working copy →
parse to a unified model → per-engine gates → one console dashboard.

**Posture: "no source code leaves."** SCA Resolver resolves dependencies on-prem
but uploads dependency metadata to the cloud. This is *not* an air-gapped tool.

## What's real vs. what needs your tenant
| Piece | State |
|---|---|
| Clone-once → scan-local flow | done |
| KICS runner + SARIF parse | done, end-to-end |
| 2ms runner + SARIF parse + secret redaction | done, end-to-end |
| Async job runner, per-engine live status, gates | done |
| Console: Scan / Setup / Pipeline tabs | done |
| Setup: package-manager detection + guided install | done (detection real) |
| Setup: kics/2ms download from GitHub + checksum verify | done (degrades to manual when GitHub is blocked) |
| Pipeline: Jenkins + Azure snippet generation | done |
| SAST runner (**CxSAST on-prem REST, v8.6+ flow**) | wired; emits **`sast.json`** via the REST flow + REST `resultsStatistics`. **Validate endpoints/team_id against your tenant** |
| SCA runner (Resolver CLI / `cx` CLI) | wired; JSON parser handles **CxOne CLI** + **Resolver** shapes. **Confirm field paths against a real report** |
| App auth (HTTP Basic, env-gated) | done — protects dashboard + API when configured |
| Tests + CI | done — `pytest` suite + GitHub Actions (`.github/workflows/ci.yml`) |

The SAST REST flow (auth → project → upload zip → scan → poll → report) and the
SCA/SAST parsers are isolated — hand me one real report of each from the
Prudential tenant and I'll lock the field paths.

### SAST / SCA as JSON
CxSAST report generation cannot emit JSON (only PDF/RTF/CSV/XML), so the SAST
runner generates XML (the only source with full data-flow), pulls severity counts
from the REST API (`/sast/scans/{id}/resultsStatistics`), and writes a unified
**`sast.json`** — that JSON is what the dashboard consumes. `parse_sast_json` also
tolerates a raw OData results page for forward-compat. SCA is JSON-native: the
parser auto-detects the CxOne `cx` CLI report (`results[]` with `type: sca`) or a
Resolver risk-report.

## Reports
PDF generated for SAST, SCA, and KICS (the human artifact). 2ms is JSON-only.
The dashboard consumes the normalized-finding JSON from all four (SAST XML is
parsed to JSON internally), so "JSON to the dashboard, PDF for people" holds.

## Quickstart (local, no tenant needed)
```bash
./run.sh                               # venv + deps + uvicorn on :8080
# open http://localhost:8080 → Setup tab installs KICS + 2ms → Scan tab → Start scan
```
`config.local.yaml` enables only the OSS engines (KICS + 2ms), so you can run the
whole flow end-to-end against a public repo with **no CxSAST/CxOne tenant and no git
credentials**. Pass it from the Scan form, or set `config_path` in the API call.

## Run (full, with a tenant)
```bash
pip install -r requirements.txt
export GIT_USER=... GIT_TOKEN=... CXSAST_USER=... CXSAST_PASSWORD=... CXSCA_TENANT=... CXSCA_USER=... CXSCA_PASSWORD=...
uvicorn app.app:app --reload --port 8080
# open http://localhost:8080  → "Start scan"
```
`config.example.yaml` drives everything: git input + auth, per-engine enable/config,
per-engine thresholds, report toggles. `${VAR}` values are read from the environment;
nothing sensitive is persisted or rendered back in the UI.

## App auth
2ms findings contain real secret locations, so put a credential in front before
anyone else can reach the port. Set **both** to enable HTTP Basic on the whole app
(dashboard + API); leave either unset and auth is off (local dev):
```bash
export CXSCAN_AUTH_USER=admin CXSCAN_AUTH_PASSWORD=change-me
```
This is a single shared credential (the floor) — swap for real SSO before hosted use.

## Tests
```bash
pip install -r requirements-dev.txt
pytest -q                              # parsers, gates, severity, env, auth
```
CI runs the same suite on every push/PR (`.github/workflows/ci.yml`).

## Run (container — podman)
```bash
podman build --build-arg TWOMS_VERSION=3.0.0 --build-arg KICS_VERSION=2.1.3 -t cxscan .
podman run --rm -p 8080:8080 \
  -e GIT_USER -e GIT_TOKEN -e CXSAST_USER -e CXSAST_PASSWORD \
  -e CXSCA_TENANT -e CXSCA_USER -e CXSCA_PASSWORD \
  -e CXSCAN_AUTH_USER -e CXSCAN_AUTH_PASSWORD \
  -v /opt/cx/ScaResolver:/opt/cx/ScaResolver:Z \
  -v /opt/cx/cxsast-cli:/opt/cx/cxsast-cli:Z \
  -v "$PWD/config.example.yaml":/srv/config.example.yaml:Z \
  cxscan
```
KICS + 2ms are baked into the image. SCA Resolver and the legacy CxSAST CLI aren't
publicly redistributable — mount them (above). The Dockerfile is OCI-standard, so
`docker` works as a drop-in if you prefer it (drop the `:Z` SELinux volume flags).

## Thresholds / gates
Each engine has a threshold map `{Severity: max_count_at_or_above}`. A gate fails if
any floor is exceeded; the overall verdict fails if any engine fails. Severities are
normalized to one scale (INFO→CRITICAL) so the dashboard compares like with like.

## Sharp edges you own
- **Dependency-manager matrix:** Resolver needs the real package managers installed to
  resolve. `generate_lockfiles` runs build tooling on cloned source = code execution —
  keep it off unless sandboxed.
- **Clone depth:** shallow clone breaks 2ms history + SCA delta. Use full clone if
  `twoms.scan_git_history` is on.
- **2ms results contain real secret locations.** In-memory store + redaction is a floor,
  not access control. Put auth in front before anyone but you touches it.
- **Pin engine versions.** `latest` on a security gate is non-reproducible.
