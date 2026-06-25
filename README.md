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
| SAST runner (**CxSAST on-prem REST, v8.6+ flow**) | wired; **validate endpoints/team_id + XML adapter against your tenant** |
| SCA runner (Resolver CLI) | wired; **JSON adapter needs a real Resolver report to finalize** |

The SAST REST flow (auth → project → upload zip → scan → poll → report) and the
SCA/SAST report parsers are isolated — hand me one real report of each from the
Prudential tenant and I'll lock the field paths.

## Reports
PDF generated for SAST, SCA, and KICS (the human artifact). 2ms is JSON-only.
The dashboard consumes the normalized-finding JSON from all four (SAST XML is
parsed to JSON internally), so "JSON to the dashboard, PDF for people" holds.

## Run (local)
```bash
pip install -r requirements.txt
export GIT_USER=... GIT_TOKEN=... CXSAST_USER=... CXSAST_PASSWORD=... CXSCA_TENANT=... CXSCA_USER=... CXSCA_PASSWORD=...
uvicorn app.app:app --reload --port 8080
# open http://localhost:8080  → "Start scan"
```
`config.example.yaml` drives everything: git input + auth, per-engine enable/config,
per-engine thresholds, report toggles. `${VAR}` values are read from the environment;
nothing sensitive is persisted or rendered back in the UI.

## Run (container)
```bash
docker build --build-arg TWOMS_VERSION=3.0.0 --build-arg KICS_VERSION=2.1.3 -t cxscan .
docker run --rm -p 8080:8080 \
  -e GIT_USER -e GIT_TOKEN -e CXSAST_USER -e CXSAST_PASSWORD \
  -e CXSCA_TENANT -e CXSCA_USER -e CXSCA_PASSWORD \
  -v /opt/cx/ScaResolver:/opt/cx/ScaResolver \
  -v /opt/cx/cxsast-cli:/opt/cx/cxsast-cli \
  -v "$PWD/config.example.yaml":/srv/config.example.yaml \
  cxscan
```
KICS + 2ms are baked into the image. SCA Resolver and the legacy CxSAST CLI aren't
publicly redistributable — mount them (above).

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
