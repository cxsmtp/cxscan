"""Generate copy-paste CI snippets that mirror the GUI scan, for teams that want
the same four engines in their existing Jenkins / Azure pipelines. Separate track:
the tool produces the text; the user pastes it. Thresholds come from the config so
the pipeline gate matches the console gate.

Note: SAST in CI uses the CxSAST plugin/CLI on the build agent (the REST flow the
GUI uses isn't ergonomic inline). SCA uses the CxOne CLI with Resolver. KICS/2ms
run as their published actions/containers."""
from __future__ import annotations


def _fail_on(threshold: dict) -> str:
    sevs = [s.lower() for s in (threshold or {}).keys()]
    return ",".join(sevs) if sevs else "high,critical"


def jenkins(cfg: dict) -> str:
    e = cfg["engines"]
    kics_fail = _fail_on(e.get("kics", {}).get("threshold"))
    return f"""// cxscan — generated Jenkins stages (gates mirror your console config)
pipeline {{
  agent any
  environment {{
    CXSAST_USER = credentials('cxsast-user')
    CXSCA_CREDS = credentials('cxsca-creds')   // tenant:user:pass
  }}
  stages {{
    stage('Checkout') {{ steps {{ checkout scm }} }}

    stage('KICS (IaC)') {{ steps {{ sh '''
      docker run --rm -v "$PWD":/path checkmarx/kics:latest scan \\
        -p /path -o /path/reports --report-formats json,pdf \\
        --fail-on {kics_fail} --no-progress
    ''' }} }}

    stage('2ms (secrets)') {{ steps {{ sh '''
      docker run --rm -v "$PWD":/repo checkmarx/2ms:latest \\
        filesystem --path /repo --report-path /repo/reports/2ms.json
    ''' }} }}

    stage('SCA (Resolver -> CxOne)') {{ steps {{ sh '''
      cx scan create --project-name "$JOB_NAME" --branch "$BRANCH_NAME" -s . \\
        --scan-types sca --sca-resolver ./ScaResolver \\
        --report-format json --output-name reports/sca
    ''' }} }}

    stage('SAST (CxSAST on-prem)') {{ steps {{ sh '''
      runCxConsole.sh Scan -CxServer "$CXSAST_SERVER" \\
        -CxUser "$CXSAST_USER_USR" -CxPassword "$CXSAST_USER_PSW" \\
        -ProjectName "CxServer/$JOB_NAME" -LocationType folder -LocationPath . \\
        -ReportPDF reports/sast.pdf -ReportXML reports/sast.xml
    ''' }} }}
  }}
  post {{ always {{ archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true }} }}
}}"""


def azure(cfg: dict) -> str:
    e = cfg["engines"]
    kics_fail = _fail_on(e.get("kics", {}).get("threshold"))
    return f"""# cxscan — generated Azure DevOps steps (gates mirror your console config)
trigger: [ main ]
pool: {{ vmImage: 'ubuntu-latest' }}
steps:
  - checkout: self

  - script: |
      docker run --rm -v "$(Build.SourcesDirectory)":/path checkmarx/kics:latest scan \\
        -p /path -o /path/reports --report-formats json,pdf --fail-on {kics_fail} --no-progress
    displayName: 'KICS (IaC)'

  - script: |
      docker run --rm -v "$(Build.SourcesDirectory)":/repo checkmarx/2ms:latest \\
        filesystem --path /repo --report-path /repo/reports/2ms.json
    displayName: '2ms (secrets)'

  - script: |
      cx scan create --project-name "$(Build.Repository.Name)" --branch "$(Build.SourceBranchName)" \\
        -s . --scan-types sca --sca-resolver ./ScaResolver --report-format json --output-name reports/sca
    displayName: 'SCA (Resolver -> CxOne)'
    env: {{ CX_TENANT: $(CXSCA_TENANT), CX_CLIENT_ID: $(CXSCA_ID), CX_CLIENT_SECRET: $(CXSCA_SECRET) }}

  - script: |
      runCxConsole.sh Scan -CxServer "$(CXSAST_SERVER)" -CxUser "$(CXSAST_USER)" \\
        -CxPassword "$(CXSAST_PASSWORD)" -ProjectName "CxServer/$(Build.Repository.Name)" \\
        -LocationType folder -LocationPath . -ReportPDF reports/sast.pdf -ReportXML reports/sast.xml
    displayName: 'SAST (CxSAST on-prem)'

  - publish: reports
    artifact: cxscan-reports
    condition: always()"""


GENERATORS = {"jenkins": jenkins, "azure": azure}
