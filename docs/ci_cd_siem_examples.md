# SecureOps: CI/CD Snippets for SIEM Log Forwarding

## GitHub Actions Example
```yaml
# .github/workflows/secureops-siem.yml
name: SecureOps SIEM Log Forwarding
on:
  push:
    branches: [ main ]
jobs:
  setup-siem:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install cmreslogging datadog
      - name: Configure SIEM environment variables
        run: |
          echo "LOG_FORWARD_ELK_ENABLED=true" >> $GITHUB_ENV
          echo "LOG_FORWARD_ELK_HOST=elk.example.com" >> $GITHUB_ENV
          echo "LOG_FORWARD_ELK_PORT=9200" >> $GITHUB_ENV
          echo "LOG_FORWARD_DATADOG_ENABLED=true" >> $GITHUB_ENV
          echo "LOG_FORWARD_DATADOG_API_KEY=${{ secrets.DATADOG_API_KEY }}" >> $GITHUB_ENV
          echo "LOG_FORWARD_SYSLOG_ENABLED=true" >> $GITHUB_ENV
          echo "LOG_FORWARD_SYSLOG_HOST=syslog.example.com" >> $GITHUB_ENV
          echo "LOG_FORWARD_SYSLOG_PORT=514" >> $GITHUB_ENV
      - name: Run tests
        run: pytest
```

## GitLab CI Example
```yaml
# .gitlab-ci.yml
stages:
  - test

setup_siem:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pip install cmreslogging datadog
    - export LOG_FORWARD_ELK_ENABLED=true
    - export LOG_FORWARD_ELK_HOST=elk.example.com
    - export LOG_FORWARD_ELK_PORT=9200
    - export LOG_FORWARD_DATADOG_ENABLED=true
    - export LOG_FORWARD_DATADOG_API_KEY=$DATADOG_API_KEY
    - export LOG_FORWARD_SYSLOG_ENABLED=true
    - export LOG_FORWARD_SYSLOG_HOST=syslog.example.com
    - export LOG_FORWARD_SYSLOG_PORT=514
    - pytest
  variables:
    DATADOG_API_KEY: $DATADOG_API_KEY
```

## Azure DevOps Example
```yaml
# azure-pipelines.yml
trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - checkout: self
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  - script: |
      pip install -r requirements.txt
      pip install cmreslogging datadog
    displayName: 'Install dependencies'
  - script: |
      echo "##vso[task.setvariable variable=LOG_FORWARD_ELK_ENABLED]true"
      echo "##vso[task.setvariable variable=LOG_FORWARD_ELK_HOST]elk.example.com"
      echo "##vso[task.setvariable variable=LOG_FORWARD_ELK_PORT]9200"
      echo "##vso[task.setvariable variable=LOG_FORWARD_DATADOG_ENABLED]true"
      echo "##vso[task.setvariable variable=LOG_FORWARD_DATADOG_API_KEY]$(DATADOG_API_KEY)"
      echo "##vso[task.setvariable variable=LOG_FORWARD_SYSLOG_ENABLED]true"
      echo "##vso[task.setvariable variable=LOG_FORWARD_SYSLOG_HOST]syslog.example.com"
      echo "##vso[task.setvariable variable=LOG_FORWARD_SYSLOG_PORT]514"
    displayName: 'Set SIEM environment variables'
  - script: pytest
    displayName: 'Run tests'
```

---
- Replace example hostnames and API keys with your actual values or secrets.
- For other CI/CD systems, follow the same pattern: install dependencies and set environment variables before running your app or tests.
