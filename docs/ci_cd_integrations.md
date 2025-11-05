# CI/CD Integrations Guide

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions Integration](#github-actions-integration)
3. [GitLab CI Integration](#gitlab-ci-integration)
4. [Jenkins Integration](#jenkins-integration)
5. [Azure DevOps Integration](#azure-devops-integration)
6. [Webhook Configuration](#webhook-configuration)
7. [Security Scanner Integration](#security-scanner-integration)
8. [Custom Integration Development](#custom-integration-development)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

## Overview

SecureOps provides comprehensive integration with major CI/CD platforms to enable automated security monitoring and compliance checking throughout your development pipeline. This document provides detailed setup instructions and configuration examples for each supported platform.

### Supported Platforms

- **GitHub Actions**: Native integration with GitHub repositories
- **GitLab CI**: GitLab.com and self-hosted GitLab instances
- **Jenkins**: Pipeline integration via plugins and REST APIs
- **Azure DevOps**: Azure Pipelines and Azure Repos integration

### Integration Features

- **Webhook Monitoring**: Real-time pipeline event processing
- **Security Scanning**: Automated vulnerability detection
- **Compliance Checking**: Policy enforcement and reporting
- **Status Reporting**: Build status updates and notifications
- **Artifact Analysis**: Scan build artifacts and container images

## GitHub Actions Integration

### Prerequisites

- GitHub repository with Actions enabled
- SecureOps API token with pipeline management permissions
- GitHub personal access token (for API access)

### Step 1: Create GitHub App (Recommended)

For organization-wide integration, create a GitHub App:

1. Navigate to **Settings** → **Developer settings** → **GitHub Apps**
2. Click **New GitHub App**
3. Fill in the application details:

```yaml
GitHub App Configuration:
  Name: SecureOps Security Monitor
  Homepage URL: https://your-secureops-instance.com
  Webhook URL: https://your-secureops-instance.com/api/v1/webhooks/github
  Webhook Secret: [Generate a secure random string]
  
Permissions:
  Repository permissions:
    - Actions: Read
    - Checks: Write
    - Contents: Read
    - Issues: Write
    - Metadata: Read
    - Pull requests: Write
    - Security events: Read
  
  Subscribe to events:
    - Check run
    - Check suite
    - Push
    - Pull request
    - Release
    - Workflow run
```

### Step 2: Install GitHub App

1. After creating the app, note the **App ID** and generate a **private key**
2. Install the app on your organization or specific repositories
3. Configure SecureOps with the GitHub App credentials

### Step 3: Configure SecureOps Pipeline

```bash
# Add GitHub pipeline via API
curl -X POST https://your-secureops-instance.com/api/v1/pipelines \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My GitHub Pipeline",
    "platform": "github",
    "repository_url": "https://github.com/myorg/myrepo",
    "branch": "main",
    "webhook_secret": "your_webhook_secret",
    "config": {
      "auto_scan": true,
      "scanners": ["trivy", "safety", "bandit"],
      "compliance_frameworks": ["owasp_top_10"],
      "notifications": {
        "slack_webhook": "https://hooks.slack.com/...",
        "email_recipients": ["security@myorg.com"]
      }
    }
  }'
```

### Step 4: GitHub Actions Workflow

Create `.github/workflows/secureops.yml`:

```yaml
name: SecureOps Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Notify SecureOps - Start
      run: |
        curl -X POST ${{ vars.SECUREOPS_API_URL }}/api/v1/pipelines/${{ vars.PIPELINE_ID }}/notify \
          -H "Authorization: Bearer ${{ secrets.SECUREOPS_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{
            "event": "pipeline_started",
            "commit_sha": "${{ github.sha }}",
            "branch": "${{ github.ref_name }}",
            "trigger": "${{ github.event_name }}"
          }'
    
    - name: Run Trivy Container Scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myorg/myapp:latest'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy Results to SecureOps
      run: |
        curl -X POST ${{ vars.SECUREOPS_API_URL }}/api/v1/scan-results \
          -H "Authorization: Bearer ${{ secrets.SECUREOPS_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{
            "pipeline_id": ${{ vars.PIPELINE_ID }},
            "scanner": "trivy",
            "format": "sarif",
            "results": "'"$(cat trivy-results.sarif | jq -R -s .)"'"
          }'
    
    - name: Python Security Scan
      run: |
        pip install safety bandit
        safety check --json --output safety-results.json || true
        bandit -r . -f json -o bandit-results.json || true
    
    - name: Upload Python Scan Results
      run: |
        # Upload Safety results
        curl -X POST ${{ vars.SECUREOPS_API_URL }}/api/v1/scan-results \
          -H "Authorization: Bearer ${{ secrets.SECUREOPS_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{
            "pipeline_id": ${{ vars.PIPELINE_ID }},
            "scanner": "safety",
            "format": "json",
            "results": "'"$(cat safety-results.json | jq -R -s .)"'"
          }'
        
        # Upload Bandit results
        curl -X POST ${{ vars.SECUREOPS_API_URL }}/api/v1/scan-results \
          -H "Authorization: Bearer ${{ secrets.SECUREOPS_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{
            "pipeline_id": ${{ vars.PIPELINE_ID }},
            "scanner": "bandit",
            "format": "json",
            "results": "'"$(cat bandit-results.json | jq -R -s .)"'"
          }'
    
    - name: Notify SecureOps - Complete
      if: always()
      run: |
        curl -X POST ${{ vars.SECUREOPS_API_URL }}/api/v1/pipelines/${{ vars.PIPELINE_ID }}/notify \
          -H "Authorization: Bearer ${{ secrets.SECUREOPS_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d '{
            "event": "pipeline_completed",
            "status": "${{ job.status }}",
            "commit_sha": "${{ github.sha }}",
            "duration": ${{ github.event.workflow_run.run_attempt }}
          }'
```

### GitHub Actions with SecureOps Action

For easier integration, use the official SecureOps GitHub Action:

```yaml
- name: SecureOps Security Scan
  uses: secureops/github-action@v1
  with:
    api-url: ${{ vars.SECUREOPS_API_URL }}
    api-token: ${{ secrets.SECUREOPS_TOKEN }}
    pipeline-id: ${{ vars.PIPELINE_ID }}
    scanners: 'trivy,safety,bandit'
    upload-artifacts: 'true'
    fail-on-high: 'true'
```

### Secrets Configuration

Configure the following secrets in your GitHub repository:

```bash
# Required secrets
SECUREOPS_TOKEN: "your_api_token"

# Optional secrets
SECUREOPS_WEBHOOK_SECRET: "your_webhook_secret"
SLACK_WEBHOOK: "https://hooks.slack.com/..."
```

## GitLab CI Integration

### Prerequisites

- GitLab project with CI/CD enabled
- GitLab API token with appropriate permissions
- SecureOps API token

### Step 1: Configure GitLab Webhook

1. Navigate to **Settings** → **Webhooks** in your GitLab project
2. Add webhook configuration:

```yaml
URL: https://your-secureops-instance.com/api/v1/webhooks/gitlab
Secret Token: your_webhook_secret

Trigger Events:
  - Push events
  - Merge request events
  - Pipeline events
  - Job events
  - Deployment events

SSL Verification: Enabled
```

### Step 2: GitLab CI Configuration

Create `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - security
  - deploy

variables:
  SECUREOPS_API_URL: "https://your-secureops-instance.com"
  PIPELINE_ID: "your_pipeline_id"

before_script:
  - apt-get update -qy
  - apt-get install -y curl jq

# Security scanning job
security_scan:
  stage: security
  image: docker:20.10.16
  services:
    - docker:20.10.16-dind
  
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  
  before_script:
    - docker info
    - apk add --no-cache curl jq python3 py3-pip
  
  script:
    # Notify scan start
    - |
      curl -X POST ${SECUREOPS_API_URL}/api/v1/pipelines/${PIPELINE_ID}/notify \
        -H "Authorization: Bearer ${SECUREOPS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
          \"event\": \"pipeline_started\",
          \"commit_sha\": \"${CI_COMMIT_SHA}\",
          \"branch\": \"${CI_COMMIT_REF_NAME}\",
          \"trigger\": \"${CI_PIPELINE_SOURCE}\"
        }"
    
    # Build and scan container
    - docker build -t ${CI_PROJECT_NAME}:${CI_COMMIT_SHA} .
    
    # Trivy container scan
    - |
      docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v $(pwd):/tmp/trivy aquasec/trivy:latest \
        image --format json --output /tmp/trivy/trivy-results.json \
        ${CI_PROJECT_NAME}:${CI_COMMIT_SHA}
    
    # Upload Trivy results
    - |
      curl -X POST ${SECUREOPS_API_URL}/api/v1/scan-results \
        -H "Authorization: Bearer ${SECUREOPS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
          \"pipeline_id\": ${PIPELINE_ID},
          \"scanner\": \"trivy\",
          \"format\": \"json\",
          \"results\": \"$(cat trivy-results.json | jq -R -s .)\"
        }"
    
    # Python dependency scan
    - pip3 install safety bandit
    - safety check --json --output safety-results.json || true
    - bandit -r . -f json -o bandit-results.json || true
    
    # Upload Python scan results
    - |
      curl -X POST ${SECUREOPS_API_URL}/api/v1/scan-results \
        -H "Authorization: Bearer ${SECUREOPS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
          \"pipeline_id\": ${PIPELINE_ID},
          \"scanner\": \"safety\",
          \"format\": \"json\",
          \"results\": \"$(cat safety-results.json | jq -R -s .)\"
        }"
    
    # Notify scan completion
    - |
      curl -X POST ${SECUREOPS_API_URL}/api/v1/pipelines/${PIPELINE_ID}/notify \
        -H "Authorization: Bearer ${SECUREOPS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
          \"event\": \"pipeline_completed\",
          \"status\": \"success\",
          \"commit_sha\": \"${CI_COMMIT_SHA}\"
        }"
  
  artifacts:
    reports:
      container_scanning: trivy-results.json
    paths:
      - trivy-results.json
      - safety-results.json
      - bandit-results.json
    expire_in: 1 week
  
  only:
    - main
    - merge_requests
    - schedules

# Include security template for GitLab security scanning
include:
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/SAST.gitlab-ci.yml
```

### GitLab Variables Configuration

Configure the following variables in **Settings** → **CI/CD** → **Variables**:

```bash
SECUREOPS_TOKEN: your_api_token (Masked, Protected)
SECUREOPS_WEBHOOK_SECRET: your_webhook_secret (Masked, Protected)
PIPELINE_ID: your_pipeline_id
```

## Jenkins Integration

### Prerequisites

- Jenkins instance with required plugins
- Jenkins API token
- SecureOps API token

### Required Jenkins Plugins

Install the following plugins:

```bash
# Core plugins
Pipeline
Credentials Binding
HTTP Request
Generic Webhook Trigger

# Security plugins
OWASP Dependency Track
Warnings Next Generation
JUnit
```

### Step 1: Configure Jenkins Credentials

1. Navigate to **Manage Jenkins** → **Manage Credentials**
2. Add the following credentials:

```yaml
Credentials:
  - ID: secureops-api-token
    Type: Secret text
    Secret: your_secureops_api_token
  
  - ID: secureops-webhook-secret
    Type: Secret text
    Secret: your_webhook_secret
```

### Step 2: Jenkins Pipeline Configuration

Create a `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        SECUREOPS_API_URL = 'https://your-secureops-instance.com'
        PIPELINE_ID = '123'
        DOCKER_IMAGE = "${env.JOB_NAME}:${env.BUILD_NUMBER}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Notify Start') {
            steps {
                script {
                    def payload = [
                        event: 'pipeline_started',
                        commit_sha: env.GIT_COMMIT,
                        branch: env.BRANCH_NAME,
                        trigger: 'jenkins',
                        build_number: env.BUILD_NUMBER
                    ]
                    
                    httpRequest(
                        httpMode: 'POST',
                        url: "${env.SECUREOPS_API_URL}/api/v1/pipelines/${env.PIPELINE_ID}/notify",
                        requestBody: groovy.json.JsonOutput.toJson(payload),
                        contentType: 'APPLICATION_JSON',
                        customHeaders: [
                            [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                        ]
                    )
                }
            }
        }
        
        stage('Build') {
            steps {
                script {
                    docker.build(env.DOCKER_IMAGE)
                }
            }
        }
        
        stage('Security Scan') {
            parallel {
                stage('Container Scan') {
                    steps {
                        script {
                            // Run Trivy scan
                            sh """
                                docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\
                                    -v \$(pwd):/tmp/results aquasec/trivy:latest \\
                                    image --format json --output /tmp/results/trivy-results.json \\
                                    ${env.DOCKER_IMAGE}
                            """
                            
                            // Upload results to SecureOps
                            def trivyResults = readFile('trivy-results.json')
                            def payload = [
                                pipeline_id: env.PIPELINE_ID,
                                scanner: 'trivy',
                                format: 'json',
                                results: trivyResults
                            ]
                            
                            httpRequest(
                                httpMode: 'POST',
                                url: "${env.SECUREOPS_API_URL}/api/v1/scan-results",
                                requestBody: groovy.json.JsonOutput.toJson(payload),
                                contentType: 'APPLICATION_JSON',
                                customHeaders: [
                                    [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                                ]
                            )
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'trivy-results.json', allowEmptyArchive: true
                        }
                    }
                }
                
                stage('Dependency Scan') {
                    when {
                        expression { fileExists('requirements.txt') || fileExists('package.json') }
                    }
                    steps {
                        script {
                            if (fileExists('requirements.txt')) {
                                // Python dependency scan
                                sh '''
                                    pip install safety bandit
                                    safety check --json --output safety-results.json || true
                                    bandit -r . -f json -o bandit-results.json || true
                                '''
                                
                                // Upload Safety results
                                if (fileExists('safety-results.json')) {
                                    def safetyResults = readFile('safety-results.json')
                                    def payload = [
                                        pipeline_id: env.PIPELINE_ID,
                                        scanner: 'safety',
                                        format: 'json',
                                        results: safetyResults
                                    ]
                                    
                                    httpRequest(
                                        httpMode: 'POST',
                                        url: "${env.SECUREOPS_API_URL}/api/v1/scan-results",
                                        requestBody: groovy.json.JsonOutput.toJson(payload),
                                        contentType: 'APPLICATION_JSON',
                                        customHeaders: [
                                            [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                                        ]
                                    )
                                }
                            }
                            
                            if (fileExists('package.json')) {
                                // Node.js dependency scan
                                sh '''
                                    npm audit --json > npm-audit-results.json || true
                                '''
                                
                                if (fileExists('npm-audit-results.json')) {
                                    def auditResults = readFile('npm-audit-results.json')
                                    def payload = [
                                        pipeline_id: env.PIPELINE_ID,
                                        scanner: 'npm_audit',
                                        format: 'json',
                                        results: auditResults
                                    ]
                                    
                                    httpRequest(
                                        httpMode: 'POST',
                                        url: "${env.SECUREOPS_API_URL}/api/v1/scan-results",
                                        requestBody: groovy.json.JsonOutput.toJson(payload),
                                        contentType: 'APPLICATION_JSON',
                                        customHeaders: [
                                            [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                                        ]
                                    )
                                }
                            }
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: '*-results.json', allowEmptyArchive: true
                        }
                    }
                }
            }
        }
        
        stage('Compliance Check') {
            steps {
                script {
                    // Trigger compliance assessment
                    def payload = [
                        pipeline_id: env.PIPELINE_ID,
                        framework: 'owasp_top_10',
                        trigger: 'pipeline'
                    ]
                    
                    httpRequest(
                        httpMode: 'POST',
                        url: "${env.SECUREOPS_API_URL}/api/v1/compliance/assess",
                        requestBody: groovy.json.JsonOutput.toJson(payload),
                        contentType: 'APPLICATION_JSON',
                        customHeaders: [
                            [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                        ]
                    )
                }
            }
        }
    }
    
    post {
        always {
            script {
                def status = currentBuild.result ?: 'SUCCESS'
                def payload = [
                    event: 'pipeline_completed',
                    status: status.toLowerCase(),
                    commit_sha: env.GIT_COMMIT,
                    duration: currentBuild.duration,
                    build_number: env.BUILD_NUMBER
                ]
                
                httpRequest(
                    httpMode: 'POST',
                    url: "${env.SECUREOPS_API_URL}/api/v1/pipelines/${env.PIPELINE_ID}/notify",
                    requestBody: groovy.json.JsonOutput.toJson(payload),
                    contentType: 'APPLICATION_JSON',
                    customHeaders: [
                        [name: 'Authorization', value: "Bearer ${env.SECUREOPS_API_TOKEN}"]
                    ]
                )
            }
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
```

### Step 3: Configure Webhook

1. Install **Generic Webhook Trigger** plugin
2. Configure webhook in job settings:

```groovy
// Add to pipeline or configure in job
properties([
    pipelineTriggers([
        GenericTrigger(
            genericVariables: [
                [key: 'ref', value: '$.ref'],
                [key: 'pusher_name', value: '$.pusher.name'],
                [key: 'repository_name', value: '$.repository.name']
            ],
            causeString: 'Triggered by webhook',
            token: 'your_webhook_token',
            printContributedVariables: true,
            printPostContent: true,
            regexpFilterText: '$ref',
            regexpFilterExpression: 'refs/heads/(main|develop)'
        )
    ])
])
```

## Azure DevOps Integration

### Prerequisites

- Azure DevOps organization/project
- Azure DevOps Personal Access Token
- SecureOps API token

### Step 1: Create Service Connection

1. Navigate to **Project Settings** → **Service connections**
2. Create **Generic** service connection:

```yaml
Service Connection:
  Name: SecureOps-API
  Server URL: https://your-secureops-instance.com
  Username: api
  Password: your_secureops_api_token
```

### Step 2: Azure Pipeline Configuration

Create `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
    - main
    - develop
  paths:
    exclude:
    - docs/*
    - README.md

variables:
  SECUREOPS_API_URL: 'https://your-secureops-instance.com'
  PIPELINE_ID: '123'
  DOCKER_IMAGE: '$(Build.Repository.Name):$(Build.BuildId)'

stages:
- stage: SecurityScan
  displayName: 'Security Scanning'
  jobs:
  - job: ContainerScan
    displayName: 'Container Security Scan'
    pool:
      vmImage: 'ubuntu-latest'
    
    steps:
    - checkout: self
    
    - task: PowerShell@2
      displayName: 'Notify Pipeline Start'
      inputs:
        targetType: 'inline'
        script: |
          $headers = @{
            'Authorization' = "Bearer $(SECUREOPS_API_TOKEN)"
            'Content-Type' = 'application/json'
          }
          
          $body = @{
            event = 'pipeline_started'
            commit_sha = "$(Build.SourceVersion)"
            branch = "$(Build.SourceBranchName)"
            trigger = 'azure_devops'
            build_id = "$(Build.BuildId)"
          } | ConvertTo-Json
          
          Invoke-RestMethod -Uri "$(SECUREOPS_API_URL)/api/v1/pipelines/$(PIPELINE_ID)/notify" -Method POST -Headers $headers -Body $body
    
    - task: Docker@2
      displayName: 'Build Docker Image'
      inputs:
        command: 'build'
        Dockerfile: '**/Dockerfile'
        tags: '$(DOCKER_IMAGE)'
    
    - task: CmdLine@2
      displayName: 'Run Trivy Scan'
      inputs:
        script: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v $(System.DefaultWorkingDirectory):/tmp/results \
            aquasec/trivy:latest image \
            --format json --output /tmp/results/trivy-results.json \
            $(DOCKER_IMAGE)
    
    - task: PowerShell@2
      displayName: 'Upload Trivy Results'
      inputs:
        targetType: 'inline'
        script: |
          $trivyResults = Get-Content -Path "$(System.DefaultWorkingDirectory)/trivy-results.json" -Raw
          
          $headers = @{
            'Authorization' = "Bearer $(SECUREOPS_API_TOKEN)"
            'Content-Type' = 'application/json'
          }
          
          $body = @{
            pipeline_id = "$(PIPELINE_ID)"
            scanner = 'trivy'
            format = 'json'
            results = $trivyResults
          } | ConvertTo-Json -Depth 10
          
          Invoke-RestMethod -Uri "$(SECUREOPS_API_URL)/api/v1/scan-results" -Method POST -Headers $headers -Body $body
    
    - task: CmdLine@2
      displayName: 'Python Security Scan'
      condition: eq(variables['Agent.OS'], 'Linux')
      inputs:
        script: |
          pip install safety bandit
          safety check --json --output safety-results.json || true
          bandit -r . -f json -o bandit-results.json || true
    
    - task: PowerShell@2
      displayName: 'Upload Python Scan Results'
      condition: eq(variables['Agent.OS'], 'Linux')
      inputs:
        targetType: 'inline'
        script: |
          # Upload Safety results
          if (Test-Path "safety-results.json") {
            $safetyResults = Get-Content -Path "safety-results.json" -Raw
            
            $headers = @{
              'Authorization' = "Bearer $(SECUREOPS_API_TOKEN)"
              'Content-Type' = 'application/json'
            }
            
            $body = @{
              pipeline_id = "$(PIPELINE_ID)"
              scanner = 'safety'
              format = 'json'
              results = $safetyResults
            } | ConvertTo-Json -Depth 10
            
            Invoke-RestMethod -Uri "$(SECUREOPS_API_URL)/api/v1/scan-results" -Method POST -Headers $headers -Body $body
          }
          
          # Upload Bandit results
          if (Test-Path "bandit-results.json") {
            $banditResults = Get-Content -Path "bandit-results.json" -Raw
            
            $body = @{
              pipeline_id = "$(PIPELINE_ID)"
              scanner = 'bandit'
              format = 'json'
              results = $banditResults
            } | ConvertTo-Json -Depth 10
            
            Invoke-RestMethod -Uri "$(SECUREOPS_API_URL)/api/v1/scan-results" -Method POST -Headers $headers -Body $body
          }
    
    - task: PowerShell@2
      displayName: 'Notify Pipeline Completion'
      condition: always()
      inputs:
        targetType: 'inline'
        script: |
          $status = if ("$(Agent.JobStatus)" -eq "Succeeded") { "success" } else { "failed" }
          
          $headers = @{
            'Authorization' = "Bearer $(SECUREOPS_API_TOKEN)"
            'Content-Type' = 'application/json'
          }
          
          $body = @{
            event = 'pipeline_completed'
            status = $status
            commit_sha = "$(Build.SourceVersion)"
            duration = [int]$((Get-Date) - [datetime]"$(System.JobStartTime)").TotalSeconds
            build_id = "$(Build.BuildId)"
          } | ConvertTo-Json
          
          Invoke-RestMethod -Uri "$(SECUREOPS_API_URL)/api/v1/pipelines/$(PIPELINE_ID)/notify" -Method POST -Headers $headers -Body $body
    
    - task: PublishTestResults@2
      displayName: 'Publish Scan Results'
      condition: always()
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: '**/scan-results.xml'
        failTaskOnFailedTests: false
    
    - task: PublishBuildArtifacts@1
      displayName: 'Publish Artifacts'
      condition: always()
      inputs:
        pathtoPublish: '$(System.DefaultWorkingDirectory)'
        artifactName: 'security-scan-results'
        publishLocation: 'Container'
```

### Step 3: Variable Groups

Create variable groups for sensitive configuration:

1. Navigate to **Pipelines** → **Library** → **Variable groups**
2. Create variable group **SecureOps-Config**:

```yaml
Variables:
  SECUREOPS_API_TOKEN: [your_api_token] (Mark as secret)
  SECUREOPS_WEBHOOK_SECRET: [your_webhook_secret] (Mark as secret)
  PIPELINE_ID: [your_pipeline_id]
```

### Step 4: Service Hooks

Configure Azure DevOps Service Hooks for real-time notifications:

1. Navigate to **Project Settings** → **Service hooks**
2. Create subscription:

```yaml
Service: Web Hooks
Event: Build completed
URL: https://your-secureops-instance.com/api/v1/webhooks/azure-devops
Resource details to send: All
Messages to send: All
Detailed messages to send: All
```

## Webhook Configuration

### Webhook Security

All webhooks should be secured using HMAC signatures or shared secrets:

```python
# Example webhook signature verification
import hashlib
import hmac

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)

# Usage in webhook handler
@app.post("/webhook/{platform}")
async def handle_webhook(platform: str, request: Request):
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")  # GitHub
    # signature = request.headers.get("X-Gitlab-Token")  # GitLab
    
    if not verify_webhook_signature(payload, signature, webhook_secret):
        raise HTTPException(401, "Invalid signature")
    
    # Process webhook
    return {"status": "processed"}
```

### Webhook Event Processing

SecureOps processes various webhook events:

```python
# Event processing logic
async def process_webhook_event(platform: str, event_data: dict):
    event_type = determine_event_type(platform, event_data)
    
    match event_type:
        case "push":
            await handle_push_event(event_data)
        case "pull_request" | "merge_request":
            await handle_pr_event(event_data)
        case "pipeline_start":
            await handle_pipeline_start(event_data)
        case "pipeline_complete":
            await handle_pipeline_complete(event_data)
        case _:
            logger.info(f"Unhandled event type: {event_type}")

async def handle_push_event(event_data: dict):
    # Extract relevant information
    repository = event_data.get("repository", {})
    commits = event_data.get("commits", [])
    
    # Find matching pipeline
    pipeline = await get_pipeline_by_repository(repository["url"])
    
    if pipeline and pipeline.auto_trigger:
        # Trigger security scan
        await trigger_security_scan(pipeline.id, event_data)
```

## Security Scanner Integration

### Scanner Configuration

Configure security scanners for automated execution:

```yaml
# scanner-config.yml
scanners:
  trivy:
    enabled: true
    image: aquasec/trivy:latest
    command: |
      trivy image 
        --format json 
        --output /results/trivy-results.json 
        --severity HIGH,CRITICAL
        {image}
    
    file_command: |
      trivy fs 
        --format json 
        --output /results/trivy-fs-results.json 
        --severity HIGH,CRITICAL
        {path}
  
  safety:
    enabled: true
    requirements: requirements.txt
    command: |
      safety check 
        --json 
        --output /results/safety-results.json
        --file {requirements_file}
  
  bandit:
    enabled: true
    command: |
      bandit -r {path} 
        -f json 
        -o /results/bandit-results.json
        -ll
  
  npm_audit:
    enabled: true
    command: |
      npm audit 
        --json 
        --audit-level moderate 
        > /results/npm-audit-results.json
  
  semgrep:
    enabled: true
    command: |
      semgrep 
        --config=auto 
        --json 
        --output=/results/semgrep-results.json 
        {path}
```

### Custom Scanner Integration

Add custom security scanners:

```python
# custom_scanner.py
from typing import List, Dict, Any
from scanners.base import BaseScanner, ScanResult, Vulnerability

class CustomScanner(BaseScanner):
    name = "custom_scanner"
    version = "1.0.0"
    
    async def scan(self, target: ScanTarget) -> ScanResult:
        # Implement custom scanning logic
        command = self.build_command(target)
        output = await self.execute_command(command)
        
        vulnerabilities = await self.parse_output(output)
        
        return ScanResult(
            scanner=self.name,
            target=target,
            vulnerabilities=vulnerabilities,
            metadata={
                "version": self.version,
                "scan_time": datetime.utcnow(),
                "command": command
            }
        )
    
    def build_command(self, target: ScanTarget) -> List[str]:
        return [
            "custom-security-tool",
            "--target", target.path,
            "--format", "json",
            "--output", "/tmp/results.json"
        ]
    
    async def parse_output(self, output: str) -> List[Vulnerability]:
        results = json.loads(output)
        vulnerabilities = []
        
        for issue in results.get("vulnerabilities", []):
            vulnerability = Vulnerability(
                scanner=self.name,
                vulnerability_id=issue.get("id"),
                title=issue.get("title"),
                description=issue.get("description"),
                severity=self.map_severity(issue.get("severity")),
                cve_id=issue.get("cve"),
                package=issue.get("package"),
                version=issue.get("version"),
                fixed_version=issue.get("fixed_version"),
                file_path=issue.get("file_path"),
                line_number=issue.get("line_number")
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def map_severity(self, scanner_severity: str) -> str:
        severity_mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        return severity_mapping.get(scanner_severity.upper(), "unknown")

# Register custom scanner
from scanners.registry import register_scanner
register_scanner(CustomScanner)
```

## Custom Integration Development

### SDK Usage

Use the SecureOps SDK for custom integrations:

```python
# Python SDK example
from secureops_sdk import SecureOpsClient
from secureops_sdk.models import Pipeline, ScanResult

# Initialize client
client = SecureOpsClient(
    base_url="https://your-secureops-instance.com",
    api_token="your_api_token"
)

# Create pipeline
pipeline = await client.pipelines.create(
    name="Custom Integration Pipeline",
    platform="custom",
    repository_url="https://example.com/repo",
    config={
        "auto_scan": True,
        "scanners": ["trivy", "safety"],
        "compliance_frameworks": ["owasp_top_10"]
    }
)

# Upload scan results
scan_result = ScanResult(
    pipeline_id=pipeline.id,
    scanner="custom_scanner",
    format="json",
    results=scan_output
)

await client.scan_results.create(scan_result)

# Get compliance status
compliance = await client.compliance.get_overview()
print(f"Compliance score: {compliance.overall_score}")
```

### REST API Integration

Direct REST API integration example:

```python
import aiohttp
import asyncio
import json

class SecureOpsIntegration:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    async def create_pipeline(self, pipeline_data: dict) -> dict:
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/api/v1/pipelines"
            async with session.post(url, headers=self.headers, json=pipeline_data) as response:
                return await response.json()
    
    async def upload_scan_results(self, scan_data: dict) -> dict:
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/api/v1/scan-results"
            async with session.post(url, headers=self.headers, json=scan_data) as response:
                return await response.json()
    
    async def get_alerts(self, pipeline_id: int) -> dict:
        async with aiohttp.ClientSession() as session:
            url = f"{self.base_url}/api/v1/alerts?pipeline_id={pipeline_id}"
            async with session.get(url, headers=self.headers) as response:
                return await response.json()

# Usage
async def main():
    integration = SecureOpsIntegration(
        base_url="https://your-secureops-instance.com",
        api_token="your_api_token"
    )
    
    # Create pipeline
    pipeline = await integration.create_pipeline({
        "name": "Custom Pipeline",
        "platform": "custom",
        "repository_url": "https://example.com/repo"
    })
    
    # Upload scan results
    await integration.upload_scan_results({
        "pipeline_id": pipeline["id"],
        "scanner": "custom_scanner",
        "format": "json",
        "results": json.dumps(scan_output)
    })

if __name__ == "__main__":
    asyncio.run(main())
```

## Troubleshooting

### Common Issues

#### Webhook Not Triggering

1. **Check webhook URL**: Ensure the URL is accessible from the CI/CD platform
2. **Verify SSL certificate**: Ensure valid SSL certificate
3. **Check webhook secret**: Verify shared secret configuration
4. **Review firewall rules**: Ensure webhook traffic is allowed

```bash
# Test webhook connectivity
curl -X POST https://your-secureops-instance.com/api/v1/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=test" \
  -d '{"test": "payload"}'
```

#### API Authentication Failures

1. **Verify API token**: Check token validity and permissions
2. **Check token expiration**: Ensure token hasn't expired
3. **Review RBAC permissions**: Verify user has required permissions

```bash
# Test API authentication
curl -X GET https://your-secureops-instance.com/api/v1/pipelines \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

#### Scanner Execution Issues

1. **Check scanner availability**: Verify scanner is installed
2. **Review command syntax**: Ensure scanner commands are correct
3. **Check file permissions**: Verify access to scan targets
4. **Review resource limits**: Ensure sufficient CPU/memory

```bash
# Test scanner locally
docker run --rm aquasec/trivy:latest image --help
safety --version
bandit --version
```

### Debug Mode

Enable debug mode for detailed logging:

```yaml
# Environment variable
SECUREOPS_DEBUG=true
SECUREOPS_LOG_LEVEL=DEBUG

# Or in configuration
logging:
  level: DEBUG
  format: detailed
  output: console
```

### Log Analysis

Common log patterns to investigate:

```bash
# Webhook processing errors
grep "webhook.*error" /var/log/secureops/api.log

# Scanner execution failures
grep "scanner.*failed" /var/log/secureops/worker.log

# Authentication issues
grep "auth.*denied\|unauthorized" /var/log/secureops/api.log

# Database connection problems
grep "database.*connection\|timeout" /var/log/secureops/api.log
```

## Best Practices

### Security

1. **Use HTTPS**: Always use HTTPS for webhook URLs
2. **Verify signatures**: Implement webhook signature verification
3. **Rotate secrets**: Regular rotation of API tokens and webhook secrets
4. **Least privilege**: Grant minimal required permissions
5. **Network security**: Use VPNs or private networks when possible

### Performance

1. **Parallel execution**: Run security scans in parallel when possible
2. **Cache results**: Cache scan results to avoid duplicate work
3. **Incremental scanning**: Scan only changed files when possible
4. **Resource limits**: Set appropriate CPU and memory limits
5. **Async processing**: Use background jobs for heavy operations

### Monitoring

1. **Pipeline health**: Monitor pipeline success rates
2. **Scanner performance**: Track scanner execution times
3. **API metrics**: Monitor API response times and error rates
4. **Alert fatigue**: Implement intelligent alert filtering
5. **Compliance tracking**: Regular compliance assessments

### Configuration Management

1. **Infrastructure as Code**: Manage pipeline configurations in version control
2. **Environment separation**: Separate configurations for dev/staging/prod
3. **Secret management**: Use dedicated secret management systems
4. **Configuration validation**: Validate configurations before deployment
5. **Documentation**: Maintain up-to-date integration documentation

This comprehensive CI/CD integrations guide provides everything needed to integrate SecureOps with major CI/CD platforms and implement automated security monitoring throughout your development pipeline.
