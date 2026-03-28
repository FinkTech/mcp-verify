# 🔄 CI/CD Integration Example

## Why Integrate MCP Verify into CI/CD?

- **Catch Issues Early:** Find security vulnerabilities before production
- **Enforce Standards:** Ensure all MCP servers meet quality bar
- **Prevent Regressions:** Detect performance degradations
- **Automate Security:** No manual security reviews needed

## GitHub Actions

### Basic Setup

Create `.github/workflows/mcp-verify.yml`:

```yaml
name: MCP Verification

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  verify:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install Dependencies
        run: npm install

      - name: Start MCP Server
        run: |
          npm start &
          sleep 5  # Wait for server to start

      - name: Install MCP Verify
        run: npm install -g mcp-verify

      - name: Run Validation
        run: mcp-verify validate http://localhost:3000

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: mcp-report
          path: ./reportes/
```

### With SARIF Output (GitHub Code Scanning)

```yaml
      - name: Run Security Scan
        run: |
          mcp-verify validate http://localhost:3000 --format sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ./reportes/mcp-report-*.sarif
```

This will show security findings directly in GitHub's Security tab!

### Fail on Security Issues

```yaml
      - name: Validate Server
        run: |
          mcp-verify validate http://localhost:3000 --html

          # Parse security score from JSON report
          SCORE=$(jq '.security.score' ./reportes/mcp-report-*.json | tail -1)

          if [ $SCORE -lt 70 ]; then
            echo "❌ Security score too low: $SCORE/100 (minimum: 70)"
            exit 1
          fi

          echo "✅ Security score: $SCORE/100"
```

### Performance Regression Check

```yaml
      - name: Performance Test
        run: |
          mcp-verify stress http://localhost:3000 --users 10 --duration 30 > perf.txt

          P95=$(grep "P95:" perf.txt | awk '{print $3}')

          if [ $P95 -gt 100 ]; then
            echo "❌ Performance regression: P95 latency $P95ms (max: 100ms)"
            exit 1
          fi
```

## GitLab CI

### `.gitlab-ci.yml`

```yaml
stages:
  - test
  - security

mcp-validation:
  stage: test
  image: node:18
  script:
    - npm install
    - npm start &
    - sleep 5
    - npm install -g mcp-verify
    - mcp-verify validate http://localhost:3000
  artifacts:
    paths:
      - reportes/
    expire_in: 1 week

security-scan:
  stage: security
  image: node:18
  script:
    - npm install
    - npm start &
    - sleep 5
    - npm install -g mcp-verify
    - mcp-verify validate http://localhost:3000 --format sarif
  artifacts:
    reports:
      sast: reportes/mcp-report-*.sarif
```

## Docker Integration

### Dockerfile for Testing

```dockerfile
FROM node:18

WORKDIR /app

# Install mcp-verify
RUN npm install -g mcp-verify

# Copy server code
COPY package*.json ./
RUN npm install
COPY . .

# Health check using mcp-verify
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD mcp-verify validate http://localhost:3000 || exit 1

EXPOSE 3000

CMD ["npm", "start"]
```

### Docker Compose for Testing

```yaml
version: '3.8'

services:
  mcp-server:
    build: .
    ports:
      - "3000:3000"
    healthcheck:
      test: ["CMD", "mcp-verify", "validate", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3

  mcp-validator:
    image: node:18
    depends_on:
      mcp-server:
        condition: service_healthy
    volumes:
      - ./reports:/reports
    command: >
      sh -c "
        npm install -g mcp-verify &&
        mcp-verify validate http://mcp-server:3000 --output /reports
      "
```

Run with:
```bash
docker-compose up --abort-on-container-exit
```

## Pre-commit Hook

### Setup

```bash
# Install husky
npm install --save-dev husky

# Create pre-commit hook
npx husky install
npx husky add .husky/pre-commit "npm run mcp-verify"
```

### `package.json`

```json
{
  "scripts": {
    "mcp-verify": "node scripts/verify-server.js"
  }
}
```

### `scripts/verify-server.js`

```javascript
const { spawn } = require('child_process');

console.log('🔍 Validating MCP server before commit...\n');

// Start server
const server = spawn('npm', ['start'], {
  detached: true,
  stdio: 'ignore'
});

setTimeout(() => {
  // Run validation
  const verify = spawn('mcp-verify', ['validate', 'http://localhost:3000']);

  verify.stdout.on('data', (data) => console.log(data.toString()));
  verify.stderr.on('data', (data) => console.error(data.toString()));

  verify.on('close', (code) => {
    server.kill();
    process.exit(code);
  });
}, 3000);
```

## Jenkins Pipeline

### `Jenkinsfile`

```groovy
pipeline {
    agent any

    stages {
        stage('Setup') {
            steps {
                sh 'npm install'
                sh 'npm install -g mcp-verify'
            }
        }

        stage('Start Server') {
            steps {
                sh 'npm start &'
                sh 'sleep 5'
            }
        }

        stage('Validate') {
            steps {
                sh 'mcp-verify validate http://localhost:3000 --html'
            }
        }

        stage('Security Check') {
            steps {
                script {
                    def score = sh(
                        script: "jq '.security.score' ./reportes/mcp-report-*.json | tail -1",
                        returnStdout: true
                    ).trim().toInteger()

                    if (score < 70) {
                        error("Security score too low: ${score}/100")
                    }

                    echo "✅ Security score: ${score}/100"
                }
            }
        }

        stage('Performance Test') {
            steps {
                sh 'mcp-verify stress http://localhost:3000 --users 10 --duration 30'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reportes/**/*', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reportes',
                reportFiles: 'mcp-report-*.html',
                reportName: 'MCP Verification Report'
            ])
        }
    }
}
```

## CircleCI

### `.circleci/config.yml`

```yaml
version: 2.1

jobs:
  verify:
    docker:
      - image: node:18
    steps:
      - checkout
      - run:
          name: Install Dependencies
          command: |
            npm install
            npm install -g mcp-verify
      - run:
          name: Start Server
          command: npm start
          background: true
      - run:
          name: Wait for Server
          command: sleep 5
      - run:
          name: Validate MCP Server
          command: mcp-verify validate http://localhost:3000 --html
      - store_artifacts:
          path: ./reportes
      - store_test_results:
          path: ./reportes

workflows:
  version: 2
  build-and-test:
    jobs:
      - verify
```

## Kubernetes Deployment Check

### Pre-deployment Validation

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: mcp-verify-precheck
spec:
  template:
    spec:
      containers:
      - name: validator
        image: node:18
        command:
          - sh
          - -c
          - |
            npm install -g mcp-verify
            mcp-verify validate http://mcp-server:3000
            if [ $? -ne 0 ]; then
              echo "❌ Validation failed - blocking deployment"
              exit 1
            fi
      restartPolicy: Never
  backoffLimit: 3
```

## Monitoring Integration

### Prometheus Metrics

Export validation results as metrics:

```bash
# Custom script to export metrics
mcp-verify validate http://localhost:3000 --format json > report.json

# Parse and export
cat report.json | jq -r '
  "mcp_security_score " + (.security.score | tostring),
  "mcp_tools_count " + (.tools.count | tostring),
  "mcp_validation_duration_ms " + (.duration_ms | tostring)
' > /metrics/mcp.prom
```

### Grafana Dashboard

Use the metrics to create dashboards showing:
- Security score trends
- Validation success rate
- Performance metrics over time

## Slack Notifications

### Notify on Failures

```bash
#!/bin/bash
mcp-verify validate http://localhost:3000 || {
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"❌ MCP Verification failed! Check the logs."}' \
    $SLACK_WEBHOOK_URL
  exit 1
}
```

## Best Practices

### 1. **Run on Every PR**
Don't wait for main branch - catch issues early

### 2. **Cache Results**
```yaml
- uses: actions/cache@v3
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
```

### 3. **Parallel Testing**
```yaml
strategy:
  matrix:
    node: [16, 18, 20]
```

### 4. **Set Thresholds**
```bash
# Fail if:
- Security score < 70
- P95 latency > 100ms
- Success rate < 99%
```

### 5. **Generate Badges**
```markdown
![MCP Verified](https://img.shields.io/badge/MCP-verified-green)
![Security Score](https://img.shields.io/badge/security-85%2F100-yellow)
```

## Common Issues

### ❌ "Server not ready"
**Solution:** Increase wait time or use health check

```bash
# Wait for server to be ready
until curl -f http://localhost:3000; do
  echo "Waiting for server..."
  sleep 1
done
```

### ❌ "Port already in use"
**Solution:** Kill existing process

```bash
# Kill process on port 3000
lsof -ti:3000 | xargs kill -9 || true
npm start &
```

### ❌ "Report not found"
**Solution:** Check output path

```bash
ls -la ./reportes/
mcp-verify validate http://localhost:3000 --output ./ci-reports
```

## Next Steps

1. Choose your CI platform
2. Copy relevant example above
3. Customize thresholds
4. Add to your repo
5. Test with a PR

## Resources

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [GitLab CI Docs](https://docs.gitlab.com/ee/ci/)
- [Example Workflows](https://github.com/FinkTech/mcp-verify/tree/main/examples/ci)
