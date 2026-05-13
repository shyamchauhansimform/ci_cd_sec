# CI/CD Security for Pipelines

A comprehensive security-focused project for securing continuous integration and continuous deployment (CI/CD) pipelines.

## Overview

This project focuses on implementing and maintaining robust security practices in CI/CD workflows. It includes vulnerability scanning, code quality analysis, and security automation for pipeline workflows.

## Project Structure

- **main.py** — Core Python application
- **package.json** — Node.js dependencies and scripts
- **sonar-project.properties** — SonarQube configuration for code quality analysis
- **.github/workflows/** — GitHub Actions automation workflows
  - `cve-lite-cli.yml` — CVE scanning and vulnerability detection workflow

## Features

- **CVE Scanning** — Automated vulnerability detection in dependencies
- **Secret Scanning** — Automated detection of hardcoded secrets in the repository contents
- **Code Quality Analysis** — SonarQube integration for code quality metrics
- **GitHub Actions Automation** — Automated security checks in CI/CD pipelines
- **Pipeline Security** — Best practices for securing deployment workflows

## Getting Started

### Prerequisites

- Python 3.x
- Node.js and npm
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/shyamchauhansimform/ci_cd_sec.git
cd ci_cd_sec

# Python setup
# No requirements.txt is currently provided in this repository.
# Install Node.js dependencies
npm install
```

### Configuration

Update `sonar-project.properties` with your SonarQube instance details:

```properties
sonar.projectKey=your-project-key
sonar.projectName=your-project-name
sonar.sources=.
```

## Security Scanning

### CVE Scanning

GitHub Actions workflow automatically scans for CVEs in dependencies. See `.github/workflows/cve-lite-cli.yml` for configuration.

### Secret Scanning

GitHub Actions also runs a Gitleaks-based secret scan to catch hardcoded credentials before they are merged.
Keep AWS keys, tokens, and similar credentials in GitHub Actions secrets or other secure secret managers instead of committing them to the repository.
If a real credential is ever exposed, rotate it outside the repository and remove it from active use immediately.

### Code Quality

Run SonarQube analysis:

```bash
sonar-scanner
```

## Workflow Automation

GitHub Actions workflows run automatically on:
- Push to main branch
- Pull requests

## Contributing

1. Create a feature branch
2. Make your changes
3. Ensure security scans pass
4. Submit a pull request

## License

This project is licensed under the MIT License.

## Contact

For questions or security concerns, please contact the project maintainers.
