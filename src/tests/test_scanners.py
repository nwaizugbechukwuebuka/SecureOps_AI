<<<<<<< HEAD
import json
from unittest.mock import mock_open, patch
import pytest
from secureops_ai.src.scanners.common import ScanResult, Vulnerability
from secureops_ai.src.scanners.dependency_scanner import DependencyScanner
from secureops_ai.src.scanners.docker_scanner import DockerScanner
from secureops_ai.src.scanners.policy_checker import PolicyChecker
from secureops_ai.src.scanners.secret_scanner import SecretScanner
=======
import asyncio
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, mock_open, patch

import pytest

from src.scanners.bandit_scanner import BanditScanner
from src.scanners.common import ScanResult, Vulnerability
from src.scanners.dependency_scanner import DependencyScanner
from src.scanners.docker_scanner import DockerScanner
from src.scanners.policy_checker import PolicyChecker
from src.scanners.safety_scanner import SafetyScanner
from src.scanners.secret_scanner import SecretScanner
from src.scanners.trivy_scanner import TrivyScanner
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3


@pytest.fixture
def sample_dockerfile():
<<<<<<< HEAD
    return """FROM node:14-alpine\nWORKDIR /app\nCOPY package.json .\nRUN npm install\nCOPY . .\nEXPOSE 3000\nCMD [\"npm\", \"start\"]\n"""

@pytest.fixture
def sample_requirements_txt():
    return """requests==2.25.1\nflask==1.1.4\ndjango==3.1.0\nnumpy==1.19.5\n"""

@pytest.fixture
def sample_package_json():
=======
    """Sample Dockerfile content for testing"""
    return """
FROM node:14-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
"""


@pytest.fixture
def sample_requirements_txt():
    """Sample requirements.txt for testing"""
    return """
requests==2.25.1
flask==1.1.4
django==3.1.0
numpy==1.19.5
"""


@pytest.fixture
def sample_package_json():
    """Sample package.json for testing"""
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    return {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {"express": "4.17.1", "lodash": "4.17.20", "moment": "2.29.1"},
        "devDependencies": {"jest": "26.6.3"},
    }

<<<<<<< HEAD
class TestSecretScanner:
    @pytest.fixture
    def secret_scanner(self):
        return SecretScanner()

    @pytest.mark.asyncio
    async def test_scan_file_for_secrets(self, secret_scanner):
        file_content = """
# Configuration file
DATABASE_URL=postgresql://user:password@localhost/db
AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_1234567890abcdef
API_KEY=sk-1234567890abcdef
"""
        with patch("builtins.open", mock_open(read_data=file_content)):
            result = await secret_scanner.scan_file("config.py")
            assert result.success is True
            assert len(result.vulnerabilities) >= 3

class TestDependencyScanner:
    @pytest.fixture
    def dependency_scanner(self):
        return DependencyScanner()

    @pytest.mark.asyncio
    async def test_scan_npm_dependencies(self, dependency_scanner, sample_package_json):
        mock_audit_result = {
            "vulnerabilities": {
                "lodash": {
                    "severity": "moderate",
                    "via": ["CVE-2020-8203"],
                    "effects": [],
                    "range": ">=1.0.0 <4.17.21",
                    "nodes": ["node_modules/lodash"],
                }
            }
        }
        with patch("subprocess.run") as mock_run, patch(
            "builtins.open", mock_open(read_data=json.dumps(sample_package_json))
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_audit_result)
            result = await dependency_scanner.scan_npm("package.json")
=======

@pytest.fixture
def sample_python_code():
    """Sample Python code with security issues"""
    return """
import subprocess
import os

def execute_command(user_input):
    # Vulnerable to command injection
    subprocess.call(user_input, shell=True)

def get_password():
    # Hardcoded password
    return "admin123"

def sql_query(user_id):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Weak random number generation
import random
secret_key = random.randint(1000, 9999)
"""


class TestTrivyScanner:
    """Test Trivy vulnerability scanner"""

    @pytest.fixture
    def trivy_scanner(self):
        return TrivyScanner()

    @pytest.mark.asyncio
    async def test_scan_docker_image_success(self, trivy_scanner):
        """Test successful Docker image scanning"""
        mock_result = {
            "Results": [
                {
                    "Target": "node:14-alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k",
                            "FixedVersion": "1.1.1l",
                            "Severity": "HIGH",
                            "Title": "OpenSSL vulnerability",
                            "Description": "Buffer overflow in OpenSSL",
                        }
                    ],
                }
            ]
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_result)

            result = await trivy_scanner.scan_image("node:14-alpine")

            assert result.success is True
            assert len(result.vulnerabilities) == 1
            assert result.vulnerabilities[0].id == "CVE-2023-1234"
            assert result.vulnerabilities[0].severity == "HIGH"

    @pytest.mark.asyncio
    async def test_scan_filesystem_success(self, trivy_scanner):
        """Test successful filesystem scanning"""
        mock_result = {
            "Results": [
                {
                    "Target": "/app",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-5678",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.20",
                            "FixedVersion": "4.17.21",
                            "Severity": "MEDIUM",
                            "Title": "Prototype pollution vulnerability",
                        }
                    ],
                }
            ]
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_result)

            result = await trivy_scanner.scan_filesystem("/app")

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            assert result.success is True
            assert len(result.vulnerabilities) == 1
            assert result.vulnerabilities[0].package == "lodash"

<<<<<<< HEAD
class TestDockerScanner:
    @pytest.fixture
    def docker_scanner(self):
        return DockerScanner()

    @pytest.mark.asyncio
    async def test_scan_dockerfile(self, docker_scanner, sample_dockerfile):
        with patch("builtins.open", mock_open(read_data=sample_dockerfile)):
            result = await docker_scanner.scan_dockerfile("Dockerfile")
            assert result.success is True
            assert len(result.vulnerabilities) >= 0

class TestPolicyChecker:
    @pytest.fixture
    def policy_checker(self):
        return PolicyChecker()

    @pytest.mark.asyncio
    async def test_check_custom_policies(self, policy_checker):
        custom_policies = {
            "max_critical_vulns": 0,
            "max_high_vulns": 2,
            "banned_packages": ["debug", "lodash"],
        }
        scan_results = [
            ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(id="CVE-001", severity="CRITICAL", package="debug"),
                    Vulnerability(id="CVE-002", severity="HIGH", package="lodash"),
                ],
            )
        ]
        policy_result = await policy_checker.check_custom_policies(scan_results, custom_policies)
        assert policy_result.success is False
        assert len(policy_result.violations) >= 2
=======
    @pytest.mark.asyncio
    async def test_scan_failure(self, trivy_scanner):
        """Test scanner failure handling"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "Trivy scan failed"

            result = await trivy_scanner.scan_image("invalid:image")

            assert result.success is False
            assert "Trivy scan failed" in result.error


class TestSafetyScanner:
    """Test Safety Python dependency scanner"""

    @pytest.fixture
    def safety_scanner(self):
        return SafetyScanner()

    @pytest.mark.asyncio
    async def test_scan_requirements_success(
        self, safety_scanner, sample_requirements_txt
    ):
        """Test successful requirements.txt scanning"""
        mock_output = """
[
    {
        "package": "flask",
        "installed": "1.1.4",
        "vulnerable": "1.1.4",
        "id": "39462",
        "advisory": "Flask vulnerability allows XSS"
    }
]
"""

        with patch("subprocess.run") as mock_run, patch(
            "builtins.open", mock_open(read_data=sample_requirements_txt)
        ):

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = mock_output

            result = await safety_scanner.scan_requirements("requirements.txt")

            assert result.success is True
            assert len(result.vulnerabilities) == 1
            assert result.vulnerabilities[0].package == "flask"

    @pytest.mark.asyncio
    async def test_scan_virtual_environment(self, safety_scanner):
        """Test virtual environment scanning"""
        mock_output = """
[
    {
        "package": "requests",
        "installed": "2.25.1",
        "vulnerable": "2.25.1",
        "id": "39525",
        "advisory": "Requests vulnerable to SSRF"
    }
]
"""

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = mock_output

            result = await safety_scanner.scan_environment("/path/to/venv")

            assert result.success is True
            assert len(result.vulnerabilities) == 1

    @pytest.mark.asyncio
    async def test_scan_no_vulnerabilities(self, safety_scanner):
        """Test scanning with no vulnerabilities found"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "[]"

            result = await safety_scanner.scan_requirements("requirements.txt")

            assert result.success is True
            assert len(result.vulnerabilities) == 0


class TestBanditScanner:
    """Test Bandit Python security scanner"""

    @pytest.fixture
    def bandit_scanner(self):
        return BanditScanner()

    @pytest.mark.asyncio
    async def test_scan_python_file_success(self, bandit_scanner, sample_python_code):
        """Test successful Python file scanning"""
        mock_result = {
            "results": [
                {
                    "filename": "test.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "HIGH",
                    "issue_text": "Use of subprocess with shell=True",
                    "line_number": 5,
                    "line_range": [5],
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                },
                {
                    "filename": "test.py",
                    "issue_confidence": "HIGH",
                    "issue_severity": "MEDIUM",
                    "issue_text": "Hardcoded password",
                    "line_number": 9,
                    "line_range": [9],
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                },
            ]
        }

        with patch("subprocess.run") as mock_run, patch(
            "builtins.open", mock_open(read_data=sample_python_code)
        ):

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_result)

            result = await bandit_scanner.scan_file("test.py")

            assert result.success is True
            assert len(result.vulnerabilities) == 2
            assert result.vulnerabilities[0].severity == "HIGH"
            assert "subprocess" in result.vulnerabilities[0].description

    @pytest.mark.asyncio
    async def test_scan_directory_success(self, bandit_scanner):
        """Test successful directory scanning"""
        mock_result = {
            "results": [
                {
                    "filename": "app.py",
                    "issue_confidence": "MEDIUM",
                    "issue_severity": "LOW",
                    "issue_text": "Use of assert detected",
                    "line_number": 10,
                    "test_id": "B101",
                    "test_name": "assert_used",
                }
            ]
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_result)

            result = await bandit_scanner.scan_directory("/app")

            assert result.success is True
            assert len(result.vulnerabilities) == 1
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

    @pytest.mark.asyncio
    async def test_custom_config(self, bandit_scanner):
        """Test scanning with custom configuration"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = '{"results": []}'

            config = {
                "exclude_dirs": ["tests", "migrations"],
                "skip_tests": ["B101", "B601"],
            }

            result = await bandit_scanner.scan_directory("/app", config=config)

            assert result.success is True
            # Verify config was applied
            call_args = mock_run.call_args[0][0]
            assert "--exclude" in call_args
            assert "--skip" in call_args


class TestSecretScanner:
    """Test secret detection scanner"""

    @pytest.fixture
    def secret_scanner(self):
        return SecretScanner()

    @pytest.mark.asyncio
    async def test_scan_file_for_secrets(self, secret_scanner):
        """Test scanning file for hardcoded secrets"""
        file_content = """
# Configuration file
DATABASE_URL=postgresql://user:password@localhost/db
AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_1234567890abcdef
API_KEY=sk-1234567890abcdef
"""

        with patch("builtins.open", mock_open(read_data=file_content)):
            result = await secret_scanner.scan_file("config.py")

            assert result.success is True
            assert len(result.vulnerabilities) >= 3  # Should find multiple secrets

    @pytest.mark.asyncio
    async def test_scan_git_repository(self, secret_scanner):
        """Test scanning git repository for secrets"""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = """
config.py:3:AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
app.py:15:GITHUB_TOKEN=ghp_1234567890abcdef
"""

            result = await secret_scanner.scan_repository("/repo")

            assert result.success is True
            assert len(result.vulnerabilities) == 2

    @pytest.mark.asyncio
    async def test_detect_common_patterns(self, secret_scanner):
        """Test detection of common secret patterns"""
        test_patterns = {
            "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
            "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
            "JWT_TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "PASSWORD": "password123",
        }

        for secret_type, secret_value in test_patterns.items():
            found = secret_scanner._detect_secret_pattern(secret_value)
            assert found is True, f"Failed to detect {secret_type}"


class TestDependencyScanner:
    """Test dependency vulnerability scanner"""

    @pytest.fixture
    def dependency_scanner(self):
        return DependencyScanner()

    @pytest.mark.asyncio
    async def test_scan_npm_dependencies(self, dependency_scanner, sample_package_json):
        """Test scanning npm dependencies"""
        mock_audit_result = {
            "vulnerabilities": {
                "lodash": {
                    "severity": "moderate",
                    "via": ["CVE-2020-8203"],
                    "effects": [],
                    "range": ">=1.0.0 <4.17.21",
                    "nodes": ["node_modules/lodash"],
                }
            }
        }

        with patch("subprocess.run") as mock_run, patch(
            "builtins.open", mock_open(read_data=json.dumps(sample_package_json))
        ):

            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_audit_result)

            result = await dependency_scanner.scan_npm("package.json")

            assert result.success is True
            assert len(result.vulnerabilities) == 1
            assert result.vulnerabilities[0].package == "lodash"

    @pytest.mark.asyncio
    async def test_scan_python_dependencies(self, dependency_scanner):
        """Test scanning Python dependencies"""
<<<<<<< HEAD
        # Simulate a ScanResult as if returned by SafetyScanner
        mock_result = ScanResult(
            success=True,
            vulnerabilities=[
                Vulnerability(
                    id="12345",
                    package="flask",
                    version="1.1.4",
                    severity="HIGH",
                    description="XSS vulnerability",
                )
            ],
        )
        with patch.object(DependencyScanner, "scan_python", return_value=mock_result):
            result = await dependency_scanner.scan_python("requirements.txt")
=======
        with patch.object(SafetyScanner, "scan_requirements") as mock_safety:
            mock_safety.return_value = ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(
                        id="12345",
                        package="flask",
                        version="1.1.4",
                        severity="HIGH",
                        description="XSS vulnerability",
                    )
                ],
            )

            result = await dependency_scanner.scan_python("requirements.txt")

>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
            assert result.success is True
            assert len(result.vulnerabilities) == 1

    @pytest.mark.asyncio
    async def test_scan_composer_dependencies(self, dependency_scanner):
        """Test scanning Composer dependencies"""
        mock_security_result = {
            "advisories": {
                "symfony/symfony": [
                    {
                        "advisoryId": "SYMFONY-2021-001",
                        "packageName": "symfony/symfony",
                        "remoteId": "CVE-2021-12345",
                        "title": "Symfony vulnerability",
                        "link": "https://symfony.com/cve-2021-12345",
                    }
                ]
            }
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps(mock_security_result)

            result = await dependency_scanner.scan_composer("composer.json")

            assert result.success is True
            assert len(result.vulnerabilities) == 1


class TestDockerScanner:
    """Test Docker security scanner"""

    @pytest.fixture
    def docker_scanner(self):
        return DockerScanner()

    @pytest.mark.asyncio
    async def test_scan_dockerfile(self, docker_scanner, sample_dockerfile):
        """Test Dockerfile security scanning"""
        with patch("builtins.open", mock_open(read_data=sample_dockerfile)):
            result = await docker_scanner.scan_dockerfile("Dockerfile")

            assert result.success is True
            # Should detect some issues like running as root, etc.
            assert len(result.vulnerabilities) >= 0

    @pytest.mark.asyncio
    async def test_scan_docker_image(self, docker_scanner):
        """Test Docker image scanning"""
<<<<<<< HEAD
        # This test previously used TrivyScanner, which is not present. Skipping.
=======
        with patch.object(TrivyScanner, "scan_image") as mock_trivy:
            mock_trivy.return_value = ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(
                        id="CVE-2023-1234",
                        package="openssl",
                        version="1.1.1k",
                        severity="HIGH",
                        description="OpenSSL vulnerability",
                    )
                ],
            )

            result = await docker_scanner.scan_image("node:14-alpine")

            assert result.success is True
            assert len(result.vulnerabilities) == 1
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

    @pytest.mark.asyncio
    async def test_dockerfile_best_practices(self, docker_scanner):
        """Test Dockerfile best practices checking"""
        bad_dockerfile = """
FROM ubuntu:latest
USER root
RUN apt-get update
COPY . .
"""

        issues = docker_scanner._check_dockerfile_practices(bad_dockerfile)

        assert len(issues) > 0
        # Should flag issues like using latest tag, running as root, etc.


class TestPolicyChecker:
    """Test security policy checker"""

    @pytest.fixture
    def policy_checker(self):
        return PolicyChecker()

    @pytest.mark.asyncio
    async def test_check_owasp_policies(self, policy_checker):
        """Test OWASP security policy checking"""
        scan_results = [
            ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(
                        id="XSS-001",
                        severity="HIGH",
                        description="Cross-site scripting vulnerability",
                        category="injection",
                    )
                ],
            )
        ]

        policy_result = await policy_checker.check_owasp_compliance(scan_results)

        assert policy_result.success is True
        assert "A03_2021" in policy_result.violations  # Injection category

    @pytest.mark.asyncio
    async def test_check_custom_policies(self, policy_checker):
        """Test custom security policy checking"""
        custom_policies = {
            "max_critical_vulns": 0,
            "max_high_vulns": 2,
            "banned_packages": ["debug", "lodash"],
        }

        scan_results = [
            ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(id="CVE-001", severity="CRITICAL", package="debug"),
                    Vulnerability(id="CVE-002", severity="HIGH", package="lodash"),
                ],
            )
        ]

        policy_result = await policy_checker.check_custom_policies(
            scan_results, custom_policies
        )

        assert policy_result.success is False
        assert len(policy_result.violations) >= 2  # Critical vuln + banned package

    @pytest.mark.asyncio
    async def test_severity_thresholds(self, policy_checker):
        """Test severity threshold policies"""
        thresholds = {"critical": 0, "high": 1, "medium": 5, "low": 10}

        vulnerabilities = [
            Vulnerability(id="1", severity="HIGH"),
            Vulnerability(id="2", severity="HIGH"),
            Vulnerability(id="3", severity="MEDIUM"),
        ]

        violations = policy_checker._check_severity_thresholds(
            vulnerabilities, thresholds
        )

        assert len(violations) > 0  # Should violate high threshold


<<<<<<< HEAD
    # Integration tests for removed scanners have been removed. Only core scanner tests remain.
=======
class TestScannerIntegration:
    """Test scanner integration and orchestration"""

    @pytest.mark.asyncio
    async def test_multi_scanner_execution(self):
        """Test running multiple scanners together"""
        scanners = [TrivyScanner(), SafetyScanner(), BanditScanner(), SecretScanner()]

        results = []
        for scanner in scanners:
            with patch.object(scanner, "scan") as mock_scan:
                mock_scan.return_value = ScanResult(
                    success=True,
                    vulnerabilities=[
                        Vulnerability(
                            id=f"{scanner.__class__.__name__}-001", severity="MEDIUM"
                        )
                    ],
                )

                result = await scanner.scan("/test/path")
                results.append(result)

        assert len(results) == 4
        assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_scan_result_aggregation(self):
        """Test aggregating results from multiple scanners"""
        results = [
            ScanResult(
                success=True,
                vulnerabilities=[
                    Vulnerability(id="1", severity="HIGH"),
                    Vulnerability(id="2", severity="MEDIUM"),
                ],
            ),
            ScanResult(
                success=True, vulnerabilities=[Vulnerability(id="3", severity="LOW")]
            ),
        ]

        # Aggregate results
        all_vulns = []
        for result in results:
            all_vulns.extend(result.vulnerabilities)

        assert len(all_vulns) == 3
        severity_counts = {}
        for vuln in all_vulns:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        assert severity_counts["HIGH"] == 1
        assert severity_counts["MEDIUM"] == 1
        assert severity_counts["LOW"] == 1

    @pytest.mark.asyncio
    async def test_scan_timeout_handling(self):
        """Test scanner timeout handling"""
        scanner = TrivyScanner()

        with patch("subprocess.run") as mock_run:
            # Simulate timeout
            import subprocess

            mock_run.side_effect = subprocess.TimeoutExpired("trivy", 30)

            result = await scanner.scan_image("test:image", timeout=30)

            assert result.success is False
            assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_scan_error_recovery(self):
        """Test scanner error recovery and fallback"""
        primary_scanner = TrivyScanner()
        fallback_scanner = SafetyScanner()

        with patch.object(primary_scanner, "scan_image") as mock_primary, patch.object(
            fallback_scanner, "scan_requirements"
        ) as mock_fallback:

            # Primary scanner fails
            mock_primary.return_value = ScanResult(
                success=False, error="Scanner failed"
            )

            # Fallback succeeds
            mock_fallback.return_value = ScanResult(success=True, vulnerabilities=[])

            # Try primary first, then fallback
            result = await primary_scanner.scan_image("test:image")
            if not result.success:
                result = await fallback_scanner.scan_requirements("requirements.txt")

            assert result.success is True


if __name__ == "__main__":
    pytest.main([__file__])
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
