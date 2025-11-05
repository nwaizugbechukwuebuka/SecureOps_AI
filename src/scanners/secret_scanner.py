"""
Secret Detection Scanner

This module provides comprehensive secret detection using multiple methods
including regex patterns, entropy analysis, and machine learning approaches.
Detects API keys, passwords, tokens, certificates, and other sensitive data.

Author: Chukwuebuka Tobiloba Nwaizugbe
Date: 2024
"""

import base64
import hashlib
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from ..utils.config import settings
from ..utils.logger import get_logger
from .common import (
    BaseScanner,
    FileTypeDetector,
    ScannerType,
    ScanResult,
    ScanSummary,
    SeverityLevel,
    orchestrator,
)

logger = get_logger(__name__)


class SecretScanner(BaseScanner):
    """Advanced secret detection scanner with multiple detection methods."""

    def __init__(self):
        super().__init__("secret-scanner", "1.0.0", ScannerType.SECRET)
        self.min_entropy = 3.5
        self.min_length = 8
        self.max_line_length = 1000  # Skip very long lines (likely binary)

        # Initialize patterns
        self.patterns = self._initialize_patterns()
        self.whitelist_patterns = self._initialize_whitelist_patterns()

    def is_available(self) -> bool:
        """Secret scanner is always available (no external dependencies)."""
        return True

    def _initialize_patterns(self) -> Dict[str, List[Pattern]]:
        """Initialize regex patterns for different secret types."""
        patterns = {
            "api_keys": [
                re.compile(
                    r'(?i)api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'
                ),
                re.compile(r'(?i)apikey\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
                re.compile(r'(?i)x-api-key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
            ],
            "aws_credentials": [
                re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
                re.compile(
                    r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?'
                ),
                re.compile(
                    r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9+/]{40})["\']?'
                ),
                re.compile(
                    r'(?i)aws[_-]?session[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{100,})["\']?'
                ),
            ],
            "google_api": [
                re.compile(r"AIza[0-9A-Za-z_\-]{35}"),  # Google API Key
                re.compile(
                    r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\']?(AIza[0-9A-Za-z_\-]{35})["\']?'
                ),
            ],
            "github_tokens": [
                re.compile(r"ghp_[a-zA-Z0-9]{36}"),  # GitHub Personal Access Token
                re.compile(r"gho_[a-zA-Z0-9]{36}"),  # GitHub OAuth Token
                re.compile(r"ghu_[a-zA-Z0-9]{36}"),  # GitHub User Token
                re.compile(r"ghs_[a-zA-Z0-9]{36}"),  # GitHub Server Token
                re.compile(r"ghr_[a-zA-Z0-9]{76}"),  # GitHub Refresh Token
            ],
            "gitlab_tokens": [
                re.compile(r"glpat-[a-zA-Z0-9_\-]{20}"),  # GitLab Personal Access Token
                re.compile(
                    r'(?i)gitlab[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'
                ),
            ],
            "slack_tokens": [
                re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"),  # Slack tokens
                re.compile(
                    r'(?i)slack[_-]?token\s*[:=]\s*["\']?(xox[baprs]-[0-9a-zA-Z]{10,48})["\']?'
                ),
            ],
            "discord_tokens": [
                re.compile(
                    r"[MN][a-zA-Z\d]{23}\.[\w-]{6}\.[\w-]{27}"
                ),  # Discord Bot Token
                re.compile(
                    r'(?i)discord[_-]?token\s*[:=]\s*["\']?([MN][a-zA-Z\d]{23}\.[\w-]{6}\.[\w-]{27})["\']?'
                ),
            ],
            "jwt_tokens": [
                re.compile(
                    r"eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*"
                ),  # JWT Token
            ],
            "database_urls": [
                re.compile(
                    r"(?i)(mysql|postgresql|mongodb|redis)://[^:\s]+:[^@\s]+@[^:\s]+:\d+"
                ),
                re.compile(
                    r'(?i)database[_-]?url\s*[:=]\s*["\']?([a-z]+://[^:\s]+:[^@\s]+@[^:\s/]+[^\s"\']*)["\']?'
                ),
            ],
            "connection_strings": [
                re.compile(
                    r"(?i)server\s*=\s*[^;]+;\s*database\s*=\s*[^;]+;\s*uid\s*=\s*[^;]+;\s*pwd\s*=\s*[^;]+"
                ),
                re.compile(
                    r"(?i)data\s+source\s*=\s*[^;]+;\s*initial\s+catalog\s*=\s*[^;]+;\s*user\s+id\s*=\s*[^;]+;\s*password\s*=\s*[^;]+"
                ),
            ],
            "passwords": [
                re.compile(r'(?i)password\s*[:=]\s*["\']([^"\'\\s]{8,})["\']'),
                re.compile(r'(?i)pwd\s*[:=]\s*["\']([^"\'\\s]{8,})["\']'),
                re.compile(r'(?i)passwd\s*[:=]\s*["\']([^"\'\\s]{8,})["\']'),
            ],
            "private_keys": [
                re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
                re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
                re.compile(r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----"),
                re.compile(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"),
                re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"),
            ],
            "certificates": [
                re.compile(r"-----BEGIN\s+CERTIFICATE-----"),
                re.compile(r"-----BEGIN\s+PUBLIC\s+KEY-----"),
            ],
            "stripe_keys": [
                re.compile(r"sk_live_[0-9a-zA-Z]{24}"),  # Stripe Secret Key
                re.compile(r"pk_live_[0-9a-zA-Z]{24}"),  # Stripe Publishable Key
            ],
            "paypal_keys": [
                re.compile(
                    r'(?i)paypal.*client[_-]?id\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{80})["\']?'
                ),
                re.compile(
                    r'(?i)paypal.*client[_-]?secret\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{80})["\']?'
                ),
            ],
            "mailgun_keys": [
                re.compile(r"key-[0-9a-zA-Z]{32}"),  # Mailgun API Key
            ],
            "twilio_keys": [
                re.compile(r"AC[0-9a-f]{32}"),  # Twilio Account SID
                re.compile(r"SK[0-9a-f]{32}"),  # Twilio API Key SID
            ],
            "sendgrid_keys": [
                re.compile(
                    r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"
                ),  # SendGrid API Key
            ],
            "square_keys": [
                re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),  # Square Access Token
                re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"),  # Square Application Secret
            ],
            "facebook_tokens": [
                re.compile(
                    r'(?i)facebook.*access[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?'
                ),
            ],
            "twitter_tokens": [
                re.compile(
                    r'(?i)twitter.*api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9]{25})["\']?'
                ),
                re.compile(
                    r'(?i)twitter.*api[_-]?secret\s*[:=]\s*["\']?([a-zA-Z0-9]{50})["\']?'
                ),
            ],
            "heroku_keys": [
                re.compile(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                ),  # Heroku API Key
            ],
            "shopify_tokens": [
                re.compile(r"shpat_[a-fA-F0-9]{32}"),  # Shopify Private App Token
                re.compile(r"shpca_[a-fA-F0-9]{32}"),  # Shopify Custom App Token
            ],
            "generic_secrets": [
                re.compile(
                    r'(?i)(secret|token|key|password|pwd|pass)\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{20,})["\']?'
                ),
            ],
        }

        return patterns

    def _initialize_whitelist_patterns(self) -> List[Pattern]:
        """Initialize patterns for common false positives to ignore."""
        return [
            re.compile(r"(?i)(example|sample|test|demo|placeholder|dummy|fake|mock)"),
            re.compile(r"(?i)(your_?api_?key|your_?token|your_?secret|your_?password)"),
            re.compile(r"(?i)(insert_?key_?here|replace_?with|change_?me|todo)"),
            re.compile(r"(?i)(<|>|\$\{|\{\{|%\(|%s|%d|\.\.\.)"),  # Template variables
            re.compile(r"^[0-9a-f]{40}$"),  # Git commit hashes
            re.compile(r"^[0-9]+$"),  # Purely numeric strings
            re.compile(
                r"^(true|false|null|undefined)$", re.IGNORECASE
            ),  # Boolean/null values
            re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0)"),  # Local addresses
        ]

    async def scan(self, target: str, **kwargs) -> Tuple[ScanSummary, List[ScanResult]]:
        """Scan target for exposed secrets."""
        started_at = datetime.now(timezone.utc)
        results = []

        try:
            # Configuration options
            check_entropy = kwargs.get("check_entropy", True)
            max_file_size = kwargs.get("max_file_size", 1024 * 1024)  # 1MB default

            # Get files to scan
            files_to_scan = self._get_scannable_files(target, max_file_size)

            self.logger.info(f"Scanning {len(files_to_scan)} files for secrets")

            # Scan each file
            for file_path in files_to_scan:
                try:
                    file_results = await self._scan_file(file_path, check_entropy)
                    results.extend(file_results)
                except Exception as e:
                    self.logger.warning(f"Failed to scan file {file_path}: {e}")

            # Remove duplicates and filter results
            results = self._deduplicate_and_filter(results)

            summary = self._create_summary(target, started_at, success=True)

            # Update summary with results
            for result in results:
                summary.add_result(result)

            self.logger.info(f"Secret scan completed: {len(results)} findings")
            return summary, results

        except Exception as e:
            error_msg = f"Secret scan failed: {e}"
            self.logger.error(error_msg)
            summary = self._create_summary(
                target, started_at, success=False, error_message=error_msg
            )
            return summary, []

    def _get_scannable_files(self, target: str, max_file_size: int) -> List[str]:
        """Get list of files that should be scanned for secrets."""
        if os.path.isfile(target):
            if os.path.getsize(target) <= max_file_size:
                return [target]
            return []

        scannable_files = []

        for file_path in FileTypeDetector.get_scannable_files(target):
            try:
                # Check file size
                if os.path.getsize(file_path) > max_file_size:
                    continue

                # Check if file is likely text (not binary)
                if self._is_text_file(file_path):
                    scannable_files.append(file_path)

            except (OSError, IOError):
                continue

        return scannable_files

    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file."""
        try:
            # Read first 1024 bytes to check for binary content
            with open(file_path, "rb") as f:
                chunk = f.read(1024)

            # Check for null bytes (common in binary files)
            if b"\x00" in chunk:
                return False

            # Try to decode as text
            try:
                chunk.decode("utf-8")
                return True
            except UnicodeDecodeError:
                try:
                    chunk.decode("latin-1")
                    return True
                except UnicodeDecodeError:
                    return False

        except Exception:
            return False

    async def _scan_file(
        self, file_path: str, check_entropy: bool = True
    ) -> List[ScanResult]:
        """Scan individual file for secrets."""
        results = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    # Skip very long lines (likely binary or minified)
                    if len(line) > self.max_line_length:
                        continue

                    line = line.strip()
                    if not line or line.startswith(
                        "#"
                    ):  # Skip empty lines and comments
                        continue

                    # Pattern-based detection
                    pattern_results = self._scan_line_with_patterns(
                        line, file_path, line_num
                    )
                    results.extend(pattern_results)

                    # Entropy-based detection
                    if check_entropy:
                        entropy_results = self._scan_line_with_entropy(
                            line, file_path, line_num
                        )
                        results.extend(entropy_results)

        except Exception as e:
            self.logger.warning(f"Failed to read file {file_path}: {e}")

        return results

    def _scan_line_with_patterns(
        self, line: str, file_path: str, line_num: int
    ) -> List[ScanResult]:
        """Scan line using regex patterns."""
        results = []

        for secret_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(line)

                for match in matches:
                    secret_value = match.group(1) if match.groups() else match.group(0)

                    # Skip if matches whitelist patterns
                    if self._is_whitelisted(secret_value, line):
                        continue

                    # Create scan result
                    result = ScanResult(
                        scanner_type=ScannerType.SECRET,
                        rule_id=f"secret-{secret_type}",
                        title=f"Exposed {secret_type.replace('_', ' ').title()}",
                        description=f"Potential {secret_type.replace('_', ' ')} found in {file_path}",
                        severity=self._get_severity_for_secret_type(secret_type),
                        confidence=self._calculate_pattern_confidence(
                            secret_type, secret_value
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._mask_secret_in_line(line, secret_value),
                        remediation=self._get_remediation_for_secret_type(secret_type),
                        metadata={
                            "secret_type": secret_type,
                            "secret_hash": hashlib.sha256(
                                secret_value.encode()
                            ).hexdigest()[:16],
                            "detection_method": "pattern",
                            "pattern_matched": pattern.pattern[:100],
                        },
                    )

                    results.append(result)

        return results

    def _scan_line_with_entropy(
        self, line: str, file_path: str, line_num: int
    ) -> List[ScanResult]:
        """Scan line using entropy analysis for high-entropy strings."""
        results = []

        # Extract potential secrets using word boundaries and common delimiters
        potential_secrets = self._extract_high_entropy_strings(line)

        for secret_candidate in potential_secrets:
            if len(secret_candidate) < self.min_length:
                continue

            # Skip if matches whitelist patterns
            if self._is_whitelisted(secret_candidate, line):
                continue

            # Calculate entropy
            entropy = self._calculate_entropy(secret_candidate)

            if entropy >= self.min_entropy:
                # Additional checks to reduce false positives
                if self._is_likely_secret(secret_candidate):

                    confidence = min(0.9, entropy / 6.0)  # Scale entropy to confidence
                    severity = (
                        SeverityLevel.MEDIUM if entropy > 4.5 else SeverityLevel.LOW
                    )

                    result = ScanResult(
                        scanner_type=ScannerType.SECRET,
                        rule_id="secret-high-entropy",
                        title="High Entropy String (Potential Secret)",
                        description=f"High entropy string detected in {file_path} (entropy: {entropy:.2f})",
                        severity=severity,
                        confidence=confidence,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._mask_secret_in_line(line, secret_candidate),
                        remediation="Review this high-entropy string and remove if it contains sensitive data",
                        metadata={
                            "secret_type": "high_entropy",
                            "entropy_score": entropy,
                            "detection_method": "entropy",
                            "string_length": len(secret_candidate),
                            "secret_hash": hashlib.sha256(
                                secret_candidate.encode()
                            ).hexdigest()[:16],
                        },
                    )

                    results.append(result)

        return results

    def _extract_high_entropy_strings(self, line: str) -> List[str]:
        """Extract potential high-entropy strings from line."""
        candidates = []

        # Split on common delimiters and whitespace
        delimiters = r'[\s=:;"\'`,\[\]{}()<>|&]'
        parts = re.split(delimiters, line)

        for part in parts:
            part = part.strip()
            if len(part) >= self.min_length:
                candidates.append(part)

        # Also look for quoted strings
        quoted_patterns = [r'"([^"]{8,})"', r"'([^']{8,})'", r"`([^`]{8,})`"]

        for pattern in quoted_patterns:
            matches = re.findall(pattern, line)
            candidates.extend(matches)

        return candidates

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_length = len(text)

        for count in frequencies.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_likely_secret(self, candidate: str) -> bool:
        """Additional checks to determine if high-entropy string is likely a secret."""
        # Skip common non-secret high-entropy strings
        if candidate.isdigit():  # Pure numbers
            return False

        if len(set(candidate)) < 4:  # Too few unique characters
            return False

        # Check for base64-like patterns
        base64_pattern = re.match(r"^[A-Za-z0-9+/=]+$", candidate)
        if base64_pattern and len(candidate) % 4 == 0:
            return True

        # Check for hex patterns
        hex_pattern = re.match(r"^[a-fA-F0-9]+$", candidate)
        if hex_pattern and len(candidate) >= 16:
            return True

        # Check for mixed case alphanumeric (common in tokens)
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_digit = any(c.isdigit() for c in candidate)

        if has_upper and has_lower and has_digit:
            return True

        return False

    def _is_whitelisted(self, secret_value: str, full_line: str) -> bool:
        """Check if secret value should be whitelisted (ignored)."""
        for pattern in self.whitelist_patterns:
            if pattern.search(secret_value) or pattern.search(full_line):
                return True

        return False

    def _get_severity_for_secret_type(self, secret_type: str) -> SeverityLevel:
        """Get appropriate severity level for secret type."""
        high_severity_types = {
            "private_keys",
            "aws_credentials",
            "database_urls",
            "connection_strings",
            "passwords",
        }

        medium_severity_types = {
            "api_keys",
            "github_tokens",
            "gitlab_tokens",
            "jwt_tokens",
            "slack_tokens",
            "stripe_keys",
            "paypal_keys",
        }

        if secret_type in high_severity_types:
            return SeverityLevel.HIGH
        elif secret_type in medium_severity_types:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _calculate_pattern_confidence(
        self, secret_type: str, secret_value: str
    ) -> float:
        """Calculate confidence level for pattern-based detection."""
        base_confidence = 0.8

        # Higher confidence for specific patterns with strong indicators
        high_confidence_types = {
            "aws_credentials",
            "github_tokens",
            "gitlab_tokens",
            "google_api",
            "private_keys",
            "certificates",
        }

        if secret_type in high_confidence_types:
            base_confidence = 0.9

        # Adjust based on secret characteristics
        if len(secret_value) > 32:  # Longer secrets generally more confident
            base_confidence += 0.05

        if re.search(r"[A-Z]", secret_value) and re.search(r"[a-z]", secret_value):
            base_confidence += 0.02  # Mixed case

        if re.search(r"[0-9]", secret_value):
            base_confidence += 0.02  # Contains numbers

        return min(0.95, base_confidence)

    def _get_remediation_for_secret_type(self, secret_type: str) -> str:
        """Get appropriate remediation advice for secret type."""
        remediation_map = {
            "private_keys": "Remove private keys from code. Use secure key management services.",
            "aws_credentials": "Remove AWS credentials. Use IAM roles or AWS credential files.",
            "api_keys": "Remove API keys from code. Use environment variables or secret management.",
            "passwords": "Remove hardcoded passwords. Use secure authentication methods.",
            "database_urls": "Remove database connection strings. Use environment variables.",
            "connection_strings": "Remove connection strings. Use configuration files or environment variables.",
            "jwt_tokens": "Remove JWT tokens from code. Generate tokens dynamically.",
            "github_tokens": "Revoke and regenerate GitHub tokens. Use secure storage.",
            "gitlab_tokens": "Revoke and regenerate GitLab tokens. Use secure storage.",
            "certificates": "Remove certificates from code. Use proper certificate management.",
        }

        return remediation_map.get(
            secret_type,
            "Remove sensitive data from code and use secure secret management practices.",
        )

    def _mask_secret_in_line(self, line: str, secret: str) -> str:
        """Mask secret in code snippet while preserving context."""
        if len(secret) <= 8:
            masked = "*" * len(secret)
        else:
            # Show first 2 and last 2 characters, mask the rest
            masked = secret[:2] + "*" * (len(secret) - 4) + secret[-2:]

        return line.replace(secret, masked)

    def _deduplicate_and_filter(self, results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicates and apply additional filtering."""
        seen_secrets = set()
        filtered_results = []

        for result in results:
            # Create a unique key for deduplication
            secret_hash = result.metadata.get("secret_hash", "")
            key = (result.file_path, result.line_number, secret_hash)

            if key not in seen_secrets:
                seen_secrets.add(key)

                # Apply additional filters
                if self._should_include_result(result):
                    filtered_results.append(result)

        return filtered_results

    def _should_include_result(self, result: ScanResult) -> bool:
        """Apply final filtering to determine if result should be included."""
        # Skip very low confidence results
        if result.confidence < 0.3:
            return False

        # Skip results in test files for certain types (reduce noise)
        if "test" in result.file_path.lower():
            test_skip_types = {"high_entropy", "generic_secrets"}
            secret_type = result.metadata.get("secret_type", "")
            if secret_type in test_skip_types and result.confidence < 0.7:
                return False

        return True


# Register scanner with orchestrator
def register_secret_scanner():
    """Register secret scanner with the orchestrator."""
    secret_scanner = SecretScanner()
    orchestrator.register_scanner(secret_scanner)

    logger.info("Registered secret scanner")


# Auto-register scanner when module is imported
register_secret_scanner()
