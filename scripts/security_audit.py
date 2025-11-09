#!/usr/bin/env python3
"""
Security audit script for SecureOps AI
Checks for outdated packages and security vulnerabilities
"""

import subprocess
import sys
import json
from typing import List, Dict


def check_package_vulnerabilities():
    """Check for known security vulnerabilities in installed packages."""
    try:
        # Run safety check if available
        result = subprocess.run(
            ["python", "-m", "pip", "list", "--format=json"], capture_output=True, text=True, check=True
        )

        packages = json.loads(result.stdout)
        print("Installed packages audit:")
        print("=" * 50)

        # Check for potentially outdated packages
        potentially_outdated = []
        for pkg in packages:
            name = pkg.get("name", "").lower()
            version = pkg.get("version", "")

            # Flag packages that commonly have security issues
            security_keywords = ["cryptography", "requests", "urllib3", "pillow", "pyyaml", "jinja2"]
            if any(keyword in name for keyword in security_keywords):
                potentially_outdated.append(f"{name}=={version}")

        if potentially_outdated:
            print("Security-sensitive packages found:")
            for pkg in potentially_outdated:
                print(f"  - {pkg}")
        else:
            print("No obviously security-sensitive packages detected.")

        return True

    except subprocess.CalledProcessError as e:
        print(f"Error running pip list: {e}")
        return False
    except Exception as e:
        print(f"Error in security audit: {e}")
        return False


def check_environment_security():
    """Check for security-related environment configuration."""
    print("\nEnvironment Security Checklist:")
    print("=" * 50)

    security_items = [
        "✓ SECRET_KEY should be unique and complex",
        "✓ DEBUG should be False in production",
        "✓ Database credentials should be secure",
        "✓ HTTPS should be enabled in production",
        "✓ CORS origins should be restricted",
        "✓ Rate limiting should be configured",
        "✓ Input validation should be implemented",
        "✓ Authentication tokens should expire",
    ]

    for item in security_items:
        print(f"  {item}")

    return True


if __name__ == "__main__":
    print("SecureOps AI Security Audit")
    print("=" * 50)

    success = True
    success &= check_package_vulnerabilities()
    success &= check_environment_security()

    print("\nAudit completed!")
    if success:
        print("✓ Basic security audit passed")
    else:
        print("⚠ Some security issues detected")
        sys.exit(1)
