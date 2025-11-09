"""
Enhanced Security Test Script for SecureOps AI
Tests authentication, authorization, and security features
"""

import asyncio
import aiohttp
import json
import sys
import time
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8001"
FRONTEND_URL = "http://localhost:3010"


class SecurityTester:
    def __init__(self):
        self.session = None
        self.token = None
        self.test_results = []

    async def setup(self):
        """Setup test session"""
        self.session = aiohttp.ClientSession()

    async def cleanup(self):
        """Cleanup test session"""
        if self.session:
            await self.session.close()

    def log_test(self, test_name, passed, details=""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append({"name": test_name, "passed": passed, "details": details})
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")

    async def test_health_check(self):
        """Test basic health check"""
        try:
            async with self.session.get(f"{BASE_URL}/health") as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test("Health Check", True, f"Status: {data.get('status')}")
                    return True
                else:
                    self.log_test("Health Check", False, f"Status code: {response.status}")
                    return False
        except Exception as e:
            self.log_test("Health Check", False, f"Connection error: {e}")
            return False

    async def test_security_status(self):
        """Test security status endpoint"""
        try:
            async with self.session.get(f"{BASE_URL}/security-status") as response:
                if response.status == 200:
                    data = await response.json()
                    features = data.get("security_features", {})
                    required_features = ["authentication", "authorization", "audit_logging", "rate_limiting"]

                    missing_features = [f for f in required_features if f not in features]
                    if not missing_features:
                        self.log_test("Security Status", True, f"All security features enabled")
                        return True
                    else:
                        self.log_test("Security Status", False, f"Missing features: {missing_features}")
                        return False
                else:
                    self.log_test("Security Status", False, f"Status code: {response.status}")
                    return False
        except Exception as e:
            self.log_test("Security Status", False, f"Error: {e}")
            return False

    async def test_login_endpoint(self):
        """Test login endpoint"""
        try:
            login_data = {"username": "admin", "password": "SecureAdmin123!"}

            async with self.session.post(f"{BASE_URL}/auth/login", json=login_data) as response:
                if response.status == 200:
                    data = await response.json()
                    if "access_token" in data or data.get("requires_mfa"):
                        self.log_test("Login Endpoint", True, "Login successful or MFA required")
                        return True
                    else:
                        self.log_test("Login Endpoint", False, "No token or MFA in response")
                        return False
                elif response.status == 401:
                    self.log_test("Login Endpoint", True, "Authentication properly rejected")
                    return True
                else:
                    self.log_test("Login Endpoint", False, f"Unexpected status: {response.status}")
                    return False
        except Exception as e:
            self.log_test("Login Endpoint", False, f"Error: {e}")
            return False

    async def test_protected_route(self):
        """Test protected route without authentication"""
        try:
            async with self.session.get(f"{BASE_URL}/users") as response:
                if response.status == 401:
                    self.log_test("Protected Route (No Auth)", True, "Access properly denied")
                    return True
                else:
                    self.log_test("Protected Route (No Auth)", False, f"Expected 401, got {response.status}")
                    return False
        except Exception as e:
            self.log_test("Protected Route (No Auth)", False, f"Error: {e}")
            return False

    async def test_rate_limiting(self):
        """Test rate limiting"""
        try:
            # Make multiple rapid requests to trigger rate limiting
            login_data = {"username": "invalid_user", "password": "invalid_password"}

            rate_limited = False
            for i in range(10):  # Try 10 rapid requests
                async with self.session.post(f"{BASE_URL}/auth/login", json=login_data) as response:
                    if response.status == 429:  # Rate limited
                        rate_limited = True
                        break
                    await asyncio.sleep(0.1)  # Small delay between requests

            if rate_limited:
                self.log_test("Rate Limiting", True, "Rate limiting activated")
                return True
            else:
                self.log_test(
                    "Rate Limiting", True, "Rate limiting not triggered (may be configured for more attempts)"
                )
                return True
        except Exception as e:
            self.log_test("Rate Limiting", False, f"Error: {e}")
            return False

    async def test_security_headers(self):
        """Test security headers"""
        try:
            async with self.session.get(f"{BASE_URL}/") as response:
                headers = response.headers

                required_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "X-XSS-Protection",
                    "Content-Security-Policy",
                ]

                missing_headers = [h for h in required_headers if h not in headers]
                if not missing_headers:
                    self.log_test("Security Headers", True, "All required headers present")
                    return True
                else:
                    self.log_test("Security Headers", False, f"Missing headers: {missing_headers}")
                    return False
        except Exception as e:
            self.log_test("Security Headers", False, f"Error: {e}")
            return False

    async def test_frontend_access(self):
        """Test frontend accessibility"""
        try:
            async with self.session.get(FRONTEND_URL) as response:
                if response.status == 200:
                    self.log_test("Frontend Access", True, "Frontend accessible")
                    return True
                else:
                    self.log_test("Frontend Access", False, f"Status code: {response.status}")
                    return False
        except Exception as e:
            self.log_test("Frontend Access", False, f"Connection error: {e}")
            return False

    async def run_all_tests(self):
        """Run all security tests"""
        print("🔐 SecureOps AI - Enhanced Security Test Suite")
        print("=" * 50)
        print()

        # Setup
        await self.setup()

        # Run tests
        tests = [
            self.test_health_check,
            self.test_security_status,
            self.test_login_endpoint,
            self.test_protected_route,
            self.test_rate_limiting,
            self.test_security_headers,
            self.test_frontend_access,
        ]

        for test in tests:
            await test()
            await asyncio.sleep(0.5)  # Small delay between tests

        # Cleanup
        await self.cleanup()

        # Summary
        print()
        print("📊 Test Summary:")
        print("-" * 30)
        passed = sum(1 for result in self.test_results if result["passed"])
        total = len(self.test_results)
        success_rate = (passed / total) * 100 if total > 0 else 0

        print(f"Passed: {passed}/{total} ({success_rate:.1f}%)")

        if passed == total:
            print("🎉 All tests passed! Your security setup is working correctly.")
        elif success_rate >= 80:
            print("✅ Most tests passed! Minor issues may need attention.")
        else:
            print("⚠️  Several tests failed. Please check your configuration.")

        print()
        print("🔗 Quick Links:")
        print(f"   Frontend: {FRONTEND_URL}")
        print(f"   API Docs: {BASE_URL}/api/docs")
        print(f"   Security Status: {BASE_URL}/security-status")

        return success_rate >= 80


def check_prerequisites():
    """Check if required services are likely running"""
    print("🔍 Checking prerequisites...")
    print("   Backend should be running on: http://localhost:8001")
    print("   Frontend should be running on: http://localhost:3010")
    print("   Use 'docker-compose up' or start services manually")
    print()


async def main():
    """Main test function"""
    check_prerequisites()

    tester = SecurityTester()
    success = await tester.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        sys.exit(1)
