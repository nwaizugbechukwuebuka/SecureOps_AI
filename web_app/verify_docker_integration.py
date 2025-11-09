#!/usr/bin/env python3
"""
SecureOps AI Docker Integration Verification Script
Tests full-stack Docker integration and connectivity
"""

import requests
import time
import subprocess
import json
from typing import Dict, List, Tuple


class DockerVerifier:
    def __init__(self):
        self.frontend_url = "http://localhost:3010"
        self.backend_url = "http://localhost:8001"
        self.results: List[Dict] = []

    def check_service(self, name: str, url: str, timeout: int = 10) -> Tuple[bool, str]:
        """Check if a service is responding"""
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return True, f"✅ {name} is healthy (Status: {response.status_code})"
            else:
                return False, f"❌ {name} returned status {response.status_code}"
        except requests.exceptions.ConnectionError:
            return False, f"❌ {name} is not responding (Connection refused)"
        except requests.exceptions.Timeout:
            return False, f"❌ {name} timed out after {timeout} seconds"
        except Exception as e:
            return False, f"❌ {name} error: {str(e)}"

    def check_docker_containers(self) -> Tuple[bool, str]:
        """Check if Docker containers are running"""
        try:
            result = subprocess.run(
                ["docker-compose", "ps", "--services", "--filter", "status=running"],
                capture_output=True,
                text=True,
                cwd=".",
            )

            if result.returncode == 0:
                running_services = result.stdout.strip().split("\n") if result.stdout.strip() else []
                expected_services = ["frontend", "backend", "redis"]

                running_expected = [svc for svc in expected_services if svc in running_services]

                if len(running_expected) >= 2:  # At least frontend and backend
                    return True, f"✅ Docker containers running: {', '.join(running_expected)}"
                else:
                    return False, f"❌ Expected services not running. Found: {', '.join(running_services)}"
            else:
                return False, f"❌ Docker compose error: {result.stderr}"

        except FileNotFoundError:
            return False, "❌ Docker or docker-compose not found"
        except Exception as e:
            return False, f"❌ Docker check error: {str(e)}"

    def check_proxy_connectivity(self) -> Tuple[bool, str]:
        """Test if frontend can proxy requests to backend"""
        try:
            # Test API endpoint through frontend proxy
            proxy_url = f"{self.frontend_url}/api/health"  # This should proxy to backend
            response = requests.get(proxy_url, timeout=10)

            if response.status_code == 200:
                return True, "✅ Frontend-to-Backend proxy is working"
            elif response.status_code == 502:
                return False, "❌ Proxy error: Backend not reachable from frontend"
            else:
                return False, f"❌ Proxy returned status {response.status_code}"

        except Exception as e:
            return False, f"❌ Proxy test failed: {str(e)}"

    def check_backend_api(self) -> Tuple[bool, str]:
        """Test backend API endpoints"""
        try:
            # Check health endpoint
            health_response = requests.get(f"{self.backend_url}/health", timeout=10)
            if health_response.status_code != 200:
                return False, f"❌ Backend health check failed: {health_response.status_code}"

            # Check API documentation
            docs_response = requests.get(f"{self.backend_url}/api/docs", timeout=10)
            if docs_response.status_code != 200:
                return False, f"❌ Backend API docs not accessible: {docs_response.status_code}"

            # Parse health response
            try:
                health_data = health_response.json()
                if health_data.get("status") == "healthy":
                    return (
                        True,
                        f"✅ Backend API is fully functional (Version: {health_data.get('version', 'Unknown')})",
                    )
                else:
                    return False, f"❌ Backend reports unhealthy status: {health_data}"
            except json.JSONDecodeError:
                return True, "✅ Backend API responding (health endpoint accessible)"

        except Exception as e:
            return False, f"❌ Backend API test failed: {str(e)}"

    def run_verification(self) -> bool:
        """Run all verification tests"""
        print("🔍 SecureOps AI Docker Integration Verification\n")

        tests = [
            ("Docker Containers", self.check_docker_containers),
            ("Backend Service", lambda: self.check_service("Backend", f"{self.backend_url}/health")),
            ("Frontend Service", lambda: self.check_service("Frontend", self.frontend_url)),
            ("Backend API", self.check_backend_api),
            ("Frontend-Backend Proxy", self.check_proxy_connectivity),
        ]

        all_passed = True

        for test_name, test_func in tests:
            print(f"Testing {test_name}...")
            success, message = test_func()
            print(f"  {message}")

            self.results.append({"test": test_name, "success": success, "message": message})

            if not success:
                all_passed = False

            time.sleep(1)  # Small delay between tests

        print("\n" + "=" * 60)
        print("📊 VERIFICATION SUMMARY")
        print("=" * 60)

        passed = sum(1 for r in self.results if r["success"])
        total = len(self.results)

        print(f"Tests Passed: {passed}/{total}")

        if all_passed:
            print("\n🎉 ALL TESTS PASSED!")
            print("\n🌐 Your SecureOps AI application is ready:")
            print(f"   Frontend: {self.frontend_url}")
            print(f"   Backend:  {self.backend_url}")
            print(f"   API Docs: {self.backend_url}/api/docs")
            print("\n✨ The full-stack integration is working perfectly!")
        else:
            print("\n⚠️  SOME TESTS FAILED")
            print("\n❌ Failed tests:")
            for result in self.results:
                if not result["success"]:
                    print(f"   - {result['test']}: {result['message']}")

            print(f"\n🔧 Troubleshooting:")
            print(f"   1. Ensure Docker is running: docker --version")
            print(f"   2. Start services: docker-compose up --build -d")
            print(f"   3. Check logs: docker-compose logs -f")
            print(f"   4. Wait 30-60 seconds for services to start completely")

        return all_passed


if __name__ == "__main__":
    verifier = DockerVerifier()
    success = verifier.run_verification()
    exit(0 if success else 1)
