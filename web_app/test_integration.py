#!/usr/bin/env python3
"""
System Integration Test for SecureOps AI
Tests frontend-backend connectivity and basic functionality
"""

import requests
import time
import sys
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def test_backend():
    """Test backend connectivity and basic endpoints"""
    print("🔧 Testing Backend Connection...")
    
    try:
        # Test health endpoint
        response = requests.get('http://localhost:8000/health', timeout=5)
        if response.status_code == 200:
            print("  ✅ Backend health check: OK")
            health_data = response.json()
            print(f"     Service: {health_data.get('service')}")
            print(f"     Version: {health_data.get('version')}")
        else:
            print(f"  ❌ Backend health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"  ❌ Backend connection failed: {e}")
        return False
    
    try:
        # Test API docs
        response = requests.get('http://localhost:8000/api/docs', timeout=5)
        if response.status_code == 200:
            print("  ✅ API documentation: Available")
        else:
            print("  ⚠️ API documentation: Not available")
    except:
        print("  ⚠️ API documentation: Not accessible")
    
    return True

def test_frontend():
    """Test frontend connectivity"""
    print("🌐 Testing Frontend Connection...")
    
    try:
        response = requests.get('http://localhost:3010', timeout=10)
        if response.status_code == 200:
            print("  ✅ Frontend server: OK")
            if 'SecureOps' in response.text or 'Vite' in response.text:
                print("  ✅ Frontend content: Loaded")
            else:
                print("  ⚠️ Frontend content: Unexpected")
            return True
        else:
            print(f"  ❌ Frontend server failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"  ❌ Frontend connection failed: {e}")
        return False

def test_api_integration():
    """Test basic API integration"""
    print("🔗 Testing API Integration...")
    
    try:
        # Test authentication endpoint
        auth_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        response = requests.post(
            'http://localhost:8000/api/auth/login',
            json=auth_data,
            timeout=5
        )
        
        if response.status_code == 200:
            print("  ✅ Authentication endpoint: Working")
            token_data = response.json()
            if 'access_token' in token_data:
                print("  ✅ JWT token generation: Working")
                return True
            else:
                print("  ⚠️ JWT token: Not in response")
        else:
            print(f"  ❌ Authentication failed: {response.status_code}")
            if response.status_code == 422:
                print("  ℹ️  This might be expected if default users aren't created yet")
            
    except Exception as e:
        print(f"  ❌ API integration test failed: {e}")
    
    return False

def test_cors():
    """Test CORS configuration"""
    print("🔒 Testing CORS Configuration...")
    
    try:
        headers = {
            'Origin': 'http://localhost:3010',
            'Access-Control-Request-Method': 'GET'
        }
        
        response = requests.options(
            'http://localhost:8000/health',
            headers=headers,
            timeout=5
        )
        
        cors_headers = response.headers
        if 'Access-Control-Allow-Origin' in cors_headers:
            print("  ✅ CORS headers: Present")
            allowed_origin = cors_headers['Access-Control-Allow-Origin']
            if allowed_origin == '*' or 'localhost:3010' in allowed_origin:
                print("  ✅ CORS origin: Configured correctly")
                return True
            else:
                print(f"  ⚠️ CORS origin: {allowed_origin}")
        else:
            print("  ❌ CORS headers: Missing")
            
    except Exception as e:
        print(f"  ❌ CORS test failed: {e}")
    
    return False

def main():
    """Run all system tests"""
    print("🛡️ SecureOps AI - System Integration Test")
    print("=" * 45)
    print()
    
    # Track results
    results = {
        'backend': False,
        'frontend': False,
        'api': False,
        'cors': False
    }
    
    # Run tests
    results['backend'] = test_backend()
    print()
    
    results['frontend'] = test_frontend()
    print()
    
    results['api'] = test_api_integration()
    print()
    
    results['cors'] = test_cors()
    print()
    
    # Summary
    print("📋 Test Summary")
    print("=" * 15)
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name.capitalize()}: {status}")
    
    print()
    print(f"📊 Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All tests passed! System is ready.")
        print()
        print("🌐 Frontend: http://localhost:3010")
        print("🔧 Backend:  http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/api/docs")
        return True
    else:
        print("⚠️ Some tests failed. Please check the configuration.")
        print()
        print("💡 Troubleshooting Tips:")
        if not results['backend']:
            print("  - Make sure backend is running on port 8000")
            print("  - Check backend logs for errors")
        if not results['frontend']:
            print("  - Make sure frontend is running on port 3010")
            print("  - Check if npm run dev is working")
        if not results['api']:
            print("  - Verify database is initialized")
            print("  - Check if default users are created")
        if not results['cors']:
            print("  - Verify CORS configuration in backend")
            print("  - Check allowed origins in settings")
        
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)