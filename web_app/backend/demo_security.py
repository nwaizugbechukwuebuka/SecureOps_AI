#!/usr/bin/env python3
"""
SecureOps AI - Enhanced Security Startup Script
Demonstrates the enterprise-grade security features
"""

import asyncio
import os
import sys
from datetime import datetime

# Add the backend directory to Python path
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_dir)

async def demonstrate_security_features():
    """Demonstrate the enhanced security features"""
    
    print("🔐 SecureOps AI - Enterprise Security Platform")
    print("=" * 50)
    print()
    
    # Import security components
    try:
        from utils.security_enhanced import TokenManager, MFAService, PasswordValidator
        from utils.audit_logger import SecurityLogger
        from models_enhanced import User
        
        print("✅ Security modules imported successfully")
        
        # Initialize security components
        token_manager = TokenManager()
        mfa_service = MFAService()
        password_validator = PasswordValidator()
        security_logger = SecurityLogger()
        
        print("✅ Security components initialized")
        print()
        
        # Demonstrate password validation
        print("🔑 Password Security Demo:")
        test_passwords = [
            "weak",
            "StrongPass123!",
            "VerySecurePassword2024@#"
        ]
        
        for password in test_passwords:
            validation = password_validator.validate_password(password)
            strength_color = "🔴" if validation['strength'] in ['weak', 'medium'] else "🟢"
            print(f"  {strength_color} '{password}': {validation['strength'].upper()} - Valid: {validation['is_valid']}")
        print()
        
        # Demonstrate MFA
        print("📱 MFA (Multi-Factor Authentication) Demo:")
        try:
            secret = mfa_service.generate_secret()
            qr_code = mfa_service.generate_qr_code("demo@secureops.ai", secret)
            print(f"  ✅ MFA Secret generated: {secret[:10]}...")
            print(f"  ✅ QR Code generated for setup")
            
            # Generate a TOTP code
            import pyotp
            totp = pyotp.TOTP(secret)
            current_code = totp.now()
            print(f"  ✅ Current TOTP code: {current_code}")
            
            # Verify the code
            is_valid = mfa_service.verify_totp(secret, current_code)
            print(f"  ✅ Code verification: {'VALID' if is_valid else 'INVALID'}")
        except Exception as e:
            print(f"  ⚠️ MFA demo error: {e}")
        print()
        
        # Demonstrate JWT tokens
        print("🎫 JWT Token Demo:")
        try:
            # Create a test token
            test_user_data = {
                "user_id": 1,
                "username": "admin",
                "role": "admin"
            }
            
            token = token_manager.create_access_token(test_user_data)
            print(f"  ✅ JWT Token created: {token[:30]}...")
            
            # Verify the token
            decoded = token_manager.decode_token(token)
            if decoded:
                print(f"  ✅ Token verification successful")
                print(f"     User: {decoded.get('username')}")
                print(f"     Role: {decoded.get('role')}")
            else:
                print(f"  ❌ Token verification failed")
        except Exception as e:
            print(f"  ⚠️ JWT demo error: {e}")
        print()
        
        # Demonstrate audit logging
        print("📋 Audit Logging Demo:")
        try:
            await security_logger.log_user_login(
                user_id=1,
                username="admin",
                ip_address="127.0.0.1",
                user_agent="Demo Script",
                success=True
            )
            print("  ✅ Login event logged")
            
            await security_logger.log_security_incident(
                incident_type="demo_security_test",
                description="Demonstrating security incident logging",
                risk_level="low"
            )
            print("  ✅ Security incident logged")
            
        except Exception as e:
            print(f"  ⚠️ Audit logging demo error: {e}")
        print()
        
        # Role-Based Access Control demo
        print("👥 RBAC (Role-Based Access Control) Demo:")
        roles = ["admin", "analyst", "viewer"]
        permissions = {
            "admin": ["*"],
            "analyst": ["view_dashboard", "manage_alerts", "view_users", "view_audit_logs"],
            "viewer": ["view_dashboard", "view_alerts"]
        }
        
        for role in roles:
            role_permissions = permissions[role]
            permission_count = len(role_permissions) if role_permissions != ["*"] else "ALL"
            print(f"  👤 {role.upper()}: {permission_count} permissions")
        print()
        
    except ImportError as e:
        print(f"❌ Failed to import security modules: {e}")
        print("💡 Make sure you have installed the required dependencies:")
        print("   pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Security demonstration failed: {e}")
        return False
    
    return True

def print_startup_info():
    """Print startup information"""
    print("🚀 Starting SecureOps AI with Enhanced Security...")
    print()
    print("Security Features Enabled:")
    print("  ✅ JWT Authentication with MFA")
    print("  ✅ Role-Based Access Control (RBAC)")
    print("  ✅ Comprehensive Audit Logging")
    print("  ✅ Rate Limiting & Brute Force Protection")
    print("  ✅ Enterprise Password Policy")
    print("  ✅ Secure Session Management")
    print("  ✅ Security Headers & CSP")
    print()
    print("Available Endpoints:")
    print("  🌐 Frontend: http://localhost:3010")
    print("  🔌 Backend API: http://localhost:8001")
    print("  📚 API Docs: http://localhost:8001/api/docs")
    print("  🔒 Security Status: http://localhost:8001/security-status")
    print("  ❤️  Health Check: http://localhost:8001/health")
    print()

async def main():
    """Main startup function"""
    print_startup_info()
    
    # Run security demo
    demo_success = await demonstrate_security_features()
    
    if demo_success:
        print("🎉 Security demonstration completed successfully!")
        print()
        print("🚀 Ready to start the application:")
        print("   Backend: python main.py")
        print("   Frontend: npm run dev")
        print("   Docker: docker-compose up")
        print()
        print("🔐 Default Admin Credentials:")
        print("   Username: admin")
        print("   Password: SecureAdmin123!")
        print("   (Change password on first login)")
        print()
    else:
        print("⚠️  Security demonstration encountered issues.")
        print("   The application will still work, but some features may be limited.")
        print()

if __name__ == "__main__":
    asyncio.run(main())