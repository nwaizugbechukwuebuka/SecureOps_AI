# Security Model Documentation

## Table of Contents

1. [Overview](#overview)
2. [Security Architecture](#security-architecture)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [Data Protection](#data-protection)
5. [Network Security](#network-security)
6. [Application Security](#application-security)
7. [Infrastructure Security](#infrastructure-security)
8. [Vulnerability Management](#vulnerability-management)
9. [Compliance and Governance](#compliance-and-governance)
10. [Incident Response](#incident-response)
11. [Security Monitoring](#security-monitoring)
12. [Security Testing](#security-testing)

## Overview

The SecureOps security model implements a comprehensive defense-in-depth strategy designed to protect against modern cybersecurity threats while maintaining operational efficiency. This document outlines the security controls, policies, and procedures that govern the SecureOps platform.

### Security Principles

#### 1. Zero Trust Architecture
- **Never Trust, Always Verify**: No implicit trust for any user, device, or network location
- **Least Privilege Access**: Users and systems receive minimum necessary permissions
- **Continuous Verification**: Ongoing authentication and authorization validation
- **Assume Breach**: Design systems assuming they will be compromised

#### 2. Defense in Depth
- **Layered Security**: Multiple overlapping security controls
- **Fail Secure**: Systems fail to a secure state when errors occur
- **Separation of Duties**: Critical operations require multiple approvals
- **Continuous Monitoring**: Real-time security monitoring and alerting

#### 3. Privacy by Design
- **Data Minimization**: Collect only necessary data
- **Purpose Limitation**: Use data only for stated purposes
- **Transparency**: Clear privacy policies and data handling practices
- **User Control**: Users can access, modify, and delete their data

### Threat Model

#### Identified Threats

**External Threats**:
- Advanced Persistent Threats (APTs)
- Ransomware and malware attacks
- Distributed Denial of Service (DDoS)
- Supply chain attacks
- Social engineering and phishing

**Internal Threats**:
- Malicious insiders
- Accidental data exposure
- Privilege escalation
- Configuration drift
- Human error

**Technical Threats**:
- Zero-day vulnerabilities
- Injection attacks (SQL, XSS, etc.)
- Authentication bypass
- Authorization flaws
- Cryptographic failures

#### Risk Assessment Matrix

| Threat Category | Likelihood | Impact | Risk Level | Mitigation Priority |
|----------------|------------|--------|------------|-------------------|
| External APT | Medium | High | High | P1 |
| Ransomware | High | High | Critical | P0 |
| DDoS | High | Medium | High | P1 |
| Supply Chain | Medium | High | High | P1 |
| Malicious Insider | Low | High | Medium | P2 |
| Data Breach | Medium | High | High | P1 |
| Service Outage | Medium | Medium | Medium | P2 |

## Security Architecture

### Security Zones

```
┌─────────────────────────────────────────────────────────────────┐
│                          Internet Zone                          │
│                     (Untrusted Network)                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                         DMZ Zone                                │
│                   (Demilitarized Zone)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Load        │  │ WAF/Proxy   │  │ Rate        │            │
│  │ Balancer    │  │             │  │ Limiter     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Application Zone                             │
│                  (Semi-Trusted Network)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Frontend    │  │ API         │  │ Auth        │            │
│  │ Services    │  │ Gateway     │  │ Service     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Service Zone                               │
│                   (Internal Network)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Business    │  │ Processing  │  │ Integration │            │
│  │ Logic       │  │ Workers     │  │ Services    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Data Zone                                 │
│                   (Trusted Network)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Primary     │  │ Cache       │  │ Backup      │            │
│  │ Database    │  │ Storage     │  │ Storage     │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### Security Controls by Zone

#### DMZ Zone Controls
- **Firewall Rules**: Restrictive ingress/egress rules
- **DDoS Protection**: Rate limiting and traffic analysis
- **WAF**: Web Application Firewall for OWASP Top 10 protection
- **SSL Termination**: TLS encryption and certificate management
- **Intrusion Detection**: Network-based IDS/IPS

#### Application Zone Controls
- **API Gateway**: Centralized API security and rate limiting
- **Authentication**: Multi-factor authentication and SSO
- **Authorization**: Role-based access control (RBAC)
- **Input Validation**: Comprehensive input sanitization
- **Output Encoding**: XSS protection and safe rendering

#### Service Zone Controls
- **Service Mesh**: Mutual TLS between services
- **Secret Management**: Encrypted secret storage and rotation
- **Container Security**: Image scanning and runtime protection
- **Process Isolation**: Containerization and sandboxing
- **Network Segmentation**: Micro-segmentation policies

#### Data Zone Controls
- **Encryption at Rest**: Database and file encryption
- **Access Controls**: Database-level permissions
- **Data Masking**: Sensitive data obfuscation
- **Backup Encryption**: Encrypted backup storage
- **Audit Logging**: Comprehensive data access logging

## Authentication and Authorization

### Multi-Factor Authentication (MFA)

#### Supported Factors

1. **Something You Know** (Knowledge Factor)
   - Username and password
   - Security questions
   - PIN codes

2. **Something You Have** (Possession Factor)
   - TOTP authenticator apps (Google Authenticator, Authy)
   - Hardware security keys (YubiKey, FIDO2)
   - SMS codes (backup method only)
   - Email verification

3. **Something You Are** (Inherence Factor)
   - Biometric authentication (future enhancement)
   - Behavioral analysis (future enhancement)

#### MFA Implementation

```python
# MFA Configuration
class MFAConfig:
    TOTP_ISSUER = "SecureOps"
    TOTP_ALGORITHM = "SHA1"
    TOTP_DIGITS = 6
    TOTP_PERIOD = 30
    
    BACKUP_CODES_COUNT = 10
    BACKUP_CODES_LENGTH = 8
    
    SMS_PROVIDER = "twilio"
    EMAIL_PROVIDER = "sendgrid"

# TOTP Implementation
import pyotp
import qrcode

class TOTPManager:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(user_email: str, secret: str) -> bytes:
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=MFAConfig.TOTP_ISSUER
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        return img_to_bytes(img)
    
    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
```

### Single Sign-On (SSO)

#### Supported Protocols

- **SAML 2.0**: Enterprise identity providers
- **OpenID Connect**: Modern OAuth 2.0 based authentication
- **LDAP/Active Directory**: Legacy directory integration

#### SSO Configuration

```yaml
# SSO Provider Configuration
sso_providers:
  azure_ad:
    type: oidc
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    discovery_url: "https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid_configuration"
    scopes: ["openid", "profile", "email"]
  
  okta:
    type: saml
    entity_id: "https://secureops.example.com"
    sso_url: "https://company.okta.com/app/secureops/sso/saml"
    certificate: "${OKTA_CERTIFICATE}"
    
  active_directory:
    type: ldap
    server: "ldap://dc.company.com:389"
    bind_dn: "CN=secureops,OU=ServiceAccounts,DC=company,DC=com"
    bind_password: "${LDAP_PASSWORD}"
    user_base: "OU=Users,DC=company,DC=com"
    user_filter: "(sAMAccountName={username})"
```

### Role-Based Access Control (RBAC)

#### Permission Model

```python
# Permission definitions
PERMISSIONS = {
    # Pipeline permissions
    'pipelines:read': 'View pipeline information',
    'pipelines:write': 'Create and modify pipelines',
    'pipelines:delete': 'Delete pipelines',
    'pipelines:execute': 'Trigger pipeline execution',
    
    # Alert permissions
    'alerts:read': 'View alerts',
    'alerts:write': 'Create and modify alerts',
    'alerts:acknowledge': 'Acknowledge alerts',
    'alerts:resolve': 'Resolve alerts',
    
    # Vulnerability permissions
    'vulnerabilities:read': 'View vulnerability information',
    'vulnerabilities:write': 'Modify vulnerability status',
    'vulnerabilities:export': 'Export vulnerability data',
    
    # Compliance permissions
    'compliance:read': 'View compliance information',
    'compliance:assess': 'Run compliance assessments',
    'compliance:report': 'Generate compliance reports',
    
    # User management permissions
    'users:read': 'View user information',
    'users:write': 'Create and modify users',
    'users:delete': 'Delete users',
    
    # System administration
    'system:admin': 'Full system administration',
    'system:audit': 'View audit logs',
    'system:backup': 'Manage backups',
}

# Role definitions
ROLES = {
    'super_admin': {
        'description': 'Full system access',
        'permissions': ['*']
    },
    
    'security_admin': {
        'description': 'Security team administrator',
        'permissions': [
            'pipelines:*', 'alerts:*', 'vulnerabilities:*',
            'compliance:*', 'users:read', 'system:audit'
        ]
    },
    
    'security_analyst': {
        'description': 'Security analyst role',
        'permissions': [
            'pipelines:read', 'alerts:read', 'alerts:acknowledge',
            'alerts:resolve', 'vulnerabilities:read', 'vulnerabilities:write',
            'compliance:read', 'compliance:assess'
        ]
    },
    
    'developer': {
        'description': 'Application developer',
        'permissions': [
            'pipelines:read', 'pipelines:write', 'pipelines:execute',
            'alerts:read', 'vulnerabilities:read'
        ]
    },
    
    'auditor': {
        'description': 'Compliance auditor',
        'permissions': [
            'pipelines:read', 'alerts:read', 'vulnerabilities:read',
            'compliance:read', 'compliance:report', 'system:audit'
        ]
    },
    
    'viewer': {
        'description': 'Read-only access',
        'permissions': [
            'pipelines:read', 'alerts:read', 'vulnerabilities:read',
            'compliance:read'
        ]
    }
}
```

#### Dynamic Permissions

```python
# Resource-based permissions
class ResourcePermission:
    def __init__(self, resource_type: str, resource_id: str, permission: str):
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.permission = permission
    
    def __str__(self):
        return f"{self.resource_type}:{self.resource_id}:{self.permission}"

# Example: Grant user access to specific pipeline
user_permissions = [
    ResourcePermission("pipeline", "123", "read"),
    ResourcePermission("pipeline", "123", "execute"),
    ResourcePermission("organization", "acme-corp", "admin")
]

# Permission checking
def check_permission(user: User, permission: str, resource: Resource = None) -> bool:
    # Check global permissions
    if permission in user.global_permissions:
        return True
    
    # Check role-based permissions
    for role in user.roles:
        if permission in ROLES[role]['permissions']:
            return True
    
    # Check resource-specific permissions
    if resource:
        resource_permission = f"{resource.type}:{resource.id}:{permission}"
        if resource_permission in user.resource_permissions:
            return True
    
    return False
```

## Data Protection

### Encryption Standards

#### Encryption at Rest

**Database Encryption**:
- **Algorithm**: AES-256-GCM
- **Key Management**: AWS KMS / Azure Key Vault / HashiCorp Vault
- **Column-Level Encryption**: Sensitive fields (PII, credentials)
- **Transparent Data Encryption**: Full database encryption

```sql
-- Database encryption configuration
-- PostgreSQL with encryption
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    -- PII encrypted at column level
    first_name TEXT ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = user_data_key),
    last_name TEXT ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = user_data_key),
    phone TEXT ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = user_data_key),
    created_at TIMESTAMP DEFAULT NOW()
);
```

**File System Encryption**:
- **Algorithm**: AES-256-XTS (dm-crypt/LUKS)
- **Key Storage**: Hardware Security Module (HSM)
- **Backup Encryption**: GPG encryption with rotating keys

```bash
# File system encryption setup
cryptsetup luksFormat /dev/sdb --cipher aes-xts-plain64 --key-size 256 --hash sha256
cryptsetup luksOpen /dev/sdb secureops_data
mkfs.ext4 /dev/mapper/secureops_data
```

#### Encryption in Transit

**TLS Configuration**:
- **Minimum Version**: TLS 1.2
- **Preferred Version**: TLS 1.3
- **Cipher Suites**: AEAD ciphers only (ChaCha20-Poly1305, AES-GCM)
- **Key Exchange**: ECDHE with P-256 or X25519
- **Signature**: RSA-PSS or EdDSA

```nginx
# Nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# Security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Service-to-Service Encryption**:
- **Mutual TLS**: Certificate-based authentication between services
- **Service Mesh**: Istio/Linkerd for automatic mTLS
- **Certificate Rotation**: Automatic certificate lifecycle management

### Key Management

#### Key Hierarchy

```
┌─────────────────────────────────────────┐
│           Root Key (HSM)                │
│         (Key Encryption Key)            │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│        Master Keys (KMS)                │
│      (Data Encryption Keys)             │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌─────────┐  ┌─────────┐  ┌─────────┐
│Database │  │  File   │  │ Backup  │
│   Key   │  │  Keys   │  │  Keys   │
└─────────┘  └─────────┘  └─────────┘
```

#### Key Rotation

```python
# Automated key rotation
import asyncio
from datetime import datetime, timedelta

class KeyRotationManager:
    def __init__(self, kms_client, rotation_period: timedelta = timedelta(days=90)):
        self.kms_client = kms_client
        self.rotation_period = rotation_period
    
    async def rotate_keys(self):
        keys_to_rotate = await self.get_keys_due_for_rotation()
        
        for key in keys_to_rotate:
            try:
                await self.rotate_key(key)
                await self.update_services_with_new_key(key)
                await self.schedule_old_key_deletion(key)
                
                logger.info(f"Successfully rotated key: {key.id}")
            except Exception as e:
                logger.error(f"Failed to rotate key {key.id}: {e}")
                await self.send_alert(f"Key rotation failed for {key.id}")
    
    async def rotate_key(self, key: EncryptionKey):
        # Generate new key version
        new_key_version = await self.kms_client.create_key_version(key.id)
        
        # Update key metadata
        key.current_version = new_key_version.version
        key.rotated_at = datetime.utcnow()
        key.next_rotation = datetime.utcnow() + self.rotation_period
        
        await self.save_key_metadata(key)
        
        return new_key_version
```

### Data Classification

#### Classification Levels

| Level | Description | Examples | Protection Requirements |
|-------|-------------|----------|------------------------|
| **Public** | Information intended for public consumption | Documentation, marketing materials | Standard web security |
| **Internal** | Information for internal use only | System configurations, internal docs | Authentication required |
| **Confidential** | Sensitive business information | User data, scan results, reports | Encryption + access controls |
| **Restricted** | Highly sensitive information | Authentication tokens, encryption keys | HSM + strict access controls |

#### Data Handling Policies

```python
# Data classification implementation
from enum import Enum

class DataClassification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

class DataHandler:
    @staticmethod
    def get_protection_requirements(classification: DataClassification) -> dict:
        requirements = {
            DataClassification.PUBLIC: {
                "encryption_at_rest": False,
                "encryption_in_transit": True,
                "access_control": False,
                "audit_logging": False,
                "retention_period": "indefinite"
            },
            DataClassification.INTERNAL: {
                "encryption_at_rest": False,
                "encryption_in_transit": True,
                "access_control": True,
                "audit_logging": True,
                "retention_period": "7_years"
            },
            DataClassification.CONFIDENTIAL: {
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "access_control": True,
                "audit_logging": True,
                "retention_period": "3_years",
                "data_masking": True
            },
            DataClassification.RESTRICTED: {
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "access_control": True,
                "audit_logging": True,
                "retention_period": "1_year",
                "hsm_required": True,
                "two_person_rule": True
            }
        }
        
        return requirements[classification]
```

### Privacy Protection

#### Personal Data Handling

```python
# GDPR compliance implementation
class PersonalDataProcessor:
    def __init__(self):
        self.consent_manager = ConsentManager()
        self.data_retention = DataRetentionManager()
    
    async def process_personal_data(self, user_id: str, data: dict, purpose: str):
        # Check consent
        if not await self.consent_manager.has_consent(user_id, purpose):
            raise InsufficientConsentError(f"No consent for purpose: {purpose}")
        
        # Apply data minimization
        minimal_data = self.minimize_data(data, purpose)
        
        # Pseudonymize sensitive fields
        pseudonymized_data = self.pseudonymize(minimal_data)
        
        # Log data processing
        await self.log_processing_activity(user_id, purpose, list(minimal_data.keys()))
        
        return pseudonymized_data
    
    def minimize_data(self, data: dict, purpose: str) -> dict:
        purpose_requirements = {
            "security_scanning": ["user_id", "repository_url"],
            "compliance_reporting": ["user_id", "organization_id", "timestamp"],
            "alerting": ["user_id", "notification_preferences"]
        }
        
        required_fields = purpose_requirements.get(purpose, [])
        return {k: v for k, v in data.items() if k in required_fields}
    
    def pseudonymize(self, data: dict) -> dict:
        pseudonymized = data.copy()
        
        # Replace direct identifiers with pseudonyms
        if 'email' in pseudonymized:
            pseudonymized['email_hash'] = hash_email(pseudonymized.pop('email'))
        
        if 'ip_address' in pseudonymized:
            pseudonymized['ip_hash'] = hash_ip(pseudonymized.pop('ip_address'))
        
        return pseudonymized
```

#### Data Subject Rights

```python
# GDPR rights implementation
class DataSubjectRights:
    async def handle_access_request(self, user_id: str) -> dict:
        """Article 15: Right of access"""
        personal_data = await self.collect_personal_data(user_id)
        processing_purposes = await self.get_processing_purposes(user_id)
        data_categories = await self.get_data_categories(user_id)
        
        return {
            "personal_data": personal_data,
            "processing_purposes": processing_purposes,
            "data_categories": data_categories,
            "retention_periods": await self.get_retention_periods(user_id),
            "third_party_recipients": await self.get_third_party_recipients(user_id)
        }
    
    async def handle_rectification_request(self, user_id: str, corrections: dict):
        """Article 16: Right to rectification"""
        await self.validate_corrections(corrections)
        await self.update_personal_data(user_id, corrections)
        await self.notify_third_parties_of_corrections(user_id, corrections)
        await self.log_rectification(user_id, corrections)
    
    async def handle_erasure_request(self, user_id: str, reason: str):
        """Article 17: Right to erasure (Right to be forgotten)"""
        if not await self.can_erase(user_id, reason):
            raise ErasureNotPermittedException(reason)
        
        await self.anonymize_personal_data(user_id)
        await self.notify_third_parties_of_erasure(user_id)
        await self.log_erasure(user_id, reason)
    
    async def handle_portability_request(self, user_id: str, format: str = "json"):
        """Article 20: Right to data portability"""
        portable_data = await self.get_portable_data(user_id)
        
        if format == "json":
            return json.dumps(portable_data, indent=2)
        elif format == "csv":
            return self.convert_to_csv(portable_data)
        else:
            raise UnsupportedFormatError(format)
```

## Network Security

### Network Segmentation

#### Micro-segmentation Strategy

```yaml
# Kubernetes Network Policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-network-policy
  namespace: secureops
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Ingress
  - Egress
  
  # Ingress rules
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8000
  
  # Egress rules
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  # Allow DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53
```

#### VPC Security

```terraform
# AWS VPC security configuration
resource "aws_vpc" "secureops" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "secureops-vpc"
    Environment = "production"
  }
}

# Private subnets for application tier
resource "aws_subnet" "private_app" {
  count                   = 3
  vpc_id                  = aws_vpc.secureops.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  
  tags = {
    Name = "secureops-private-app-${count.index + 1}"
    Tier = "application"
  }
}

# Private subnets for data tier
resource "aws_subnet" "private_data" {
  count                   = 3
  vpc_id                  = aws_vpc.secureops.id
  cidr_block              = "10.0.${count.index + 10}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  
  tags = {
    Name = "secureops-private-data-${count.index + 1}"
    Tier = "data"
  }
}

# Security groups
resource "aws_security_group" "api_server" {
  name_prefix = "secureops-api-"
  vpc_id      = aws_vpc.secureops.id
  
  # Allow HTTPS from load balancer
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
  }
  
  # Allow outbound to database
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
  }
  
  # Allow outbound to Redis
  egress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.redis.id]
  }
  
  tags = {
    Name = "secureops-api-server"
  }
}
```

### Firewall Configuration

#### Web Application Firewall (WAF)

```yaml
# AWS WAF Configuration
Resources:
  SecureOpsWebACL:
    Type: AWS::WAFv2::WebACL
    Properties:
      Name: SecureOps-WebACL
      Scope: CLOUDFRONT
      DefaultAction:
        Allow: {}
      
      Rules:
        # Rate limiting
        - Name: RateLimitRule
          Priority: 1
          Statement:
            RateBasedStatement:
              Limit: 1000
              AggregateKeyType: IP
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: RateLimitRule
        
        # SQL Injection protection
        - Name: SQLInjectionRule
          Priority: 2
          Statement:
            SqliMatchStatement:
              FieldToMatch:
                Body: {}
              TextTransformations:
                - Priority: 0
                  Type: URL_DECODE
                - Priority: 1
                  Type: HTML_ENTITY_DECODE
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: SQLInjectionRule
        
        # XSS protection
        - Name: XSSRule
          Priority: 3
          Statement:
            XssMatchStatement:
              FieldToMatch:
                Body: {}
              TextTransformations:
                - Priority: 0
                  Type: URL_DECODE
                - Priority: 1
                  Type: HTML_ENTITY_DECODE
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: XSSRule
        
        # IP reputation list
        - Name: IPReputationRule
          Priority: 4
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesAmazonIpReputationList
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: IPReputationRule
```

#### DDoS Protection

```python
# Application-level DDoS protection
import asyncio
from collections import defaultdict, deque
from datetime import datetime, timedelta
import redis

class DDoSProtection:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.rate_limits = {
            'requests_per_minute': 60,
            'requests_per_hour': 1000,
            'requests_per_day': 10000
        }
    
    async def check_rate_limit(self, client_ip: str) -> bool:
        current_time = datetime.utcnow()
        
        # Check different time windows
        for window, limit in self.rate_limits.items():
            if window == 'requests_per_minute':
                window_seconds = 60
            elif window == 'requests_per_hour':
                window_seconds = 3600
            else:  # requests_per_day
                window_seconds = 86400
            
            key = f"rate_limit:{client_ip}:{window}"
            
            # Use sliding window counter
            count = await self.get_sliding_window_count(key, window_seconds)
            
            if count >= limit:
                await self.log_rate_limit_violation(client_ip, window, count, limit)
                return False
        
        # Increment counters
        await self.increment_counters(client_ip)
        return True
    
    async def get_sliding_window_count(self, key: str, window_seconds: int) -> int:
        current_time = datetime.utcnow().timestamp()
        cutoff_time = current_time - window_seconds
        
        # Remove expired entries
        await self.redis.zremrangebyscore(key, 0, cutoff_time)
        
        # Count current entries
        count = await self.redis.zcard(key)
        return count
    
    async def increment_counters(self, client_ip: str):
        current_time = datetime.utcnow().timestamp()
        
        for window in self.rate_limits.keys():
            key = f"rate_limit:{client_ip}:{window}"
            
            # Add current request
            await self.redis.zadd(key, {str(current_time): current_time})
            
            # Set expiry for the key
            if window == 'requests_per_minute':
                await self.redis.expire(key, 120)  # 2 minutes buffer
            elif window == 'requests_per_hour':
                await self.redis.expire(key, 7200)  # 2 hours buffer
            else:
                await self.redis.expire(key, 172800)  # 2 days buffer
```

### Intrusion Detection and Prevention

#### Network-based IDS/IPS

```yaml
# Suricata configuration
# /etc/suricata/suricata.yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80,443,8000,8080,8443"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - secureops-custom.rules

# Custom rules for SecureOps
# /var/lib/suricata/rules/secureops-custom.rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Potential SQL Injection"; content:"UNION SELECT"; nocase; sid:1000001; rev:1;)
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Potential XSS Attack"; content:"<script"; nocase; sid:1000002; rev:1;)
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"High Request Rate"; threshold:type both, track by_src, count 100, seconds 60; sid:1000003; rev:1;)
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Directory Traversal"; content:"../"; sid:1000004; rev:1;)
```

#### Host-based IDS

```python
# OSSEC/Wazuh agent configuration
import psutil
import hashlib
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SecurityMonitor:
    def __init__(self):
        self.baseline_hashes = {}
        self.suspicious_processes = []
        self.file_monitor = FileMonitor()
    
    def start_monitoring(self):
        # Start file integrity monitoring
        self.file_monitor.start()
        
        # Start process monitoring
        self.monitor_processes()
        
        # Start network monitoring
        self.monitor_network_connections()
    
    def monitor_processes(self):
        """Monitor for suspicious process activity"""
        while True:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
                try:
                    # Check for suspicious process names
                    if self.is_suspicious_process(proc.info['name']):
                        self.alert_suspicious_process(proc.info)
                    
                    # Check for high CPU usage
                    if proc.info['cpu_percent'] > 80:
                        self.alert_high_cpu_usage(proc.info)
                    
                    # Check for suspicious command lines
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if self.is_suspicious_cmdline(cmdline):
                        self.alert_suspicious_cmdline(proc.info, cmdline)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            time.sleep(10)
    
    def is_suspicious_process(self, process_name: str) -> bool:
        suspicious_names = [
            'nc', 'netcat', 'ncat',  # Network tools
            'wget', 'curl',  # Download tools
            'python', 'perl', 'ruby',  # Scripting languages (context-dependent)
            'powershell', 'cmd.exe',  # Windows shells
            'bash', 'sh', 'zsh'  # Unix shells
        ]
        
        return process_name.lower() in suspicious_names
    
    def is_suspicious_cmdline(self, cmdline: str) -> bool:
        suspicious_patterns = [
            'rm -rf /', 'dd if=', 'mkfs',  # Destructive commands
            'base64', 'decode',  # Encoding/decoding
            '/dev/tcp/', '/dev/udp/',  # Network redirection
            'wget http', 'curl http',  # External downloads
            'chmod +x', 'chmod 777'  # Permission changes
        ]
        
        return any(pattern in cmdline.lower() for pattern in suspicious_patterns)

class FileMonitor(FileSystemEventHandler):
    def __init__(self):
        self.critical_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/hosts',
            '/var/log/', '/etc/crontab'
        ]
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path in self.critical_paths:
            self.alert_file_modification(event.src_path)
    
    def alert_file_modification(self, file_path: str):
        alert_data = {
            "type": "file_integrity_violation",
            "file_path": file_path,
            "timestamp": time.time(),
            "severity": "high"
        }
        
        # Send alert to SecureOps
        self.send_security_alert(alert_data)
```

## Application Security

### Input Validation and Sanitization

#### Comprehensive Input Validation

```python
# Input validation framework
from typing import Any, Dict, List, Optional, Union
import re
import html
import bleach
from pydantic import BaseModel, validator, Field

class InputValidator:
    # Regular expressions for common validations
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    URL_REGEX = re.compile(r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$')
    IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    
    # Dangerous patterns to block
    SQL_INJECTION_PATTERNS = [
        r'union\s+select', r'insert\s+into', r'delete\s+from',
        r'drop\s+table', r'update\s+set', r'exec\s*\(',
        r'script\s*:', r'javascript\s*:', r'vbscript\s*:'
    ]
    
    XSS_PATTERNS = [
        r'<script', r'javascript:', r'vbscript:', r'onload\s*=',
        r'onerror\s*=', r'onclick\s*=', r'onmouseover\s*='
    ]
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        return bool(cls.EMAIL_REGEX.match(email))
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        return bool(cls.URL_REGEX.match(url))
    
    @classmethod
    def sanitize_html(cls, html_content: str) -> str:
        # Allow only safe HTML tags
        allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'h1', 'h2', 'h3']
        allowed_attributes = {}
        
        return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attributes)
    
    @classmethod
    def check_sql_injection(cls, input_string: str) -> bool:
        input_lower = input_string.lower()
        return any(re.search(pattern, input_lower) for pattern in cls.SQL_INJECTION_PATTERNS)
    
    @classmethod
    def check_xss(cls, input_string: str) -> bool:
        input_lower = input_string.lower()
        return any(re.search(pattern, input_lower) for pattern in cls.XSS_PATTERNS)

# Pydantic models with validation
class PipelineCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, regex=r'^[a-zA-Z0-9\s\-_]+$')
    description: Optional[str] = Field(None, max_length=1000)
    platform: str = Field(..., regex=r'^(github|gitlab|jenkins|azure_devops)$')
    repository_url: str = Field(..., max_length=500)
    branch: str = Field(default="main", max_length=100, regex=r'^[a-zA-Z0-9\-_/]+$')
    
    @validator('repository_url')
    def validate_repository_url(cls, v):
        if not InputValidator.validate_url(v):
            raise ValueError('Invalid repository URL format')
        
        # Additional validation for supported platforms
        valid_domains = ['github.com', 'gitlab.com', 'dev.azure.com']
        if not any(domain in v for domain in valid_domains):
            raise ValueError('Repository must be from a supported platform')
        
        return v
    
    @validator('description')
    def validate_description(cls, v):
        if v:
            if InputValidator.check_xss(v) or InputValidator.check_sql_injection(v):
                raise ValueError('Description contains potentially malicious content')
            
            # Sanitize HTML content
            return InputValidator.sanitize_html(v)
        
        return v

class AlertCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1, max_length=2000)
    severity: str = Field(..., regex=r'^(critical|high|medium|low)$')
    source: str = Field(..., max_length=50)
    pipeline_id: Optional[int] = Field(None, gt=0)
    
    @validator('title', 'description')
    def validate_content(cls, v):
        if InputValidator.check_xss(v) or InputValidator.check_sql_injection(v):
            raise ValueError('Content contains potentially malicious patterns')
        return html.escape(v)
```

### Output Encoding and Escaping

```python
# Output encoding utilities
import html
import json
import urllib.parse
from typing import Any, Dict

class OutputEncoder:
    @staticmethod
    def html_encode(text: str) -> str:
        """Encode text for safe HTML output"""
        return html.escape(text, quote=True)
    
    @staticmethod
    def javascript_encode(text: str) -> str:
        """Encode text for safe JavaScript output"""
        return json.dumps(text)[1:-1]  # Remove surrounding quotes
    
    @staticmethod
    def url_encode(text: str) -> str:
        """Encode text for safe URL parameter output"""
        return urllib.parse.quote(text, safe='')
    
    @staticmethod
    def css_encode(text: str) -> str:
        """Encode text for safe CSS output"""
        # Escape CSS special characters
        css_escapes = {
            '"': '\\"',
            "'": "\\'",
            '\\': '\\\\',
            '\n': '\\A',
            '\r': '\\D',
            '\t': '\\9'
        }
        
        result = text
        for char, escape in css_escapes.items():
            result = result.replace(char, escape)
        
        return result
    
    @staticmethod
    def safe_json_response(data: Any) -> str:
        """Create safe JSON response with proper encoding"""
        return json.dumps(data, ensure_ascii=True, separators=(',', ':'))

# Template security
from jinja2 import Environment, select_autoescape

# Configure Jinja2 with auto-escaping
template_env = Environment(
    autoescape=select_autoescape(['html', 'xml']),
    trim_blocks=True,
    lstrip_blocks=True
)

# Custom filters for additional security
def safe_markdown(text: str) -> str:
    """Convert markdown to safe HTML"""
    import markdown
    from markdown.extensions import codehilite
    
    md = markdown.Markdown(
        extensions=['codehilite', 'fenced_code', 'tables'],
        extension_configs={
            'codehilite': {
                'css_class': 'highlight',
                'use_pygments': True
            }
        },
        safe_mode='escape'
    )
    
    return md.convert(text)

template_env.filters['safe_markdown'] = safe_markdown
template_env.filters['html_encode'] = OutputEncoder.html_encode
template_env.filters['js_encode'] = OutputEncoder.javascript_encode
```

### Content Security Policy (CSP)

```python
# CSP implementation
class CSPBuilder:
    def __init__(self):
        self.directives = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", "data:", "https:"],
            'font-src': ["'self'", "https://fonts.gstatic.com"],
            'connect-src': ["'self'"],
            'media-src': ["'none'"],
            'object-src': ["'none'"],
            'child-src': ["'none'"],
            'frame-ancestors': ["'none'"],
            'form-action': ["'self'"],
            'base-uri': ["'self'"],
            'manifest-src': ["'self'"]
        }
    
    def add_script_src(self, source: str):
        self.directives['script-src'].append(source)
    
    def add_style_src(self, source: str):
        self.directives['style-src'].append(source)
    
    def add_connect_src(self, source: str):
        self.directives['connect-src'].append(source)
    
    def build(self) -> str:
        csp_parts = []
        for directive, sources in self.directives.items():
            csp_parts.append(f"{directive} {' '.join(sources)}")
        
        return '; '.join(csp_parts)

# CSP middleware
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware

class CSPMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, csp_builder: CSPBuilder):
        super().__init__(app)
        self.csp = csp_builder.build()
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add CSP header
        response.headers["Content-Security-Policy"] = self.csp
        
        # Add other security headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response
```

### Session Security

```python
# Secure session management
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional

class SecureSessionManager:
    def __init__(self, redis_client, session_timeout: int = 3600):
        self.redis = redis_client
        self.session_timeout = session_timeout
        self.max_sessions_per_user = 5
    
    async def create_session(self, user_id: str, user_agent: str, ip_address: str) -> str:
        # Generate cryptographically secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create session data
        session_data = {
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat(),
            'last_activity': datetime.utcnow().isoformat(),
            'user_agent_hash': hashlib.sha256(user_agent.encode()).hexdigest()[:16],
            'ip_address_hash': hashlib.sha256(ip_address.encode()).hexdigest()[:16],
            'csrf_token': secrets.token_urlsafe(32)
        }
        
        # Store session
        session_key = f"session:{session_id}"
        await self.redis.hset(session_key, mapping=session_data)
        await self.redis.expire(session_key, self.session_timeout)
        
        # Add to user's active sessions
        user_sessions_key = f"user_sessions:{user_id}"
        await self.redis.sadd(user_sessions_key, session_id)
        await self.redis.expire(user_sessions_key, self.session_timeout)
        
        # Enforce session limit
        await self.enforce_session_limit(user_id)
        
        return session_id
    
    async def validate_session(self, session_id: str, user_agent: str, ip_address: str) -> Optional[dict]:
        session_key = f"session:{session_id}"
        session_data = await self.redis.hgetall(session_key)
        
        if not session_data:
            return None
        
        # Validate user agent fingerprint
        current_ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        if session_data.get('user_agent_hash') != current_ua_hash:
            await self.invalidate_session(session_id)
            return None
        
        # Validate IP address (optional, can be disabled for mobile users)
        current_ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]
        if session_data.get('ip_address_hash') != current_ip_hash:
            # Log potential session hijacking
            await self.log_security_event("session_ip_mismatch", {
                'session_id': session_id,
                'original_ip_hash': session_data.get('ip_address_hash'),
                'current_ip_hash': current_ip_hash
            })
        
        # Update last activity
        await self.redis.hset(session_key, 'last_activity', datetime.utcnow().isoformat())
        await self.redis.expire(session_key, self.session_timeout)
        
        return session_data
    
    async def invalidate_session(self, session_id: str):
        session_key = f"session:{session_id}"
        session_data = await self.redis.hgetall(session_key)
        
        if session_data and 'user_id' in session_data:
            user_id = session_data['user_id']
            user_sessions_key = f"user_sessions:{user_id}"
            await self.redis.srem(user_sessions_key, session_id)
        
        await self.redis.delete(session_key)
    
    async def enforce_session_limit(self, user_id: str):
        user_sessions_key = f"user_sessions:{user_id}"
        sessions = await self.redis.smembers(user_sessions_key)
        
        if len(sessions) > self.max_sessions_per_user:
            # Get session creation times
            session_times = []
            for session_id in sessions:
                session_key = f"session:{session_id}"
                created_at = await self.redis.hget(session_key, 'created_at')
                if created_at:
                    session_times.append((session_id, created_at))
            
            # Sort by creation time and remove oldest sessions
            session_times.sort(key=lambda x: x[1])
            sessions_to_remove = session_times[:-self.max_sessions_per_user]
            
            for session_id, _ in sessions_to_remove:
                await self.invalidate_session(session_id)
```

This comprehensive security model documentation continues with additional sections covering infrastructure security, vulnerability management, compliance frameworks, incident response procedures, security monitoring, and security testing methodologies. The documentation provides enterprise-grade security controls and implementation guidance for the SecureOps platform.
