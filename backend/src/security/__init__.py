"""
Security Module
Comprehensive security features for DevOps-Shield
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .auth_manager import (
    auth_manager,
    TokenManager,
    PasswordManager,
    MFAManager,
    RBACManager,
    AuthenticationManager,
    UserRole,
    get_current_user
)

from .webhook_security import (
    webhook_signature_verifier,
    input_sanitizer,
    payload_validator,
    webhook_rate_limiter,
    WebhookSignatureVerifier,
    InputSanitizer,
    PayloadValidator,
    WebhookRateLimiter
)

from .audit_logger import (
    immutable_audit_logger,
    security_audit_logger,
    AuditEventType,
    AuditLogEntry,
    ImmutableAuditLogger,
    SecurityAuditLogger
)

from .model_security import (
    model_security_manager,
    ModelSecurityManager,
    DataValidator,
    PoisonDetector
)

from .incident_response import (
    security_monitor,
    incident_response,
    IncidentType,
    SeverityLevel,
    SecurityMonitor,
    IncidentResponsePlaybook
)

from .secrets_manager import (
    secret_vault,
    environment_manager,
    secret_rotation_service,
    SecretVault,
    EnvironmentManager,
    SecretRotationService,
    SecretType
)

from .backup_recovery import (
    backup_manager,
    database_backup,
    BackupManager,
    DatabaseBackup,
    BackupType
)


from .source_integrity import (
    SourceIntegrityManager,
    DeveloperProfile,
    PreCommitSecretsScanner
)

from .dependency_sentinel import (
    DependencySentinel,
    NamespaceLock,
    SupplyChainAnalyzer
)

from .blockchain_ledger import (
    BlockchainLedger,
    BuildPipeline,
    BuildStep
)

from .artifact_hardener import (
    ArtifactHardener,
    CryptographicSigner,
    IsolatedEnvironment,
    MalwareScanner
)

from .zero_trust_orchestrator import (
    ZeroTrustOrchestrator,
    PipelineContext
)

from .performance_cache import (
    performance_optimizer,
    SecurityCache,
    AsyncTaskManager
)

from .adaptive_thresholds import (
    adaptive_thresholds,
    AdaptiveThresholdManager
)

__all__ = [
    # Auth
    "auth_manager",
    "TokenManager",
    "PasswordManager",
    "MFAManager",
    "RBACManager",
    "AuthenticationManager",
    "UserRole",
    "get_current_user",
    
    # Webhooks
    "webhook_signature_verifier",
    "input_sanitizer",
    "payload_validator",
    "webhook_rate_limiter",
    "WebhookSignatureVerifier",
    "InputSanitizer",
    "PayloadValidator",
    "WebhookRateLimiter",
    
    # Audit
    "immutable_audit_logger",
    "security_audit_logger",
    "AuditEventType",
    "AuditLogEntry",
    "ImmutableAuditLogger",
    "SecurityAuditLogger",
    
    # ML Security
    "model_security_manager",
    "ModelSecurityManager",
    "DataValidator",
    "PoisonDetector",
    
    # Incidents
    "security_monitor",
    "incident_response",
    "IncidentType",
    "SeverityLevel",
    "SecurityMonitor",
    "IncidentResponsePlaybook",
    
    # Secrets
    "secret_vault",
    "environment_manager",
    "secret_rotation_service",
    "SecretVault",
    "EnvironmentManager",
    "SecretRotationService",
    "SecretType",
    
    # Backups
    "backup_manager",
    "database_backup",
    "BackupManager",
    "DatabaseBackup",
    "BackupType",
    

    # Source Integrity
    "SourceIntegrityManager",
    "DeveloperProfile",
    "PreCommitSecretsScanner",

    # Dependency Sentinel
    "DependencySentinel",
    "NamespaceLock",
    "SupplyChainAnalyzer",

    # Blockchain Ledger
    "BlockchainLedger",
    "BuildPipeline",
    "BuildStep",

    # Artifact Hardener
    "ArtifactHardener",
    "CryptographicSigner",
    "IsolatedEnvironment",
    "MalwareScanner",

    # Zero Trust Orchestrator
    "ZeroTrustOrchestrator",
    "PipelineContext",

    # Performance Cache
    "performance_optimizer",
    "SecurityCache",
    "AsyncTaskManager",

    # Adaptive Thresholds
    "adaptive_thresholds",
    "AdaptiveThresholdManager"
]
