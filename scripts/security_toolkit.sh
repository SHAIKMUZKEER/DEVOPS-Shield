#!/bin/bash
#
# DevOps-Shield Security & Incident Response Scripts
# Comprehensive toolkit for deployment, monitoring, and incident handling
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PYTHON_CMD="python3"

echo "=== DevOps-Shield Security Toolkit ==="
echo "Project Root: $PROJECT_ROOT"

# ===== COLOR CODES =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===== LOGGING FUNCTIONS =====
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ===== SECURITY DEPLOYMENT =====
deploy_secure() {
    log_info "Starting secure deployment..."
    
    # 1. Build images
    log_info "Building Docker images..."
    docker-compose build --no-cache
    log_success "Docker images built"
    
    # 2. Setup secrets
    log_info "Initializing secrets vault..."
    $PYTHON_CMD -c "
from src.security.secrets_manager import secret_vault, SecretType
import os
import secrets

# Generate and store secrets
webhook_secret = os.getenv('WEBHOOK_SECRET', secrets.token_urlsafe(32))
jwt_secret = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))

secret_vault.store_secret('WEBHOOK_SECRET', webhook_secret, SecretType.WEBHOOK_SECRET)
secret_vault.store_secret('JWT_SECRET', jwt_secret, SecretType.JWT_SECRET)
print('Secrets initialized')
"
    log_success "Secrets vault configured"
    
    # 3. Initialize database
    log_info "Initializing database..."
    $PYTHON_CMD scripts/init_db.py
    log_success "Database initialized"
    
    # 4. Create initial backup
    log_info "Creating initial backup..."
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager, database_backup
success, backup_id = backup_manager.create_backup('database/', 'full')
if success:
    print(f'Backup created: {backup_id}')
else:
    print(f'Backup failed: {backup_id}')
"
    log_success "Initial backup created"
    
    # 5. Start services
    log_info "Starting services..."
    docker-compose up -d
    log_success "Services started"
    
    # 6. Verify deployment
    log_info "Verifying deployment..."
    sleep 5
    
    if curl -s http://localhost:8000/health > /dev/null; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        exit 1
    fi
    
    log_success "Secure deployment completed"
}

# ===== INCIDENT RESPONSE: UNAUTHORIZED ACCESS =====
respond_to_breach() {
    log_warning "Starting incident response for breach..."
    log_warning "This is a CRITICAL incident response"
    
    # Step 1: Isolate
    log_info "Step 1: Isolating system (IMMEDIATE ACTION)..."
    docker-compose down
    log_success "System isolated - all services stopped"
    
    # Step 2: Revoke credentials
    log_info "Step 2: Revoking all access..."
    $PYTHON_CMD -c "
from src.security.secrets_manager import secret_vault
from src.security.auth_manager import auth_manager

# Invalidate all tokens (in production, implement token blacklist)
log_info('Clearing cached tokens...')

# Generate new JWT secret
import secrets
new_jwt = secrets.token_urlsafe(32)
secret_vault.rotate_secret('JWT_SECRET', new_jwt)
print('JWT secret rotated')
"
    log_success "Credentials revoked"
    
    # Step 3: Analyze logs
    log_info "Step 3: Analyzing audit logs..."
    $PYTHON_CMD -c "
from src.security.audit_logger import immutable_audit_logger
import json

# Export logs for analysis
logs = immutable_audit_logger.get_logs(limit=999999)
with open('incident_logs_$(date +%s).json', 'w') as f:
    json.dump(logs, f, indent=2)
print(f'Exported {len(logs)} audit logs')

# Verify integrity
report = immutable_audit_logger.verify_integrity()
print(f'Log integrity: {report[\"status\"]}')
"
    log_success "Logs analyzed"
    
    # Step 4: Identify compromised resources
    log_info "Step 4: Identifying compromised resources..."
    log_warning "MANUAL REVIEW REQUIRED - Examine exported logs for:"
    log_warning "  - Unauthorized API calls"
    log_warning "  - Data access from unknown IPs"
    log_warning "  - Privilege escalation attempts"
    log_warning "  - Lateral movement indicators"
    
    # Step 5: Restore from backup
    log_info "Step 5: Preparing clean backup restoration..."
    log_warning "Select clean backup (before compromise timestamp):"
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

backups = backup_manager.list_backups(limit=10)
for i, backup in enumerate(backups):
    print(f'  {i+1}. {backup[\"backup_id\"]} - {backup[\"created_at\"]}')
"
    
    log_warning "Run: restore_from_backup <backup_id>"
    
    # Step 6: Harden system
    log_info "Step 6: Hardening system before restart..."
    log_warning "Perform these actions BEFORE redeployment:"
    log_warning "  1. Review and update firewall rules"
    log_warning "  2. Rotate all secrets and keys"
    log_warning "  3. Update all dependencies"
    log_warning "  4. Apply security patches"
    log_warning "  5. Review and patch vulnerability"
    
    log_warning "Run: harden_system"
    
    log_warning "INCIDENT RESPONSE INITIATED - MANUAL STEPS REQUIRED"
}

# ===== RESTORE FROM BACKUP =====
restore_from_backup() {
    local backup_id=$1
    
    if [ -z "$backup_id" ]; then
        log_error "Usage: $0 restore_from_backup <backup_id>"
        exit 1
    fi
    
    log_warning "Restoring from backup: $backup_id"
    log_warning "This will overwrite current data!"
    read -p "Type 'YES' to confirm: " confirm
    
    if [ "$confirm" != "YES" ]; then
        log_info "Restore cancelled"
        return
    fi
    
    log_info "Verifying backup integrity..."
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

success, message = backup_manager.verify_backup('$backup_id')
if success:
    print('Backup verified - proceeding with restore')
else:
    print(f'Backup verification failed: {message}')
    exit(1)
"
    
    log_info "Restoring backup..."
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

success, message = backup_manager.restore_backup('$backup_id', 'database/')
if success:
    print(f'Restore successful: {message}')
else:
    print(f'Restore failed: {message}')
    exit(1)
"
    
    log_success "Restore completed"
}

# ===== HARDEN SYSTEM =====
harden_system() {
    log_info "Hardening system for redeployment..."
    
    # 1. Update dependencies
    log_info "Updating dependencies..."
    pip install -r backend/requirements.txt --upgrade
    log_success "Dependencies updated"
    
    # 2. Rotate secrets
    log_info "Rotating all secrets..."
    $PYTHON_CMD -c "
from src.security.secrets_manager import secret_rotation_service

results = secret_rotation_service.rotate_all_due_secrets()
for secret, success in results.items():
    status = 'OK' if success else 'FAILED'
    print(f'  {secret}: {status}')
"
    log_success "Secrets rotated"
    
    # 3. Generate new encryption keys
    log_info "Generating new encryption keys..."
    $PYTHON_CMD -c "
import secrets
from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open('.env.security', 'w') as f:
    f.write(f'MASTER_KEY={key.decode()}\\n')
    
print('New encryption keys generated')
"
    log_success "Encryption keys updated"
    
    # 4. Verify audit log integrity
    log_info "Verifying audit log integrity..."
    $PYTHON_CMD -c "
from src.security.audit_logger import immutable_audit_logger

report = immutable_audit_logger.verify_integrity()
if report['status'] == 'passed':
    print(f'Audit logs verified: {report[\"total_logs\"]} entries')
else:
    print(f'⚠ Audit log anomalies detected: {len(report[\"invalid_signatures\"])} invalid signatures')
"
    log_success "System hardened"
    
    log_warning "Next step: redeploy_secure"
}

# ===== BACKUP MANAGEMENT =====
create_backup() {
    log_info "Creating backup..."
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager, database_backup

# Backup application data
success, backup_id = backup_manager.create_backup('backend/', 'full')
if success:
    print(f'Application backup: {backup_id}')
else:
    print(f'Application backup failed: {backup_id}')
    exit(1)

# Backup database
success, filepath = database_backup.backup_database('database/fraud_logs.db')
if success:
    print(f'Database backup: {filepath}')
else:
    print(f'Database backup failed: {filepath}')
    exit(1)
"
    log_success "Backup completed"
}

list_backups() {
    log_info "Available backups:"
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

backups = backup_manager.list_backups(limit=20)
print(f'Total backups: {len(backups)}\\n')

for backup in backups:
    size_mb = backup['size_bytes'] / (1024*1024)
    print(f\"  {backup['backup_id']}\")
    print(f\"    Created: {backup['created_at']}\")
    print(f\"    Size: {size_mb:.2f} MB\")
    print(f\"    Files: {backup['file_count']}\")
    print(f\"    Expires: {backup['expiration_date']}\")
    print()
"
}

verify_backup() {
    local backup_id=$1
    
    if [ -z "$backup_id" ]; then
        log_error "Usage: $0 verify_backup <backup_id>"
        exit 1
    fi
    
    log_info "Verifying backup: $backup_id"
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

success, message = backup_manager.verify_backup('$backup_id')
if success:
    print(f'✓ Backup verified: {message}')
else:
    print(f'✗ Verification failed: {message}')
    exit(1)
"
}

# ===== MONITORING & ALERTS =====
check_security_status() {
    log_info "Checking security status..."
    
    echo ""
    log_info "=== Authentication & Access ==="
    $PYTHON_CMD -c "
from src.security.auth_manager import auth_manager
print(f'  Failed login threshold: {auth_manager.max_failed_attempts}')
print(f'  Lockout duration: {auth_manager.lockout_duration} minutes')
print(f'  Active lockouts: {len([k for k in auth_manager.failed_logins.keys() if \"_locked_until\" in k])}')
"
    
    echo ""
    log_info "=== Audit Logging ==="
    $PYTHON_CMD -c "
from src.security.audit_logger import immutable_audit_logger

report = immutable_audit_logger.verify_integrity()
print(f'  Total audit logs: {report[\"total_logs\"]}')
print(f'  Integrity status: {report[\"status\"]}')
print(f'  Tampering detected: {report[\"tampering_detected\"]}')
if report['tampering_detected']:
    print(f'  ⚠ Invalid signatures: {len(report[\"invalid_signatures\"])}')
"
    
    echo ""
    log_info "=== Security Incidents ==="
    $PYTHON_CMD -c "
from src.security.incident_response import security_monitor

incidents = security_monitor.get_incidents(status='open', limit=10)
if incidents:
    print(f'  Open incidents: {len(incidents)}')
    for incident in incidents:
        print(f'    - {incident[\"id\"]}: {incident[\"title\"]} ({incident[\"severity\"]})')
else:
    print('  No open incidents')

alerts = security_monitor.get_recent_alerts(limit=5, severity='high')
if alerts:
    print(f'  Recent high-severity alerts: {len(alerts)}')
else:
    print('  No high-severity alerts')
"
    
    echo ""
    log_info "=== Secrets Management ==="
    $PYTHON_CMD -c "
from src.security.secrets_manager import secret_vault

due = secret_vault.get_rotation_due()
if due:
    print(f'  ⚠ Secrets due for rotation: {len(due)}')
    for name in due:
        print(f'    - {name}')
else:
    print('  All secrets are current')
"
    
    echo ""
    log_info "=== Backups ==="
    $PYTHON_CMD -c "
from src.security.backup_recovery import backup_manager

backups = backup_manager.list_backups(limit=3)
if backups:
    latest = backups[0]
    print(f'  Latest backup: {latest[\"backup_id\"]}')
    print(f'  Created: {latest[\"created_at\"]}')
    size_mb = latest['size_bytes'] / (1024*1024)
    print(f'  Size: {size_mb:.2f} MB')
else:
    print('  ⚠ No backups found!')
"
}

# ===== MAIN COMMAND HANDLER =====
case "${1}" in
    deploy)
        deploy_secure
        ;;
    incident)
        respond_to_breach
        ;;
    restore)
        restore_from_backup "$2"
        ;;
    harden)
        harden_system
        ;;
    backup)
        create_backup
        ;;
    list-backups)
        list_backups
        ;;
    verify-backup)
        verify_backup "$2"
        ;;
    status)
        check_security_status
        ;;
    *)
        echo "DevOps-Shield Security Toolkit"
        echo ""
        echo "Usage: $0 <command> [arguments]"
        echo ""
        echo "Commands:"
        echo "  deploy              - Deploy system with security hardening"
        echo "  incident            - Initiate incident response procedure"
        echo "  restore <backup_id> - Restore from backup"
        echo "  harden              - Harden system before redeployment"
        echo "  backup              - Create backup"
        echo "  list-backups        - List all backups"
        echo "  verify-backup <id>  - Verify backup integrity"
        echo "  status              - Check security status"
        echo ""
        exit 1
        ;;
esac
