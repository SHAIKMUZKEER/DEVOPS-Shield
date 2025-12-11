#!/usr/bin/env python3
"""
Script to populate database with large training dataset for fraud detection
This generates realistic fraud events, alerts, and analysis data
"""

import sqlite3
import random
import json
from datetime import datetime, timedelta
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

try:
    from src.services.db_service import DBService
    from src.utils.logger import get_logger
except ImportError as e:
    print(f"Warning: Could not import from backend: {e}")
    DBService = None
    logger = None

# Realistic data generators
RISK_LEVELS = ['critical', 'high', 'medium', 'low']
FRAUD_TYPES = [
    'unauthorized_access',
    'credential_exposure',
    'suspicious_deployment',
    'policy_violation',
    'malware_detection',
    'lateral_movement',
    'data_exfiltration',
    'privilege_escalation',
    'malicious_commit',
    'supply_chain_attack'
]

AUTHORS = [
    'abdul@devops.io',
    'security@company.io',
    'dev-team@company.io',
    'contractor@external.io',
    'bot-ci@company.io',
    'intern@company.io',
    'unknown-user',
    'service-account@company.io',
    'external-contributor@github.com'
]

REPOSITORIES = [
    'backend-api',
    'frontend-app',
    'infrastructure-code',
    'ml-models',
    'security-tools',
    'blockchain-contracts',
    'docker-images',
    'kubernetes-configs',
    'terraform-modules',
    'ansible-playbooks',
    'database-schemas',
    'microservices-core'
]

FILES_ACCESSED = [
    'config.yaml',
    'credentials.json',
    '.env',
    'secrets.vault',
    'private_key.pem',
    'database.sql',
    'deploy.sh',
    'docker-compose.yml',
    'requirements.txt',
    'package.json',
    'Dockerfile',
    'Jenkinsfile'
]

COMMIT_MESSAGES = [
    'Update configuration',
    'Fix security issue',
    'Add new feature',
    'Emergency hotfix',
    'Update dependencies',
    'Merge PR #123',
    'Revert changes',
    'Cleanup code',
    'Optimize performance',
    'Update documentation'
]

def generate_fraud_event(event_num):
    """Generate a realistic fraud event"""
    now = datetime.now()
    event_time = now - timedelta(hours=random.randint(0, 720), minutes=random.randint(0, 60))
    
    risk_score = round(random.uniform(0.1, 1.0), 2)
    risk_level = RISK_LEVELS[int(risk_score * 3)]
    
    return {
        'event_id': f'EVT-{event_num:08d}',
        'timestamp': event_time.isoformat(),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'fraud_type': random.choice(FRAUD_TYPES),
        'repository': random.choice(REPOSITORIES),
        'author': random.choice(AUTHORS),
        'commit_id': f'{random.randint(100000, 999999):x}'.lower()[:7],
        'commit_message': random.choice(COMMIT_MESSAGES),
        'files_accessed': random.sample(FILES_ACCESSED, k=random.randint(1, 4)),
        'suspicious_flags': random.sample([
            'unusual_time_access',
            'multiple_failed_logins',
            'suspicious_ip',
            'privilege_escalation_attempt',
            'high_data_transfer',
            'encrypted_payload',
            'known_malware_signature',
            'policy_violation'
        ], k=random.randint(1, 4)),
        'is_resolved': random.choice([True, False]) if random.random() > 0.7 else False,
        'resolved_by': random.choice(AUTHORS) if random.random() > 0.7 else None,
        'notes': f'Automated analysis - {risk_level} risk detected'
    }

def generate_alerts(num_events):
    """Generate alert records from fraud events"""
    alerts = []
    for i in range(num_events):
        event = generate_fraud_event(i)
        alert = {
            'alert_id': f'ALR-{i:08d}',
            'event_id': event['event_id'],
            'severity': 'critical' if event['risk_score'] > 0.8 else 'high' if event['risk_score'] > 0.5 else 'medium',
            'title': f"{event['fraud_type'].replace('_', ' ').title()} - {event['repository']}",
            'description': f"Potential {event['fraud_type']} in {event['repository']} by {event['author']}",
            'created_at': event['timestamp'],
            'updated_at': event['timestamp'],
            'is_acknowledged': random.choice([True, False]),
            'is_resolved': event['is_resolved']
        }
        alerts.append(alert)
    
    return alerts

def generate_stats():
    """Generate overall statistics"""
    return {
        'total_analyses': random.randint(1000, 5000),
        'high_risk_analyses': random.randint(50, 500),
        'critical_risk_analyses': random.randint(10, 100),
        'active_alerts': random.randint(5, 50),
        'resolved_alerts': random.randint(100, 1000),
        'average_risk_score': round(random.uniform(0.2, 0.7), 2),
        'success_rate': round(random.uniform(0.85, 0.99), 2)
    }

def populate_database(num_events=1000):
    """Populate database with training data"""
    print(f"Generating training dataset with {num_events} events...")
    
    # Use in-memory database for this script
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS fraud_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        risk_score REAL,
        fraud_type TEXT,
        repository TEXT,
        author TEXT,
        commit_id TEXT,
        data JSON
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        event_id TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        created_at TEXT,
        is_resolved BOOLEAN,
        data JSON
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS statistics (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        total_analyses INTEGER,
        high_risk_analyses INTEGER,
        average_risk_score REAL
    )
    ''')
    
    print(f"Creating {num_events} fraud events...")
    for i in range(num_events):
        event = generate_fraud_event(i)
        cursor.execute('''
        INSERT INTO fraud_events 
        (id, timestamp, risk_score, fraud_type, repository, author, commit_id, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event['event_id'],
            event['timestamp'],
            event['risk_score'],
            event['fraud_type'],
            event['repository'],
            event['author'],
            event['commit_id'],
            json.dumps(event)
        ))
        
        if (i + 1) % 100 == 0:
            print(f"  ✓ Created {i + 1} events...")
    
    print(f"Creating alerts...")
    alerts = generate_alerts(min(num_events, 500))  # Create alerts for subset
    for alert in alerts:
        cursor.execute('''
        INSERT INTO alerts 
        (id, event_id, severity, title, description, created_at, is_resolved, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert['alert_id'],
            alert['event_id'],
            alert['severity'],
            alert['title'],
            alert['description'],
            alert['created_at'],
            alert['is_resolved'],
            json.dumps(alert)
        ))
    print(f"  ✓ Created {len(alerts)} alerts")
    
    print(f"Creating statistics...")
    for i in range(30):  # 30 days of statistics
        stats = generate_stats()
        date = datetime.now() - timedelta(days=i)
        cursor.execute('''
        INSERT INTO statistics 
        (timestamp, total_analyses, high_risk_analyses, average_risk_score)
        VALUES (?, ?, ?, ?)
        ''', (
            date.isoformat(),
            stats['total_analyses'],
            stats['high_risk_analyses'],
            stats['average_risk_score']
        ))
    print(f"  ✓ Created 30 days of statistics")
    
    conn.commit()
    
    # Print summary
    cursor.execute('SELECT COUNT(*) FROM fraud_events')
    event_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alerts')
    alert_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM statistics')
    stat_count = cursor.fetchone()[0]
    
    print("\n" + "="*50)
    print("TRAINING DATASET SUMMARY")
    print("="*50)
    print(f"✓ Fraud Events:    {event_count:,}")
    print(f"✓ Alerts:          {alert_count:,}")
    print(f"✓ Statistics:      {stat_count} records")
    print(f"\nRisk Score Distribution:")
    
    cursor.execute('SELECT risk_score FROM fraud_events ORDER BY risk_score')
    scores = [row[0] for row in cursor.fetchall()]
    if scores:
        print(f"  Min:        {min(scores):.2f}")
        print(f"  Max:        {max(scores):.2f}")
        print(f"  Avg:        {sum(scores)/len(scores):.2f}")
    
    cursor.execute('SELECT fraud_type, COUNT(*) as count FROM fraud_events GROUP BY fraud_type ORDER BY count DESC LIMIT 5')
    print(f"\nTop Fraud Types:")
    for fraud_type, count in cursor.fetchall():
        print(f"  {fraud_type:30s} {count:4d}")
    
    conn.close()
    print("\n✅ Dataset generation complete!")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate training data for fraud detection')
    parser.add_argument('--events', type=int, default=1000, help='Number of fraud events to generate')
    args = parser.parse_args()
    
    try:
        populate_database(args.events)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
