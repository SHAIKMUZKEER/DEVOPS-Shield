#!/usr/bin/env python3
"""
Test DevOps-Shield Zero Trust API Endpoints Locally
"""
import requests
import json
from datetime import datetime
import time

BASE_URL = "http://localhost:8000"

def test_source_integrity():
    """Test Source Integrity endpoint"""
    print("\n=== Testing Source Integrity ===")
    payload = {
        "developer_id": "alice@company.com",
        "commit_sha": "abc123def456789",
        "device_id": "laptop-xyz789",
        "ip_address": "192.168.1.100",
        "timestamp": datetime.utcnow().isoformat(),
        "has_secrets": False
    }
    try:
        resp = requests.post(f"{BASE_URL}/api/zero-trust/source/verify", json=payload, timeout=5)
        print(f"Status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.json(), indent=2)}")
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_dependency_sentinel():
    """Test Dependency Sentinel endpoint"""
    print("\n=== Testing Dependency Sentinel ===")
    payload = {
        "manifest": {
            "numpy": "1.21.0",
            "pandas": "1.3.0",
            "flask": "2.0.1",
            "pytorch-malicious": "1.0.0"  # Should be blocked
        }
    }
    try:
        resp = requests.post(f"{BASE_URL}/api/zero-trust/deps/check", json=payload, timeout=5)
        print(f"Status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.json(), indent=2)}")
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_blockchain_ledger():
    """Test Blockchain Ledger endpoint"""
    print("\n=== Testing Blockchain Ledger ===")
    payload = {
        "step": "build",
        "hash": "sha256:abc123def456",
        "previous_hash": "sha256:xyz789abc123",
        "metadata": {
            "commit_sha": "abc123def456789",
            "build_duration": 45.2,
            "environment": "production"
        }
    }
    try:
        resp = requests.post(f"{BASE_URL}/api/zero-trust/ledger/record", json=payload, timeout=5)
        print(f"Status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.json(), indent=2)}")
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_artifact_hardening():
    """Test Artifact Hardening endpoint"""
    print("\n=== Testing Artifact Hardening ===")
    payload = {
        "artifact_hash": "sha256:artifact123456789",
        "signature": "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2...\n-----END PGP SIGNATURE-----"
    }
    try:
        resp = requests.post(f"{BASE_URL}/api/zero-trust/artifact/verify", json=payload, timeout=5)
        print(f"Status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.json(), indent=2)}")
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_data_endpoints():
    """Test data API endpoints"""
    print("\n=== Testing Data Endpoints ===")
    all_passed = True
    
    print("\n-- Real World Security Scenarios --")
    try:
        resp = requests.get(f"{BASE_URL}/api/data/real_world_security_scenarios", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"Scenarios: {len(data.get('scenarios', []))} found")
            if data.get('scenarios'):
                print(f"  - {data['scenarios'][0]['title']}")
        else:
            all_passed = False
    except Exception as e:
        print(f"Error: {e}")
        all_passed = False
    
    print("\n-- Blockchain Trust Architecture --")
    try:
        resp = requests.get(f"{BASE_URL}/api/data/blockchain_trust_architecture", timeout=5)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            layers = data.get('trust_layers')
            print(f"Trust layers: {layers}")
        else:
            all_passed = False
    except Exception as e:
        print(f"Error: {e}")
        all_passed = False
    
    return all_passed

def main():
    print("=" * 60)
    print("DevOps-Shield Zero Trust API Test Suite")
    print("=" * 60)
    print(f"Base URL: {BASE_URL}")
    print(f"Time: {datetime.utcnow().isoformat()}")
    
    # Give server time to start
    time.sleep(1)
    
    # Check health
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"\nHealth Check: {resp.status_code} - {resp.json()}")
    except Exception as e:
        print(f"\nHealth Check Failed: {e}")
        print("⚠ Backend not running. Make sure to start: python backend/main.py")
        return
    
    # Run tests
    results = {
        "source_integrity": test_source_integrity(),
        "dependency_sentinel": test_dependency_sentinel(),
        "blockchain_ledger": test_blockchain_ledger(),
        "artifact_hardening": test_artifact_hardening(),
        "data_endpoints": test_data_endpoints(),
    }
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")

if __name__ == "__main__":
    main()
