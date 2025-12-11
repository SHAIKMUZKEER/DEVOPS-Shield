#!/usr/bin/env python3
"""
Test script to check if all imports work correctly
"""
import sys
import os
import pytest

BACKEND_DIR = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.join(BACKEND_DIR, 'src')

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

def test_imports():
    print("Testing imports...")

    try:
        # Test core imports
        from src.core.fraud_engine import FraudEngine
        print("✓ FraudEngine imported")

        from src.core.ai_analyzer import AIAnalyzer
        print("✓ AIAnalyzer imported")

        from src.core.rule_engine import RuleEngine
        print("✓ RuleEngine imported")

        from src.core.risk_scorer import RiskScorer
        print("✓ RiskScorer imported")

        # Test service imports
        from src.services.db_service import DBService
        print("✓ DBService imported")

        from src.services.gitlab_service import GitLabService
        print("✓ GitLabService imported")

        # Test API router imports
        from src.api.webhook_handler import router as webhook_router
        print("✓ Webhook router imported")

        from src.api.fraud_controller import router as fraud_router
        print("✓ Fraud router imported")

        from src.api.alerts_controller import router as alerts_router
        print("✓ Alerts router imported")

        # Test utils
        from src.utils.logger import get_logger
        print("✓ Logger imported")

        from src.utils.config import Config
        print("✓ Config imported")

        print("\n🎉 All imports successful!")

        # Test router contents
        print(f"\nRouter contents:")
        print(f"Webhook routes: {len(webhook_router.routes)}")
        print(f"Fraud routes: {len(fraud_router.routes)}")
        print(f"Alerts routes: {len(alerts_router.routes)}")

    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        pytest.fail(f"Import check failed: {e}")

if __name__ == "__main__":
    test_imports()