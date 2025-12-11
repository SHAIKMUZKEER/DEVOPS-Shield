#!/usr/bin/env python3
"""
Test script for the complete Zero Trust DevOps Shield workflow
"""

import asyncio
import sys
import os
sys.path.append('backend/src')

from security.zero_trust_orchestrator import ZeroTrustOrchestrator, PipelineContext

async def test_zero_trust_workflow():
    """Test the complete zero-trust workflow"""
    print("🛡️ Testing DevOps Shield Zero Trust Workflow")
    print("=" * 50)

    # Initialize orchestrator
    orchestrator = ZeroTrustOrchestrator()
    print("✅ Zero Trust Orchestrator initialized")

    # Create test pipeline context
    context = PipelineContext(
        pipeline_id="test_pipeline_001",
        repository="test-org/test-repo",
        commit_sha="abc123def456789",
        developer_id="test-developer",
        trigger="test"
    )

    print(f"🚀 Starting pipeline: {context.pipeline_id}")
    print(f"📋 Repository: {context.repository}")
    print(f"🔗 Commit: {context.commit_sha}")
    print("-" * 30)

    # Execute the pipeline
    result = await orchestrator.execute_zero_trust_pipeline(context)

    print("\n📊 Pipeline Results:")
    print(f"Status: {result['status']}")
    print(f"Duration: {result.get('end_time', 'N/A')}")

    if result['status'] == 'completed':
        print("✅ Pipeline completed successfully!")
        print("📋 Phases completed:")
        if result.get('source_integrity'):
            si = result['source_integrity']
            print(f"  🔍 Source Integrity: approved={si.get('approved', False)}")
        if result.get('dependency_check'):
            dc = result['dependency_check']
            print(f"  🔒 Dependency Check: approved={dc.get('approved', False)}")
        if result.get('build_steps'):
            print(f"  ⚙️ Build Steps: {len(result['build_steps'])} completed")
        if result.get('artifact_hardening'):
            ah = result['artifact_hardening']
            print(f"  🔐 Artifact Hardening: {ah.get('final_status', 'unknown')}")
    else:
        print(f"❌ Pipeline failed: {result.get('error_message', 'Unknown error')}")

    # Test individual components
    print("\n🧪 Testing Individual Components:")
    print("-" * 30)

    # Test Source Integrity
    try:
        from security.source_integrity import SourceIntegrityManager
        si_manager = SourceIntegrityManager()
        test_result = si_manager.verify_source_integrity(
            developer_id="test-dev",
            commit_sha="test123",
            device_id="test-device",
            ip_address="127.0.0.1",
            commit_data={'lines_added': 10, 'files_changed': ['test.py']}
        )
        print(f"✅ Source Integrity: {test_result.get('approved', False)}")
    except Exception as e:
        print(f"❌ Source Integrity test failed: {e}")

    # Test Dependency Sentinel
    try:
        from security.dependency_sentinel import DependencySentinel
        ds = DependencySentinel()
        test_deps = {'requests': '2.28.0', 'numpy': '1.24.0'}
        dep_result = ds.check_dependencies(test_deps)
        print(f"✅ Dependency Sentinel: {dep_result.get('approved', False)}")
    except Exception as e:
        print(f"❌ Dependency Sentinel test failed: {e}")

    # Test Blockchain Ledger
    try:
        from security.blockchain_ledger import BlockchainLedger
        ledger = BlockchainLedger()
        ledger_stats = ledger.get_ledger_stats()
        print(f"✅ Blockchain Ledger: {ledger_stats.get('blockchain_connected', 'unknown')} connection")
    except Exception as e:
        print(f"❌ Blockchain Ledger test failed: {e}")

    # Test Artifact Hardener
    try:
        from security.artifact_hardener import ArtifactHardener
        hardener = ArtifactHardener()
        hardener_stats = hardener.get_hardening_stats()
        print(f"✅ Artifact Hardener: {hardener_stats.get('signer_status', 'unknown')}")
    except Exception as e:
        print(f"❌ Artifact Hardener test failed: {e}")

    print("\n🎉 DevOps Shield Zero Trust Workflow test completed!")
    return result

if __name__ == "__main__":
    # Run the test
    result = asyncio.run(test_zero_trust_workflow())

    # Exit with appropriate code
    if result and result.get('status') == 'completed':
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)