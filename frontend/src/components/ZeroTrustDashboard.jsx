import React, { useEffect, useState } from 'react';
import zeroTrustService from '../api/zeroTrustService';
import './ZeroTrustDashboard.css';

const ZeroTrustDashboard = ({ onBack }) => {
  const [pipelineStage, setPipelineStage] = useState('idle');
  const [stageResults, setStageResults] = useState({
    sourceIntegrity: null,
    dependencySentinel: null,
    blockchainLedger: null,
    artifactHardening: null
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [lastRun, setLastRun] = useState(null);
  const [simulatedIncident, setSimulatedIncident] = useState(null);

  const commitInsights = React.useMemo(() => {
    const source = stageResults.sourceIntegrity;
    if (!source) return null;

    const score = Math.round(((source.identity_score ?? 0) * 100));
    const secretsFound = Boolean(source.secrets_found);
    const approved = Boolean(source.approved);
    const verdict = !secretsFound && approved && score >= 80 ? 'SAFE' : 'FRAUD ALERT';
    const riskBand = score >= 90 ? 'Low' : score >= 75 ? 'Elevated' : 'Critical';
    const summary = secretsFound
      ? 'Secrets leakage flagged in latest commit'
      : approved
        ? 'Identity profile consistent with training baseline'
        : 'Model ensemble denied source integrity approval';

    return {
      score,
      verdict,
      riskBand,
      summary,
      reasons: source.reasons || []
    };
  }, [stageResults.sourceIntegrity]);

  const stages = [
    {
      id: 'sourceIntegrity',
      title: 'Source Integrity',
      icon: '🔐',
      description: 'AI-driven behavioral analysis + secret scanning',
      protects: 'Uber/GitHub credential theft'
    },
    {
      id: 'dependencySentinel',
      title: 'Dependency Sentinel',
      icon: '🛡️',
      description: 'Namespace locking + hash verification',
      protects: 'PyTorch/Apple dependency confusion'
    },
    {
      id: 'blockchainLedger',
      title: 'Blockchain Ledger',
      icon: '⛓️',
      description: 'Tamper-proof audit trail',
      protects: 'SolarWinds/Codecov build tampering'
    },
    {
      id: 'artifactHardening',
      title: 'Artifact Hardening',
      icon: '✅',
      description: 'Cryptographic signing + sandbox verification',
      protects: 'Malware injection'
    }
  ];

  useEffect(() => {
    const checkHealth = async () => {
      try {
        await zeroTrustService.healthCheck();
        setBackendStatus('healthy');
      } catch (e) {
        setBackendStatus('down');
      }
    };
    checkHealth();
  }, []);

  const runZeroTrustPipeline = async () => {
    setLoading(true);
    setSimulatedIncident(null);
    const results = {};

    try {
      // Stage 1: Source Integrity
      setPipelineStage('sourceIntegrity');
      const sourceResp = await zeroTrustService.verifySourceIntegrity({
        developer_id: 'demo@company.com',
        commit_sha: 'abc123def456789',
        device_id: 'laptop-demo-001',
        ip_address: '192.168.1.100',
        timestamp: new Date().toISOString(),
        has_secrets: false
      });
      results.sourceIntegrity = sourceResp;
      setStageResults({ ...results });
      await sleep(1000);

      // Stage 2: Dependency Sentinel
      setPipelineStage('dependencySentinel');
      const depsData = await zeroTrustService.checkDependencies({
        'numpy': '1.21.0',
        'pandas': '1.3.0',
        'flask': '2.0.1'
      });
      results.dependencySentinel = depsData;
      setStageResults({ ...results });
      await sleep(1000);

      // Stage 3: Blockchain Ledger
      setPipelineStage('blockchainLedger');
      const ledgerData = await zeroTrustService.recordToBlockchain({
        step: 'build',
        hash: 'sha256:' + Math.random().toString(36).substring(7),
        previous_hash: 'sha256:genesis',
        metadata: {
          commit_sha: 'abc123def456789',
          timestamp: new Date().toISOString(),
          environment: 'production'
        }
      });
      results.blockchainLedger = ledgerData;
      setStageResults({ ...results });
      await sleep(1000);

      // Stage 4: Artifact Hardening
      setPipelineStage('artifactHardening');
      const artifactData = await zeroTrustService.verifyArtifact({
        artifact_hash: 'sha256:final-artifact-' + Math.random().toString(36).substring(7),
        signature: '-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2\n...\n-----END PGP SIGNATURE-----'
      });
      results.artifactHardening = artifactData;
      setStageResults({ ...results });

      setPipelineStage('completed');
      setLastRun({ status: 'success', at: new Date().toISOString() });
    } catch (error) {
      console.error('Pipeline error:', error);
      setError(error.message || 'Pipeline failed. Check backend connection at http://localhost:8000');
      setPipelineStage('failed');
      setLastRun({ status: 'failed', at: new Date().toISOString() });
    } finally {
      setLoading(false);
    }
  };

  const simulateBreachScenario = () => {
    setSimulatedIncident({
      title: 'Production Supply-Chain Injection Blocked',
      detail: '@supply-chain/stealth-kit detected during dependencySentinel (prod mirror)',
      action: 'Build quarantined, runner token revoked, signing keys rotated',
      status: 'BLOCKED',
      triggeredAt: new Date().toISOString()
    });
    setPipelineStage('failed');
    setError('Simulated breach captured — pipeline halted');
    setLastRun({ status: 'failed', at: new Date().toISOString() });
  };

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  const getStageStatus = (stageId) => {
    const result = stageResults[stageId];
    if (!result) return 'pending';
    if (stageId === 'sourceIntegrity' && result.approved) return 'success';
    if (stageId === 'dependencySentinel' && result.approved) return 'success';
    if (stageId === 'blockchainLedger' && result.recorded) return 'success';
    if (stageId === 'artifactHardening' && result.approved) return 'success';
    return 'warning';
  };

  return (
    <div className="zero-trust-dashboard">
      <div className="dashboard-header">
        {onBack && (
          <button className="dashboard-back" onClick={onBack} type="button">
            ← Back to overview
          </button>
        )}
        <h1>🛡️ Zero Trust CI/CD Pipeline</h1>
        <p className="subtitle">Immutable Security Layer: Commit -> Build -> Deploy</p>
      </div>

      <div className="status-grid">
        <div className={`status-card ${backendStatus === 'healthy' ? 'status-ok' : 'status-bad'}`}>
          <div className="status-label">Backend</div>
          <div className="status-value">{backendStatus === 'healthy' ? 'Healthy' : backendStatus === 'checking' ? 'Checking…' : 'Unavailable'}</div>
          <div className="status-sub">http://localhost:8000</div>
        </div>
        <div className="status-card">
          <div className="status-label">Last Run</div>
          <div className="status-value">{lastRun ? (lastRun.status === 'success' ? 'Success' : 'Blocked') : 'Not run yet'}</div>
          <div className="status-sub">{lastRun ? new Date(lastRun.at).toLocaleString() : 'Run the pipeline to view results'}</div>
        </div>
        <div className="status-card">
          <div className="status-label">Simulation</div>
          <div className={`status-value ${simulatedIncident ? 'status-risk' : ''}`}>{simulatedIncident ? simulatedIncident.status : 'Production-grade'}</div>
          <div className="status-sub">Trigger a red-team failure</div>
        </div>
        <div className="status-card commit-score-card">
          <div className="status-label">Commit Trust</div>
          <div className={`status-value ${commitInsights ? (commitInsights.verdict === 'SAFE' ? 'status-good' : 'status-risk') : ''}`}>
            {commitInsights ? `${commitInsights.score}%` : 'Pending'}
          </div>
          <div className="status-sub">
            {commitInsights
              ? `${commitInsights.verdict} • ${commitInsights.riskBand} risk`
              : 'Run the pipeline to score the latest commit'}
          </div>
          {commitInsights && (
            <div className="status-sub secondary-line">{commitInsights.summary}</div>
          )}
          {commitInsights?.reasons?.length > 0 && (
            <ul className="status-reasons">
              {commitInsights.reasons.slice(0, 2).map((reason, idx) => (
                <li key={idx}>{reason}</li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div className="simulation-panel">
        <div className="simulation-header">
          <h2>Attack Simulation</h2>
          <span className={`badge ${simulatedIncident ? 'badge-blocked' : 'badge-idle'}`}>
            {simulatedIncident ? simulatedIncident.status : 'IDLE'}
          </span>
        </div>
        <p className="simulation-overview">
          Launch the breach drill to validate that automated containment kicks in before production is impacted.
        </p>
        {simulatedIncident ? (
          <ul className="simulation-details">
            <li><strong>Scenario:</strong> {simulatedIncident.title}</li>
            <li><strong>Signal:</strong> {simulatedIncident.detail}</li>
            <li><strong>Response:</strong> {simulatedIncident.action}</li>
            <li><strong>Detected:</strong> {new Date(simulatedIncident.triggeredAt).toLocaleTimeString()}</li>
          </ul>
        ) : (
          <div className="simulation-placeholder">
            No active incidents. Use the breach simulation to rehearse your incident playbook.
          </div>
        )}
      </div>

      <div className="pipeline-flow">
        {stages.map((stage, index) => (
          <div key={stage.id} className="pipeline-stage-container">
            <div 
              className={`pipeline-stage ${
                pipelineStage === stage.id ? 'active' : 
                getStageStatus(stage.id) === 'success' ? 'completed' :
                getStageStatus(stage.id) === 'warning' ? 'warning' : ''
              }`}
            >
              <div className="stage-icon">{stage.icon}</div>
              <h3>{stage.title}</h3>
              <p className="stage-description">{stage.description}</p>
              <div className="stage-protects">
                <strong>Protects Against:</strong> {stage.protects}
              </div>

              {stageResults[stage.id] && (
                <div className="stage-result">
                  {stage.id === 'sourceIntegrity' && (
                    <>
                      <div className="result-item">
                        <span>Identity Score:</span>
                        <span className={stageResults[stage.id].identity_score > 0.8 ? 'success' : 'warning'}>
                          {(stageResults[stage.id].identity_score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Secrets Found:</span>
                        <span className={stageResults[stage.id].secrets_found ? 'error' : 'success'}>
                          {stageResults[stage.id].secrets_found ? '❌ Yes' : '✅ No'}
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Status:</span>
                        <span className={stageResults[stage.id].approved ? 'success' : 'error'}>
                          {stageResults[stage.id].approved ? '✅ APPROVED' : '❌ BLOCKED'}
                        </span>
                      </div>
                    </>
                  )}
                  {stage.id === 'dependencySentinel' && (
                    <>
                      <div className="result-item">
                        <span>Packages Checked:</span>
                        <span>3</span>
                      </div>
                      <div className="result-item">
                        <span>Blocked Packages:</span>
                        <span className={stageResults[stage.id].blocked_packages.length > 0 ? 'warning' : 'success'}>
                          {stageResults[stage.id].blocked_packages.length}
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Status:</span>
                        <span className={stageResults[stage.id].approved ? 'success' : 'warning'}>
                          {stageResults[stage.id].approved ? '✅ CLEAN' : '⚠️ BLOCKED'}
                        </span>
                      </div>
                    </>
                  )}
                  {stage.id === 'blockchainLedger' && (
                    <>
                      <div className="result-item">
                        <span>Recorded:</span>
                        <span className="success">
                          {stageResults[stage.id].recorded ? '✅ Yes' : '❌ No'}
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Chain Valid:</span>
                        <span className="success">
                          {stageResults[stage.id].chain_valid ? '✅ Yes' : '❌ No'}
                        </span>
                      </div>
                    </>
                  )}
                  {stage.id === 'artifactHardening' && (
                    <>
                      <div className="result-item">
                        <span>Signed:</span>
                        <span className="success">
                          {stageResults[stage.id].signed ? '✅ Yes' : '❌ No'}
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Sandbox Verified:</span>
                        <span className="success">
                          {stageResults[stage.id].sandbox_verified ? '✅ Yes' : '❌ No'}
                        </span>
                      </div>
                      <div className="result-item">
                        <span>Status:</span>
                        <span className={stageResults[stage.id].approved ? 'success' : 'error'}>
                          {stageResults[stage.id].approved ? '✅ APPROVED' : '❌ BLOCKED'}
                        </span>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
            {index < stages.length - 1 && (
              <div className="pipeline-arrow">-&gt;</div>
            )}
          </div>
        ))}
      </div>

      <div className="pipeline-controls">
        <button 
          className="btn-primary"
          onClick={runZeroTrustPipeline}
          disabled={loading}
        >
          {loading ? '🔄 Running Pipeline...' : '▶️ Run Zero Trust Pipeline'}
        </button>

        <button
          className="btn-secondary"
          onClick={simulateBreachScenario}
          disabled={loading}
        >
          🚨 Launch Breach Drill
        </button>
        
        {error && (
          <div className="pipeline-error">
            ⚠️ {error}
            <div style={{fontSize: '0.85rem', marginTop: '8px', opacity: 0.8}}>
              Ensure backend is running at http://localhost:8000
            </div>
          </div>
        )}
        
        {pipelineStage === 'completed' && (
          <div className="pipeline-complete">
            ✅ Pipeline Complete - Deployment Authorized
          </div>
        )}
        {pipelineStage === 'failed' && !error && (
          <div className="pipeline-failed">
            ❌ Pipeline Failed - Deployment Blocked
          </div>
        )}
      </div>
    </div>
  );
};

export default ZeroTrustDashboard;
