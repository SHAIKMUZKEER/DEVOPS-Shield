import React, { useMemo } from 'react';
import RunCard from '../components/RunCard';
import RiskBadge from '../components/RiskBadge';
import AlertsTable from '../components/AlertsTable';
import ImpactMetrics from '../components/ImpactMetrics.jsx';
import SecurityHighlights from '../components/SecurityHighlights.jsx';

const Dashboard = ({
  pipelines = [],
  runsByPipeline = {},
  alerts = [],
  impactMetrics = {},
  authSession,
  securityHighlights = [],
  onRunAction,
  onAlertAction,
  onSelectPipeline
}) => {
  const allRuns = useMemo(() => Object.values(runsByPipeline).flat(), [runsByPipeline]);
  const highestRiskRun = useMemo(() => [...allRuns].sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0))[0], [allRuns]);
  const overallRiskScore = Math.round(
    allRuns.reduce((acc, run) => acc + (run.risk?.score || 0), 0) / Math.max(allRuns.length, 1)
  );

  const topPipelines = pipelines.slice(0, 3);

  return (
    <div className="grid dashboard-grid">
      <section className="card span-2">
        <header className="card-header">
          <div>
            <h2>Live risk posture</h2>
            <p className="muted">CI/CD guardrails across {pipelines.length} pipelines.</p>
          </div>
          <RiskBadge score={overallRiskScore} size="lg" />
        </header>
        <div className="dashboard-metrics">
          <div>
            <span className="label">Active pipelines</span>
            <span>{pipelines.length}</span>
          </div>
          <div>
            <span className="label">High-risk incidents</span>
            <span>{alerts.filter((alert) => alert.severity === 'High' || alert.severity === 'Critical').length}</span>
          </div>
          <div>
            <span className="label">Malicious deploys blocked</span>
            <span>{impactMetrics.blockedMaliciousDeploys ?? 0}</span>
          </div>
          <div>
            <span className="label">Critical infra pipelines</span>
            <span>{pipelines.filter((p) => p.tags?.includes('civinfra')).length}</span>
          </div>
          <div>
            <span className="label">GitHub OAuth</span>
            <span>{authSession?.status ?? 'Unknown'}</span>
          </div>
          <div>
            <span className="label">PKCE enforced</span>
            <span>{authSession?.pkce ? 'Yes' : 'Review'}</span>
          </div>
        </div>
      </section>

      <section className="card span-2">
        <header className="card-header">
          <h2>Top watch pipelines</h2>
          <p className="muted">Focus on the pipelines shaping national scale services.</p>
        </header>
        <div className="top-pipelines">
          {topPipelines.map((pipeline) => (
            <button key={pipeline.id} type="button" className="top-pipeline-card" onClick={() => onSelectPipeline?.(pipeline.id)}>
              <div className="top-pipeline-card-header">
                <h3>{pipeline.name}</h3>
                <RiskBadge score={pipeline.lastRiskScore} level={pipeline.lastRiskLevel} />
              </div>
              <p className="muted">Last run status: {pipeline.lastStatus}</p>
              <div className="tags">
                {pipeline.tags?.map((tag) => <span key={tag} className="tag">{tag}</span>)}
              </div>
              <span className="btn-link" aria-hidden="true">View pipeline -&gt;</span>
            </button>
          ))}
        </div>
      </section>

      {highestRiskRun && (
        <RunCard run={highestRiskRun} onAction={onRunAction} />
      )}

      <AlertsTable alerts={alerts.slice(0, 3)} onAction={onAlertAction} />

      <ImpactMetrics data={impactMetrics} />

      <SecurityHighlights items={securityHighlights} />
    </div>
  );
};

export default Dashboard;
