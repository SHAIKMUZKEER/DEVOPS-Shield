import React, { useMemo, useState } from 'react';
import RiskBadge from '../components/RiskBadge';
import RiskGraph from '../components/RiskGraph';
import zeroTrustService from '../api/zeroTrustService';
import { formatDateTime } from '../utils/dateHelpers';

const eventTemplates = {
  'supply-chain': [
    { phase: 'Intelligence', detail: 'Unknown package version uploaded to private registry.' },
    { phase: 'Build', detail: 'Dependency Sentinel detects hash mismatch versus SBOM baseline.' },
    { phase: 'Signing', detail: 'Artifact Hardening rejects unsigned binary and quarantines output.' },
    { phase: 'Response', detail: 'Runner token revoked, maintainers alerted, incident ticket created.' }
  ],
  'secret-leak': [
    { phase: 'Build', detail: 'Log sanitization rules flag PAT string inside test output.' },
    { phase: 'Source Integrity', detail: 'Identity model lowers trust score due to leaked token usage.' },
    { phase: 'Response', detail: 'Credential revoked and SIEM notified for downstream investigation.' }
  ],
  'rogue-runner': [
    { phase: 'Provision', detail: 'New runner joined with unrecognized fingerprint and outdated kernel patches.' },
    { phase: 'Behaviour', detail: 'Behavioral AI flags inconsistent command invocation pattern.' },
    { phase: 'Containment', detail: 'Runner isolated, PKCE challenge re-authenticates maintainer, SOC escalated.' }
  ]
};

const Simulation = ({ scenarios = [], history = [] }) => {
  const [riskHistory, setRiskHistory] = useState(history);
  const [activeScenarioId, setActiveScenarioId] = useState(null);
  const [events, setEvents] = useState([]);
  const [loadingScenario, setLoadingScenario] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [lastRunAt, setLastRunAt] = useState(null);

  const activeScenario = useMemo(
    () => scenarios.find((scenario) => scenario.id === activeScenarioId) || null,
    [scenarios, activeScenarioId]
  );

  const runScenario = async (scenario) => {
    setLoadingScenario(true);
    setActiveScenarioId(scenario.id);
    setEvents([]);

    try {
      await zeroTrustService.healthCheck();
      setBackendStatus('healthy');
    } catch (error) {
      console.error('Health check failed before simulation', error);
      setBackendStatus('unavailable');
    }

    const template = eventTemplates[scenario.id] || [];
    const generatedEvents = template.map((step, index) => ({
      ...step,
      timestamp: new Date(Date.now() + index * 1000).toISOString()
    }));

    setEvents(generatedEvents);

    const riskPoint = {
      date: new Date().toISOString().split('T')[0],
      riskScore: Math.min(1, Math.max(0, scenario.riskScore / 100)),
      analyses: 24 + Math.floor(Math.random() * 8),
      alerts: Math.max(1, Math.round(scenario.riskScore / 20))
    };

    setRiskHistory((prev) => [...prev, riskPoint]);
    setLastRunAt(new Date().toISOString());
    setLoadingScenario(false);
  };

  const resetSimulation = () => {
    setActiveScenarioId(null);
    setEvents([]);
    setLastRunAt(null);
  };

  return (
    <div className="simulation-page">
      <section className="card simulation-hero">
        <header className="card-header">
          <div>
            <h2>Attack simulation lab</h2>
            <p className="muted">Recreate real-world supply-chain incidents and watch DevOps Shield contain the breach in real time.</p>
          </div>
          {activeScenario && <RiskBadge score={activeScenario.riskScore} level={activeScenario.type} size="lg" />}
        </header>
        <div className="simulation-meta">
          <div>
            <span className="label">Backend status</span>
            <span>{backendStatus}</span>
          </div>
          <div>
            <span className="label">Last drill</span>
            <span>{lastRunAt ? formatDateTime(lastRunAt) : 'Not run yet'}</span>
          </div>
          <div>
            <span className="label">Risk history points</span>
            <span>{riskHistory.length}</span>
          </div>
        </div>
        <div className="simulation-actions">
          {scenarios.map((scenario) => (
            <button
              key={scenario.id}
              type="button"
              className={`btn-outline scenario-button ${scenario.id === activeScenarioId ? 'active' : ''}`}
              onClick={() => runScenario(scenario)}
              disabled={loadingScenario}
            >
              {loadingScenario && scenario.id === activeScenarioId ? 'Simulating...' : `Run ${scenario.name}`}
            </button>
          ))}
          <button type="button" className="btn-ghost" onClick={resetSimulation} disabled={loadingScenario}>Reset</button>
        </div>
      </section>

      <section className="card simulation-content">
        <div className="simulation-main">
          <RiskGraph data={riskHistory} />
        </div>
        <aside className="simulation-sidebar">
          {activeScenario ? (
            <div className="scenario-detail">
              <h3>{activeScenario.name}</h3>
              <p className="muted">{activeScenario.description}</p>
              <div className="scenario-stats">
                <div>
                  <span className="label">Risk score</span>
                  <span>{activeScenario.riskScore}</span>
                </div>
                <div>
                  <span className="label">Threat level</span>
                  <span>{activeScenario.type}</span>
                </div>
              </div>
              <div>
                <span className="label">Detections triggered</span>
                <ul className="detections">
                  {activeScenario.detections.map((detection) => (
                    <li key={detection}>{detection}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="label">Mitigation</span>
                <p>{activeScenario.mitigation}</p>
              </div>
            </div>
          ) : (
            <div className="scenario-placeholder">
              <h3>Select a scenario to begin</h3>
              <p className="muted">Choose a simulated attack from the left to generate risk telemetry and incident timeline.</p>
            </div>
          )}
        </aside>
      </section>

      <section className="card simulation-events">
        <header className="card-header">
          <h3>Incident timeline</h3>
          <p className="muted">Every control plane that activates during the simulated compromise.</p>
        </header>
        {events.length > 0 ? (
          <ol className="event-timeline">
            {events.map((event) => (
              <li key={`${event.phase}-${event.timestamp}`}>
                <div className="event-phase">{event.phase}</div>
                <div className="event-detail">{event.detail}</div>
                <div className="event-time">{formatDateTime(event.timestamp)}</div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="muted">No events yet — run a scenario to populate the timeline.</p>
        )}
      </section>
    </div>
  );
};

export default Simulation;
