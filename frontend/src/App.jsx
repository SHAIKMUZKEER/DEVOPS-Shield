import React, { useState } from 'react';
import './App.css';
import Dashboard from './pages/Dashboard.jsx';
import Pipelines from './pages/Pipelines.jsx';
import AlertsPage from './pages/Alerts.jsx';
import AuditPage from './pages/Audit.jsx';
import SettingsPage from './pages/Settings.jsx';
import ImpactPage from './pages/Impact.jsx';
import SimulationPage from './pages/Simulation.jsx';
import AuthBanner from './components/AuthBanner.jsx';
import {
  pipelines as pipelineData,
  runsByPipeline as runsData,
  alerts as alertData,
  auditRecords,
  impactMetrics,
  integrations,
  policyControls,
  authSession,
  securityHighlights,
  attackScenarios,
  simulationRiskHistory,
} from './utils/sampleData.js';

const VIEWS = {
  DASHBOARD: 'dashboard',
  PIPELINES: 'pipelines',
  ALERTS: 'alerts',
  AUDIT: 'audit',
  SETTINGS: 'settings',
  IMPACT: 'impact',
  SIMULATION: 'simulation'
};

const navItems = [
  { id: VIEWS.DASHBOARD, label: 'Dashboard' },
  { id: VIEWS.PIPELINES, label: 'Pipelines' },
  { id: VIEWS.ALERTS, label: 'Alerts' },
   { id: VIEWS.SIMULATION, label: 'Attack Simulation' },
  { id: VIEWS.AUDIT, label: 'Audit' },
  { id: VIEWS.SETTINGS, label: 'Settings' },
  { id: VIEWS.IMPACT, label: 'Societal Impact' }
];

const App = () => {
  const [view, setView] = useState(VIEWS.DASHBOARD);
  const [activePipelineId, setActivePipelineId] = useState(pipelineData[0]?.id);
  const defaultRunId = runsData[pipelineData[0]?.id]?.[0]?.runId;
  const [activeRunId, setActiveRunId] = useState(defaultRunId);

  const onSelectPipeline = (pipelineId) => {
    setActivePipelineId(pipelineId);
    const nextRunId = runsData[pipelineId]?.[0]?.runId;
    setActiveRunId(nextRunId);
    setView(VIEWS.PIPELINES);
  };

  const onSelectRun = (runId) => {
    setActiveRunId(runId);
  };

  const onRunAction = (action, payload) => {
    console.info('Run action', action, payload?.runId);
  };

  const onAlertAction = (action, payload) => {
    console.info('Alert action', action, payload?.id);
  };

  const onExport = (format, record) => {
    console.info('Export', format, record?.id);
  };

  const onReconnect = (provider) => {
    console.info('Re-authenticate provider', provider);
  };

  const onDisconnect = (provider) => {
    console.info('Disconnect provider', provider);
  };

  let content;
  switch (view) {
    case VIEWS.DASHBOARD:
      content = (
        <Dashboard
          pipelines={pipelineData}
          runsByPipeline={runsData}
          alerts={alertData}
          impactMetrics={impactMetrics}
          authSession={authSession}
          securityHighlights={securityHighlights}
          onSelectPipeline={onSelectPipeline}
          onRunAction={onRunAction}
          onAlertAction={onAlertAction}
        />
      );
      break;
    case VIEWS.PIPELINES:
      content = (
        <Pipelines
          pipelines={pipelineData}
          runsByPipeline={runsData}
          activePipelineId={activePipelineId}
          activeRunId={activeRunId}
          onSelectPipeline={onSelectPipeline}
          onSelectRun={onSelectRun}
          onRunAction={onRunAction}
        />
      );
      break;
    case VIEWS.ALERTS:
      content = <AlertsPage alerts={alertData} onAction={onAlertAction} />;
      break;
    case VIEWS.AUDIT:
      content = <AuditPage records={auditRecords} onExport={onExport} />;
      break;
    case VIEWS.SETTINGS:
      content = (
        <SettingsPage
          integrations={integrations}
          policies={policyControls}
          authSession={authSession}
          securityHighlights={securityHighlights}
        />
      );
      break;
    case VIEWS.IMPACT:
      content = <ImpactPage impactMetrics={impactMetrics} />;
      break;
    case VIEWS.SIMULATION:
      content = (
        <SimulationPage
          scenarios={attackScenarios}
          history={simulationRiskHistory}
        />
      );
      break;
    default:
      content = null;
  }

  return (
    <div className="shell">
      <aside className="shell-nav">
        <div className="nav-brand">DEVOPS SHIELD</div>
        <nav>
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              className={item.id === view ? 'nav-link active' : 'nav-link'}
              onClick={() => setView(item.id)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="nav-footer">
          <span className="muted">Immutable by design · {new Date().getFullYear()}</span>
        </div>
      </aside>
      <main className="shell-content">
        <AuthBanner session={authSession} onReconnect={onReconnect} onDisconnect={onDisconnect} />
        <header className="content-header">
          <div>
            <h1>{navItems.find((item) => item.id === view)?.label}</h1>
            <p className="muted">Production-ready CI/CD risk observability.</p>
          </div>
          <div className="header-actions">
            <button type="button" className="btn-outline" onClick={() => setView(VIEWS.SIMULATION)}>Simulate attack</button>
            <button type="button" className="btn-primary" onClick={() => setView(VIEWS.PIPELINES)}>View pipelines</button>
          </div>
        </header>
        <div className="content-body">
          {content}
        </div>
      </main>
    </div>
  );
};

export default App;
