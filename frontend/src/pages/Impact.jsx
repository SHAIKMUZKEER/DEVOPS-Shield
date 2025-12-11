import React from 'react';
import ImpactMetrics from '../components/ImpactMetrics.jsx';

const ImpactPage = ({ impactMetrics }) => (
  <div className="impact-page">
    <header className="page-header">
      <h1>Societal Impact</h1>
      <p className="muted">Transparency dashboard describing how DevOps Shield protects critical infrastructure.</p>
    </header>
    <ImpactMetrics data={impactMetrics} />
    <section className="card impact-narrative">
      <header className="card-header">
        <h2>Public safety narrative</h2>
      </header>
      <p>
        Pipeline guardrails have automatically blocked malicious firmware pushes targeting smart grid devices, preserving
        reliable power for over 1.2M citizens across three metropolitan regions. Banking pipelines enforce real-time rollback,
        protecting financial transactions and preventing fraudulent settlement updates. Healthcare systems continue to receive
        signed, verified updates with zero unsafe deploys reaching production.
      </p>
    </section>
  </div>
);

export default ImpactPage;
