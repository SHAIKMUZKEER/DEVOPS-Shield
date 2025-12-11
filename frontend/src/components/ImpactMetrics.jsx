import React from 'react';

const ImpactMetrics = ({ data }) => {
  if (!data) return null;
  return (
    <section className="card impact-board">
      <header className="card-header">
        <div>
          <h2>Societal Impact Board</h2>
          <p className="muted">How DevOps Shield protects critical services in production.</p>
        </div>
      </header>
      <div className="impact-grid">
        <div className="impact-stat">
          <span className="impact-value">{data.blockedMaliciousDeploys}</span>
          <span className="impact-label">Blocked malicious deploys</span>
        </div>
        <div className="impact-stat">
          <span className="impact-value">{data.protectedUsers.toLocaleString()}</span>
          <span className="impact-label">Users protected</span>
        </div>
        <div className="impact-stat">
          <span className="impact-value">{data.transparency.publicAlertsIssued}</span>
          <span className="impact-label">Public safety alerts</span>
        </div>
        <div className="impact-stat">
          <span className="impact-value">{data.transparency.regulatorNotifications}</span>
          <span className="impact-label">Regulator notifications</span>
        </div>
      </div>
      <div className="impact-sections">
        <div>
          <h3>Protected assets</h3>
          <ul>
            {Object.entries(data.protectedAssets).map(([sector, count]) => (
              <li key={sector}>{sector}: {count}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3>Compliance posture</h3>
          <ul>
            {data.compliancePosture.map((item) => (
              <li key={item.framework}>{item.framework} — {item.status} (last audit {item.lastAudit})</li>
            ))}
          </ul>
        </div>
        <div>
          <h3>Supply-chain integrity</h3>
          <ul>
            <li>Verified publishers: {data.supplyChain.verifiedPublishers}</li>
            <li>Quarantined packages: {data.supplyChain.quarantinedPackages}</li>
            <li>Avg resolution: {data.supplyChain.avgResolutionHours}h</li>
          </ul>
        </div>
      </div>
    </section>
  );
};

export default ImpactMetrics;
