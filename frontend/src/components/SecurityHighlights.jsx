import React from 'react';

const SecurityHighlights = ({ items = [] }) => {
  if (!items.length) return null;
  return (
    <section className="card security-highlights">
      <header className="card-header">
        <div>
          <h2>Security posture</h2>
          <p className="muted">Real-time checks on GitHub OAuth, log privacy, and supply-chain defenses.</p>
        </div>
      </header>
      <div className="security-grid">
        {items.map((item) => (
          <article key={item.id} className="security-item">
            <div className="security-item-top">
              <h3>{item.title}</h3>
              <span className={`security-status status-${(item.status || '').toLowerCase()}`}>{item.status}</span>
            </div>
            <p className="muted">{item.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
};

export default SecurityHighlights;
