import React from 'react';
import RiskBadge from './RiskBadge';
import { formatDateTime } from '../utils/dateHelpers';

const AlertsTable = ({ alerts = [], onAction }) => (
  <section className="card alerts-table">
    <header className="card-header">
      <div>
        <h2>Active incidents</h2>
        <p className="muted">Prioritized queue: acknowledge, quarantine, or open ticket.</p>
      </div>
      <div className="alerts-actions">
        <button type="button" className="btn-outline">Filter critical</button>
        <button type="button" className="btn-outline">Assign</button>
      </div>
    </header>
    <table>
      <thead>
        <tr>
          <th scope="col">Incident</th>
          <th scope="col">Pipeline</th>
          <th scope="col">Severity</th>
          <th scope="col">Risk</th>
          <th scope="col">Opened</th>
          <th scope="col">Impact</th>
          <th scope="col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((alert) => (
          <tr key={alert.id}>
            <td>
              <strong>{alert.title}</strong>
              <div className="muted">{alert.id}</div>
            </td>
            <td>{alert.pipelineId}</td>
            <td>{alert.severity}</td>
            <td><RiskBadge score={alert.riskScore} size="sm" /></td>
            <td>{formatDateTime(alert.createdAt)}</td>
            <td>{alert.impact}</td>
            <td className="alerts-actions-cell">
              <button type="button" className="btn-link" onClick={() => onAction?.('ack', alert)}>Acknowledge</button>
              <button type="button" className="btn-link" onClick={() => onAction?.('rollback', alert)}>Rollback</button>
              <button type="button" className="btn-link" onClick={() => onAction?.('ticket', alert)}>Create ticket</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </section>
);

export default AlertsTable;
