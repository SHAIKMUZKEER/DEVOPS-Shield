import React from 'react';
import ReportExporter from '../components/ReportExporter';

const AuditPage = ({ records, onExport }) => (
  <div className="audit-page">
    <header className="page-header">
      <h1>Audit & Reports</h1>
      <p className="muted">Export immutable evidence packages for compliance, regulators, and executive briefings.</p>
    </header>
    <div className="audit-grid">
      {records.map((record) => (
        <ReportExporter key={record.id} record={record} onExport={onExport} />
      ))}
    </div>
  </div>
);

export default AuditPage;
