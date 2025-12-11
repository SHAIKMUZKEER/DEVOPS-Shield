import React from 'react';
import { formatDateTime } from '../utils/dateHelpers';
import { verifySignature } from '../utils/verifySignature';

const ReportExporter = ({ record, onExport }) => {
  const proofStatus = verifySignature(record?.immutableProof || {});

  return (
    <article className="card report-exporter">
      <header className="card-header">
        <div>
          <h3>{record.pipelineId} — {record.runId}</h3>
          <p className="muted">Generated {formatDateTime(record.generatedAt)} · Reviewer {record.reviewer}</p>
        </div>
        <span className={`proof-status ${proofStatus.valid ? 'proof-valid' : 'proof-invalid'}`}>
          {proofStatus.valid ? 'Signature verified' : 'Verify before sharing'}
        </span>
      </header>
      <dl className="proof-grid">
        <div><dt>Ledger hash</dt><dd>{record.immutableProof?.chainHash}</dd></div>
        <div><dt>Transaction</dt><dd>{record.immutableProof?.txId}</dd></div>
        <div><dt>Status</dt><dd>{record.status}</dd></div>
        <div><dt>Verification</dt><dd>{proofStatus.reason}</dd></div>
      </dl>
      <div className="report-actions">
        <button type="button" className="btn-primary" onClick={() => onExport?.('pdf', record)}>Export PDF</button>
        <button type="button" className="btn-outline" onClick={() => onExport?.('json', record)}>Export JSON</button>
      </div>
    </article>
  );
};

export default ReportExporter;
