import React from 'react';
import RiskBadge from './RiskBadge';
import { formatDateTime } from '../utils/dateHelpers';

const Timeline = ({ stages = [] }) => (
  <ol className="timeline">
    {stages.map((stage) => (
      <li key={stage.id} className={`timeline-item status-${(stage.status || 'unknown').toLowerCase()}`}>
        <div className="timeline-ring" />
        <div className="timeline-body">
          <div className="timeline-header">
            <h4>{stage.name}</h4>
            <RiskBadge score={stage.riskScore} size="sm" />
          </div>
          {stage.summary && <p>{stage.summary}</p>}
          {stage.evidence && <p className="muted">{stage.evidence}</p>}
          <div className="timeline-meta">
            <span>{formatDateTime(stage.startedAt)}</span>
            {stage.action && <span className="badge-action">{stage.action}</span>}
          </div>
        </div>
      </li>
    ))}
  </ol>
);

export default Timeline;
