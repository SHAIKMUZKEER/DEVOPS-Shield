import React from 'react';
import RiskBadge from './RiskBadge';
import { formatDateTime } from '../utils/dateHelpers';

const PipelineRow = ({ pipeline, onSelect }) => {
  const trendValues = pipeline.trend || [];
  const lastTrend = trendValues[trendValues.length - 1];
  const trendDirection = trendValues.length >= 2 && trendValues[trendValues.length - 1] > trendValues[trendValues.length - 2]
    ? 'up'
    : 'down';

  return (
    <div className="pipeline-row" role="button" tabIndex={0} onClick={() => onSelect?.(pipeline)} onKeyDown={(event) => {
      if (event.key === 'Enter') onSelect?.(pipeline);
    }}>
      <div className="pipeline-row-main">
        <h3>{pipeline.name}</h3>
        <div className="tags">
          {pipeline.tags?.map((tag) => (
            <span key={tag} className="tag">{tag}</span>
          ))}
        </div>
        <p className="muted">{pipeline.description}</p>
      </div>
      <div className="pipeline-row-meta">
        <RiskBadge score={pipeline.lastRiskScore} level={pipeline.lastRiskLevel} />
        <div className="pipeline-metrics">
          <span className="label">Last run</span>
          <span>{formatDateTime(runsById[pipeline.lastRunId]?.completedAt) || '—'}</span>
        </div>
        <div className={`trend trend-${trendDirection}`}>
          <span>{lastTrend ?? '—'}</span>
        </div>
        <button type="button" className="btn-ghost" onClick={(event) => {
          event.stopPropagation();
          onSelect?.(pipeline);
        }}>View</button>
      </div>
    </div>
  );
};

const runsById = {};

export const registerPipelineRuns = (runs) => {
  if (Array.isArray(runs)) {
    runs.forEach((run) => {
      runsById[run.runId] = run;
    });
  }
};

export default PipelineRow;
