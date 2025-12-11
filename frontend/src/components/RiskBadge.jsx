import React from 'react';
import { getRiskLevel, getRiskToneClass } from '../utils/riskFormatter';

const levelTone = {
  Safe: 'risk-safe',
  Low: 'risk-low',
  Medium: 'risk-medium',
  High: 'risk-high',
  Critical: 'risk-critical',
  Unknown: 'risk-unknown'
};

const RiskBadge = ({ score, level: providedLevel, size = 'md' }) => {
  const level = providedLevel || getRiskLevel(score);
  const toneClass = getRiskToneClass(level);
  const colorClass = levelTone[level] || levelTone.Unknown;
  const sizeClass = size === 'lg' ? 'risk-badge-lg' : size === 'sm' ? 'risk-badge-sm' : 'risk-badge-md';

  return (
    <span
      className={`risk-badge ${sizeClass} ${colorClass} ${toneClass}`}
      aria-label={`Risk ${level} at score ${typeof score === 'number' ? score : 'unknown'}`}
    >
      <span className="risk-badge-level">{level}</span>
      {typeof score === 'number' && <span className="risk-badge-score">{score}</span>}
    </span>
  );
};

export default RiskBadge;
