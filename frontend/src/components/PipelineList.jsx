import React, { useMemo } from 'react';
import PipelineRow, { registerPipelineRuns } from './PipelineRow';

const PipelineList = ({ pipelines = [], runs = {}, onSelectPipeline }) => {
  const flattenedRuns = useMemo(() => Object.values(runs).flat(), [runs]);
  registerPipelineRuns(flattenedRuns);

  return (
    <section className="card pipeline-list">
      <header className="card-header">
        <div>
          <h2>Pipelines</h2>
          <p className="muted">Monitor the risk posture of every CI/CD workflow.</p>
        </div>
        <button type="button" className="btn-outline">Create pipeline</button>
      </header>
      <div className="pipeline-list-body">
        {pipelines.map((pipeline) => (
          <PipelineRow key={pipeline.id} pipeline={pipeline} onSelect={onSelectPipeline} />
        ))}
      </div>
    </section>
  );
};

export default PipelineList;
