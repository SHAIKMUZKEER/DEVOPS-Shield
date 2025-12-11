import React from 'react';
import PipelineList from '../components/PipelineList';
import PipelineDetail from '../components/PipelineDetail';

const Pipelines = ({ pipelines, runsByPipeline, activePipelineId, activeRunId, onSelectPipeline, onSelectRun, onRunAction }) => {
  const activePipeline = pipelines.find((pipeline) => pipeline.id === activePipelineId) || pipelines[0];
  const activeRuns = (runsByPipeline && activePipeline) ? runsByPipeline[activePipeline.id] || [] : [];

  return (
    <div className="pipelines-grid">
      <PipelineList pipelines={pipelines} runs={runsByPipeline} onSelectPipeline={(pipeline) => onSelectPipeline?.(pipeline.id)} />
      <PipelineDetail
        pipeline={activePipeline}
        runs={activeRuns}
        activeRunId={activeRunId}
        onSelectRun={onSelectRun}
        onAction={onRunAction}
      />
    </div>
  );
};

export default Pipelines;
