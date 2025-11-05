import React from 'react';
import AIThreatDashboard from './ai-threats/AIThreatDashboard';

// Example: get pipelineId from props, context, or route
const pipelineId = 1; // Replace with dynamic value as needed

const AIThreatDashboardEntry = () => (
  <div style={{ margin: '32px 0' }}>
    <AIThreatDashboard pipelineId={pipelineId} />
  </div>
);

export default AIThreatDashboardEntry;
