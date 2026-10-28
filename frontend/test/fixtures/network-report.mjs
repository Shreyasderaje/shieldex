// Local graph-only fixture. These relationships are test data and never used by live scans.
export const networkReport = {
  graph: {
    root: { id: '', name: 'fixture-network' },
    nodes: [
      { id: 'node_modules/cedar', name: 'cedar', version: '2.0.0', riskLevel: 'HIGH', isDirect: true },
      { id: 'node_modules/cedar/node_modules/spruce', name: 'spruce', version: '1.4.0', riskLevel: 'LOW', isDirect: false },
      { id: 'node_modules/pine', name: 'pine', version: '3.1.0', riskLevel: 'NONE', isDirect: true },
      { id: 'node_modules/ash', name: 'ash', version: '1.0.0', riskLevel: 'UNKNOWN', isDirect: false },
    ],
    edges: [
      { from: 'node_modules/cedar', to: 'node_modules/cedar/node_modules/spruce', range: '^1.0.0' },
      { from: 'node_modules/cedar/node_modules/spruce', to: 'node_modules/pine', range: '~3.0.0' },
    ],
  },
  dependencies: [
    { id: 'node_modules/cedar', name: 'cedar', version: '2.0.0', riskLevel: 'HIGH', isDirect: true, vulnerabilities: [{ id: 'OSV-FIXTURE-1' }] },
    { id: 'node_modules/cedar/node_modules/spruce', name: 'spruce', version: '1.4.0', riskLevel: 'LOW', isDirect: false, vulnerabilities: [] },
    { id: 'node_modules/pine', name: 'pine', version: '3.1.0', riskLevel: 'NONE', isDirect: true, vulnerabilities: [] },
    { id: 'node_modules/ash', name: 'ash', version: '1.0.0', riskLevel: 'UNKNOWN', isDirect: false, vulnerabilities: [] },
  ],
};
