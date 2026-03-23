import { readFileSync, writeFileSync } from 'node:fs';

interface LogEntry {
  event: string;
  agentJti?: string;
  jti?: string;
  iss?: string;
  sub?: string;
  role?: string;
  action?: string;
  decision?: string;
  parent_chain?: string[];
  [key: string]: unknown;
}

/**
 * Reads an OVID audit log (JSONL) and generates an HTML file with an
 * interactive Sankey diagram showing agent governance flows.
 */
export async function generateSankeyHtml(logPath: string, outputPath: string): Promise<void> {
  const lines = readFileSync(logPath, 'utf-8').trim().split('\n');
  const entries: LogEntry[] = lines.filter((l: string) => l.length > 0).map((l: string) => JSON.parse(l) as LogEntry);

  // Build data structures
  const agents = new Map<string, { iss: string; role: string; depth: number }>();
  const decisionCounts = new Map<string, Map<string, number>>(); // agent -> decision -> count
  const actionCounts = new Map<string, Map<string, number>>(); // agent -> action -> count

  for (const e of entries) {
    if (e.event === 'issuance' && e.sub && e.iss && e.role) {
      const depth = (e.parent_chain as string[] | undefined)?.length ?? 0;
      agents.set(e.sub, { iss: e.iss, role: e.role as string, depth });
    }
    if (e.event === 'decision' && e.agentJti && e.decision) {
      if (!decisionCounts.has(e.agentJti)) decisionCounts.set(e.agentJti, new Map());
      const m = decisionCounts.get(e.agentJti)!;
      m.set(e.decision, (m.get(e.decision) ?? 0) + 1);
      if (e.action) {
        if (!actionCounts.has(e.agentJti)) actionCounts.set(e.agentJti, new Map());
        const a = actionCounts.get(e.agentJti)!;
        a.set(e.action, (a.get(e.action) ?? 0) + 1);
      }
    }
  }

  // Build nodes and links for Sankey
  const nodeNames: string[] = [];
  const nodeIndex = (name: string) => {
    let idx = nodeNames.indexOf(name);
    if (idx === -1) { idx = nodeNames.length; nodeNames.push(name); }
    return idx;
  };

  const links: { source: number; target: number; value: number }[] = [];

  // Agent hierarchy links
  for (const [agentId, info] of agents) {
    const totalDecisions = [...(decisionCounts.get(agentId)?.values() ?? [])].reduce((a, b) => a + b, 0) || 1;
    links.push({ source: nodeIndex(info.iss), target: nodeIndex(agentId), value: totalDecisions });
  }

  // Agent -> decision outcome links
  for (const [agentId, decisions] of decisionCounts) {
    for (const [decision, count] of decisions) {
      links.push({ source: nodeIndex(agentId), target: nodeIndex(decision), value: count });
    }
  }

  // Agent -> action type links
  for (const [agentId, actions] of actionCounts) {
    for (const [action, count] of actions) {
      links.push({ source: nodeIndex(agentId), target: nodeIndex(`action:${action}`), value: count });
    }
  }

  const nodesJson = JSON.stringify(nodeNames.map(name => ({ name })));
  const linksJson = JSON.stringify(links);

  const html = buildSankeyHtml(nodesJson, linksJson, false);
  writeFileSync(outputPath, html);
}

function buildSankeyHtml(nodesJson: string, linksJson: string, includeTextArea: boolean): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>OVID Agent Governance Flow</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0a; color: #c4a87c; font-family: 'Georgia', serif; }
  h1 { text-align: center; padding: 24px; font-size: 28px; letter-spacing: 2px; }
  #chart { width: 100%; height: 600px; }
  .node rect { cursor: pointer; }
  .node text { fill: #c4a87c; font-size: 11px; }
  .link { fill: none; stroke-opacity: 0.4; }
  .link:hover { stroke-opacity: 0.7; }
  .tooltip { position: absolute; background: #1a1a1a; border: 1px solid #c4a87c; color: #c4a87c; padding: 8px 12px; border-radius: 4px; font-size: 13px; pointer-events: none; display: none; }
  ${includeTextArea ? `textarea { width: 90%; margin: 20px auto; display: block; height: 150px; background: #111; color: #81d8d0; border: 1px solid #333; padding: 10px; font-family: monospace; font-size: 12px; }
  button { display: block; margin: 10px auto; padding: 8px 24px; background: #c4a87c; color: #0a0a0a; border: none; cursor: pointer; font-weight: bold; border-radius: 4px; }
  button:hover { background: #81d8d0; }` : ''}
</style>
</head>
<body>
<h1>OVID Agent Governance Flow</h1>
<div id="chart"></div>
<div class="tooltip" id="tooltip"></div>
${includeTextArea ? `<textarea id="logInput" placeholder="Paste JSONL audit log here to regenerate the diagram..."></textarea>
<button onclick="regenerate()">Regenerate Diagram</button>` : ''}
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
<script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12"></script>
<script>
const colorMap = {
  'allow-proven': '#81d8d0',
  'allow-unproven': '#c4a87c',
  'deny': '#e06060'
};

function linkColor(d) {
  const name = d.target.name || '';
  return colorMap[name] || '#555';
}

function renderSankey(nodes, links) {
  const container = document.getElementById('chart');
  container.innerHTML = '';
  const width = container.clientWidth || 1200;
  const height = 600;
  const svg = d3.select('#chart').append('svg').attr('width', width).attr('height', height);
  const sankey = d3.sankey().nodeWidth(20).nodePadding(12).extent([[40, 40], [width - 40, height - 40]]);
  const graph = sankey({ nodes: nodes.map(d => ({...d})), links: links.map(d => ({...d})) });
  const tooltip = document.getElementById('tooltip');

  svg.append('g').selectAll('.link')
    .data(graph.links).enter().append('path')
    .attr('class', 'link')
    .attr('d', d3.sankeyLinkHorizontal())
    .attr('stroke', linkColor)
    .attr('stroke-width', d => Math.max(1, d.width))
    .on('mouseover', (ev, d) => {
      tooltip.style.display = 'block';
      tooltip.innerHTML = d.source.name + ' → ' + d.target.name + ': ' + d.value;
    })
    .on('mousemove', ev => {
      tooltip.style.left = (ev.pageX + 12) + 'px';
      tooltip.style.top = (ev.pageY - 20) + 'px';
    })
    .on('mouseout', () => { tooltip.style.display = 'none'; });

  const node = svg.append('g').selectAll('.node')
    .data(graph.nodes).enter().append('g').attr('class', 'node');

  node.append('rect')
    .attr('x', d => d.x0).attr('y', d => d.y0)
    .attr('height', d => Math.max(1, d.y1 - d.y0))
    .attr('width', sankey.nodeWidth())
    .attr('fill', d => colorMap[d.name] || '#c4a87c')
    .attr('stroke', '#0a0a0a');

  node.append('text')
    .attr('x', d => d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6)
    .attr('y', d => (d.y0 + d.y1) / 2)
    .attr('dy', '0.35em')
    .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
    .text(d => d.name);
}

let initialNodes = ${nodesJson};
let initialLinks = ${linksJson};
renderSankey(initialNodes.map((n,i) => ({...n, index: i})), initialLinks);

${includeTextArea ? `
function parseLog(text) {
  const lines = text.trim().split('\\n').filter(l => l.length > 0);
  const entries = lines.map(l => JSON.parse(l));
  const agents = new Map();
  const decisionCounts = new Map();
  const actionCounts = new Map();
  for (const e of entries) {
    if (e.event === 'issuance' && e.sub && e.iss && e.role) {
      const depth = (e.parent_chain || []).length;
      agents.set(e.sub, { iss: e.iss, role: e.role, depth });
    }
    if (e.event === 'decision' && e.agentJti && e.decision) {
      if (!decisionCounts.has(e.agentJti)) decisionCounts.set(e.agentJti, new Map());
      const m = decisionCounts.get(e.agentJti);
      m.set(e.decision, (m.get(e.decision) || 0) + 1);
      if (e.action) {
        if (!actionCounts.has(e.agentJti)) actionCounts.set(e.agentJti, new Map());
        const a = actionCounts.get(e.agentJti);
        a.set(e.action, (a.get(e.action) || 0) + 1);
      }
    }
  }
  const nodeNames = [];
  const nodeIndex = name => { let i = nodeNames.indexOf(name); if (i === -1) { i = nodeNames.length; nodeNames.push(name); } return i; };
  const links = [];
  for (const [id, info] of agents) {
    const total = [...(decisionCounts.get(id)?.values() || [])].reduce((a,b) => a+b, 0) || 1;
    links.push({ source: nodeIndex(info.iss), target: nodeIndex(id), value: total });
  }
  for (const [id, decs] of decisionCounts) {
    for (const [dec, cnt] of decs) links.push({ source: nodeIndex(id), target: nodeIndex(dec), value: cnt });
  }
  for (const [id, acts] of actionCounts) {
    for (const [act, cnt] of acts) links.push({ source: nodeIndex(id), target: nodeIndex('action:' + act), value: cnt });
  }
  return { nodes: nodeNames.map((n,i) => ({name: n, index: i})), links };
}

function regenerate() {
  const text = document.getElementById('logInput').value;
  if (!text.trim()) return;
  try {
    const { nodes, links } = parseLog(text);
    renderSankey(nodes, links);
  } catch(e) { alert('Parse error: ' + e.message); }
}
` : ''}
</script>
</body>
</html>`;
}
