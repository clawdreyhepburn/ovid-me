import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateSankeyHtml } from '../src/visualize.js';
import { writeFileSync, readFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('generateSankeyHtml', () => {
  let dir: string;
  let logPath: string;
  let outPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'viz-'));
    logPath = join(dir, 'audit.jsonl');
    outPath = join(dir, 'out.html');
  });

  afterEach(() => {
    try { unlinkSync(logPath); } catch {}
    try { unlinkSync(outPath); } catch {}
  });

  const sampleLog = [
    { event: 'issuance', sub: 'agent-1', iss: 'orchestrator', role: 'worker', parent_chain: [] },
    { event: 'issuance', sub: 'agent-2', iss: 'orchestrator', role: 'reviewer', parent_chain: [] },
    { event: 'decision', agentJti: 'agent-1', decision: 'allow-proven', action: 'read_file' },
    { event: 'decision', agentJti: 'agent-1', decision: 'allow-proven', action: 'write_file' },
    { event: 'decision', agentJti: 'agent-1', decision: 'deny', action: 'exec' },
    { event: 'decision', agentJti: 'agent-2', decision: 'allow-proven', action: 'read_file' },
  ];

  it('generates valid HTML from sample data', async () => {
    writeFileSync(logPath, sampleLog.map(e => JSON.stringify(e)).join('\n'));
    await generateSankeyHtml(logPath, outPath);
    const html = readFileSync(outPath, 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
    // SVG is rendered client-side by D3; the HTML contains the D3 sankey setup
    expect(html).toContain('d3.sankey');
    expect(html).toContain("append('svg')");
  });

  it('contains expected agent names from input data', async () => {
    writeFileSync(logPath, sampleLog.map(e => JSON.stringify(e)).join('\n'));
    await generateSankeyHtml(logPath, outPath);
    const html = readFileSync(outPath, 'utf-8');
    expect(html).toContain('agent-1');
    expect(html).toContain('agent-2');
    expect(html).toContain('orchestrator');
  });

  it('contains SVG rendering elements', async () => {
    writeFileSync(logPath, sampleLog.map(e => JSON.stringify(e)).join('\n'));
    await generateSankeyHtml(logPath, outPath);
    const html = readFileSync(outPath, 'utf-8');
    // D3 Sankey renders rect and path elements
    expect(html).toContain('d3.sankey');
    expect(html).toContain('renderSankey');
    expect(html).toContain('.node');
    expect(html).toContain('.link');
  });

  it('handles empty log gracefully', async () => {
    // Single empty-ish log with no meaningful entries
    writeFileSync(logPath, '{"event":"startup"}\n');
    await generateSankeyHtml(logPath, outPath);
    const html = readFileSync(outPath, 'utf-8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('renderSankey');
  });

  it('embedded JavaScript parses without errors', async () => {
    writeFileSync(logPath, sampleLog.map(e => JSON.stringify(e)).join('\n'));
    await generateSankeyHtml(logPath, outPath);
    const html = readFileSync(outPath, 'utf-8');

    // Extract all script content (skip external CDN scripts)
    const scriptMatches = html.matchAll(/<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi);
    for (const match of scriptMatches) {
      const js = match[1].trim();
      if (!js) continue;
      // new Function will throw SyntaxError if JS is invalid
      expect(() => new Function(js)).not.toThrow();
    }
  });
});
