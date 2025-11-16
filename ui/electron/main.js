const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

const isDev = !app.isPackaged;
const streams = new Map();
let windowRef;

function resolveFrontendPath() {
  if (isDev) {
    return 'http://localhost:4200';
  }
  return `file://${path.join(__dirname, '..', 'dist', 'paranoid-av-ui', 'browser', 'index.html')}`;
}

function resolveBackendBinary() {
  if (process.env.PARANOID_AV_BIN) {
    return process.env.PARANOID_AV_BIN;
  }
  const localPath = path.join(__dirname, '..', '..', 'build', 'paranoid_av');
  return process.platform === 'win32' ? `${localPath}.exe` : localPath;
}

function createWindow() {
  windowRef = new BrowserWindow({
    width: 1440,
    height: 900,
    backgroundColor: '#0d1b2a',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  windowRef.loadURL(resolveFrontendPath());

  if (isDev) {
    windowRef.webContents.openDevTools({ mode: 'detach' });
  }
}

function sendStream(channel, payload) {
  if (windowRef) {
    windowRef.webContents.send('stream:event', { channel, payload });
  }
}

async function runBackend(args, options = {}) {
  const binary = resolveBackendBinary();
  return new Promise((resolve, reject) => {
    const proc = spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    const stdout = [];
    const stderr = [];

    proc.stdout.on('data', (chunk) => stdout.push(chunk.toString()));
    proc.stderr.on('data', (chunk) => stderr.push(chunk.toString()));
    proc.on('error', (error) => reject(error));
    proc.on('close', (code) => {
      if (stderr.length) {
        sendStream('log', stderr.join(''));
      }
      if (code !== 0 && stdout.length === 0) {
        reject(new Error(`Command exited with code ${code}`));
        return;
      }
      resolve(stdout.join(''));
    });
  });
}

function parseJsonSafe(text) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return undefined;
  }
}

function normaliseProcesses(json) {
  if (!Array.isArray(json)) {
    return [];
  }
  return json.map((proc) => ({
    pid: proc.pid,
    name: proc.name,
    user: proc.user,
    riskScore: Number(proc.risk ?? proc.riskScore ?? 0),
    heuristics: Array.isArray(proc.heuristics)
      ? proc.heuristics.map((finding) => ({
          weight: Number(finding.score ?? finding.weight ?? 0),
          description: finding.description ?? '',
          reference: finding.reference
        }))
      : [],
    exePath: proc.exe,
    threatIntelHits: proc.threatIntelHits ?? []
  }));
}

function parseSystemFindings(text) {
    const findings = [];
    text
        .split(/\r?\n/)
        .map((line) => line.trim())
    .filter((line) => line.startsWith('['))
    .forEach((line, index) => {
      const match = line.match(/^\[(.|)\s\]\s([^()]+)\(severity=([\d.]+)\)\s(.+?)(?:\sref=(.+))?$/);
      if (match) {
        const severityScore = Number(match[3]);
        const severity = severityScore >= 7.5 ? 'high' : severityScore >= 4 ? 'medium' : 'low';
        findings.push({
          id: `${match[2].trim()}-${index}`,
          severity,
          description: `${match[2].trim()} – ${match[4].trim()}`,
          remediation: match[5] ? match[5].trim() : undefined
        });
      }
    });
  return findings;
}

function parseRootkitJson(text) {
  const results = parseJsonSafe(text);
  if (!Array.isArray(results)) {
    return [];
  }
  return results.map((item, index) => ({
    id: item.indicator ? `${item.indicator}-${index}` : `rootkit-${index}`,
    indicator: item.indicator || 'indicator',
    description: item.description || '',
    severity: Number(item.severity || 0),
    evidence: item.evidence || '',
    remediation: item.remediation || ''
  }));
}

function parseDarkwebFindings(text, metadata = {}) {
  const hits = [];
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .forEach((line) => {
      if (line.startsWith('- ')) {
        const match = line.match(/^-\s(.+?)(?:\s\[(.+?)\])?(?:\s\(confidence\s([\d.]+)\))?(?:\sline\s(\d+))?\s->\s(.+)$/);
        if (match) {
          hits.push({
            keyword: match[1],
            matchType: match[2] || 'raw',
            confidence: match[3] ? Number(match[3]) * 100 : 0,
            lineNumber: match[4] ? Number(match[4]) : undefined,
            context: match[5],
            source: metadata.host ? `${metadata.host}${metadata.path || ''}` : undefined
          });
        }
      }
    });
  return hits;
}

function buildMonitorArgs(detailed) {
  const args = ['--json'];
  if (detailed) {
    args.push('--detailed');
  }
  args.push('--monitor');
  return args;
}

function buildDarkwebArgs({ host, path: onionPath, keywords, port, proxy }) {
  if (!host) {
    throw new Error('Dark web host is required');
  }
  const args = [];
  if (proxy) {
    args.push('--tor-proxy', String(proxy));
  }
  if (port) {
    args.push('--darkweb-port', String(port));
  }
  args.push('--darkweb-scan', host, onionPath || '/', (keywords || []).join(','));
  return args;
}

function parseWindowsPlanObject(plan) {
  if (!plan) {
    return undefined;
  }
  return {
    version: plan.version || '',
    build: plan.build || '',
    manifestKey: plan.manifestKey || '',
    windowsRoot: plan.windowsRoot || '',
    issues: Array.isArray(plan.issues)
      ? plan.issues.map((issue) => ({
          type: issue.type || 'missing',
          path: issue.path || '',
          critical: Boolean(issue.critical),
          expectedHash: issue.expectedHash || '',
          expectedSize: Number(issue.expectedSize || 0),
          observedHash: issue.observedHash || '',
          observedSize: Number(issue.observedSize || 0)
        }))
      : [],
    errors: Array.isArray(plan.errors) ? plan.errors : []
  };
}

function parseWindowsCollectionObject(json) {
  if (!json) {
    return { plan: undefined, stage: undefined };
  }
  const plan = parseWindowsPlanObject(json.plan);
  const stage = json.stage
    ? {
        success: Boolean(json.stage.success),
        copied: Array.isArray(json.stage.copied) ? json.stage.copied : [],
        missingSources: Array.isArray(json.stage.missingSources) ? json.stage.missingSources : [],
        errors: Array.isArray(json.stage.errors) ? json.stage.errors : []
      }
    : undefined;
  const planPath = json.planPath
    ? {
        path: json.planPath.path || '',
        saved: Boolean(json.planPath.saved)
      }
    : undefined;
  return { plan, stage, planPath };
}

ipcMain.handle('command:monitor', async (_event, payload) => {
  const output = await runBackend(buildMonitorArgs(payload?.detailed));
  const json = parseJsonSafe(output);
  const processes = normaliseProcesses(json);
  if (processes.length) {
    return { processes, log: `Updated ${processes.length} processes.` };
  }
  return { log: output.trim() };
});

ipcMain.handle('command:system-audit', async () => {
  const output = await runBackend(['--system-audit']);
  const findings = parseSystemFindings(output);
  return { findings, log: output.trim() };
});

ipcMain.handle('command:rootkit-scan', async () => {
  const output = await runBackend(['--json', '--rootkit-scan']);
  const findings = parseRootkitJson(output);
  return { findings, log: output.trim() };
});

ipcMain.handle('command:file-integrity', async (_event, payload = {}) => {
  const { action, path: target, snapshot } = payload;
  if (action === 'baseline') {
    const output = await runBackend(['--integrity-baseline', target, snapshot]);
    return { log: output.trim() };
  }
  if (action === 'verify') {
    const output = await runBackend(['--integrity-verify', target, snapshot]);
    return { log: output.trim() };
  }
  return { log: 'Unsupported integrity action' };
});

ipcMain.handle('command:threat-intel', async (_event, payload = {}) => {
  const output = await runBackend(['--threat-intel-load', payload.path]);
  return { log: output.trim() };
});

ipcMain.handle('command:signature-scan', async (_event, payload = {}) => {
  if (payload.withYara) {
    const output = await runBackend(['--yara', payload.yaraRules || 'rules/index.yar', payload.target]);
    return { log: output.trim() };
  }
  const output = await runBackend(['--scan', payload.target]);
  return { log: output.trim() };
});

ipcMain.handle('command:quarantine', async (_event, payload = {}) => {
  if (payload.action === 'kill') {
    const output = await runBackend(['--kill-pid', payload.value]);
    return { log: output.trim() };
  }
  if (payload.action === 'file') {
    const output = await runBackend(['--quarantine-file', payload.value]);
    return { log: output.trim() };
  }
  return { log: 'Unsupported quarantine request' };
});

ipcMain.handle('command:darkweb-search', async (_event, payload = {}) => {
  const args = buildDarkwebArgs(payload);
  const output = await runBackend(args);
  const hits = parseDarkwebFindings(output, payload);
  return { hits, log: output.trim() };
});

ipcMain.handle('command:firewall-status', async () => {
  const output = await runBackend(['--json', '--firewall-status']);
  const status = parseJsonSafe(output) || {};
  return { status, log: output.trim() };
});

ipcMain.handle('command:firewall-allow-app', async (_event, payload = {}) => {
  if (!payload.path) {
    throw new Error('Application path required');
  }
  const args = ['--firewall-allow-app', payload.path];
  if (payload.label) {
    args.push(payload.label);
  }
  if (payload.direction) {
    args.push(payload.direction);
  }
  const output = await runBackend(args);
  return { log: output.trim() };
});

ipcMain.handle('command:firewall-allow-port', async (_event, payload = {}) => {
  if (!payload.port) {
    throw new Error('Port required');
  }
  const args = ['--firewall-allow-port', String(payload.port)];
  if (payload.protocol) {
    args.push(payload.protocol);
  }
  if (payload.direction) {
    args.push(payload.direction);
  }
  if (payload.label) {
    args.push(payload.label);
  }
  const output = await runBackend(args);
  return { log: output.trim() };
});

ipcMain.handle('command:firewall-policy-load', async (_event, payload = {}) => {
  if (!payload.path) {
    throw new Error('Policy file required');
  }
  const output = await runBackend(['--firewall-load-policy', payload.path]);
  return { log: output.trim() };
});

ipcMain.handle('command:firewall-policy-save', async (_event, payload = {}) => {
  if (!payload.path) {
    throw new Error('Policy file required');
  }
  const output = await runBackend(['--firewall-save-policy', payload.path]);
  return { log: output.trim() };
});

ipcMain.handle('command:firewall-remove-rule', async (_event, payload = {}) => {
  if (!payload.name) {
    throw new Error('Rule name required');
  }
  const output = await runBackend(['--firewall-remove-rule', payload.name]);
  return { log: output.trim() };
});

ipcMain.handle('command:security-center-status', async () => {
  const output = await runBackend(['--json', '--security-center-status']);
  const products = parseJsonSafe(output) || [];
  return { products, log: output.trim() };
});

ipcMain.handle('command:security-center-register', async (_event, payload = {}) => {
  if (!payload.name || !payload.path) {
    throw new Error('Product name and executable path are required');
  }
  const args = ['--security-center-register', payload.name, payload.path];
  if (payload.guid) {
    args.push(`guid=${payload.guid}`);
  }
  if (payload.reporting) {
    args.push(`reporting=${payload.reporting}`);
  }
  if (payload.mode) {
    args.push(`mode=${payload.mode}`);
  }
  const output = await runBackend(args);
  return { log: output.trim() };
});

ipcMain.handle('command:windows-detect', async () => {
  const output = await runBackend(['--json', '--windows-repair-detect']);
  const json = parseJsonSafe(output) || {};
  return { info: json, log: output.trim() };
});

ipcMain.handle('command:windows-audit', async (_event, payload = {}) => {
  const args = ['--json'];
  if (payload.windowsRoot) {
    args.push('--windows-root', payload.windowsRoot);
  }
  args.push('--windows-repair-audit', payload.manifest);
  if (payload.planPath) {
    args.push(payload.planPath);
  }
  const output = await runBackend(args);
  const json = parseJsonSafe(output);
  const plan = json?.plan ? parseWindowsPlanObject(json.plan) : undefined;
  const planPath = json?.planPath ? { path: json.planPath.path, saved: Boolean(json.planPath.saved) } : undefined;
  return { plan, planPath, log: output.trim() };
});

ipcMain.handle('command:windows-collect', async (_event, payload = {}) => {
  const args = ['--json'];
  if (payload.windowsRoot) {
    args.push('--windows-root', payload.windowsRoot);
  }
  args.push('--windows-repair-collect', payload.repository, payload.output);
  if (payload.manifest) {
    args.push(payload.manifest);
  }
  const output = await runBackend(args);
  const json = parseJsonSafe(output);
  const parsed = parseWindowsCollectionObject(json);
  return { plan: parsed.plan, stage: parsed.stage, planPath: parsed.planPath, log: output.trim() };
});

ipcMain.handle('command:usb-build', async (_event, payload = {}) => {
  const { device, workdir, includeTor } = payload;
  if (!device) {
    throw new Error('USB device path required');
  }
  const args = [];
  if (includeTor) {
    args.push('--usb-include-tor');
  }
  args.push('--usb-create', device);
  if (workdir) {
    args.push(workdir);
  }
  const output = await runBackend(args);
  return { log: output.trim() };
});

ipcMain.handle('stream:start', async (_event, payload = {}) => {
  const name = payload.name;
  const token = `${name}-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  if (name === 'monitor-loop') {
    const intervalMs = Math.max(2, Number(payload.args?.intervalSeconds ?? 10)) * 1000;
    const detailed = Boolean(payload.args?.detailed);
    const run = async () => {
      try {
        const output = await runBackend(buildMonitorArgs(detailed));
        const json = parseJsonSafe(output);
        const processes = normaliseProcesses(json);
        if (processes.length) {
          sendStream('process-update', processes);
        }
        sendStream('log', `[monitor] refreshed ${processes.length || 0} processes.`);
      } catch (error) {
        sendStream('log', `[monitor] error: ${error.message}`);
      }
    };
    run();
    const timer = setInterval(run, intervalMs);
    streams.set(token, { stop: () => clearInterval(timer) });
    return token;
  }

  if (name === 'darkweb-loop') {
    const cadenceMs = Math.max(5, Number(payload.args?.cadenceMinutes ?? 30)) * 60 * 1000;
    const run = async () => {
      try {
        const args = buildDarkwebArgs(payload.args || {});
        const output = await runBackend(args);
        const hits = parseDarkwebFindings(output, payload.args || {});
        if (hits.length) {
          sendStream('darkweb-hit', hits);
        }
        sendStream('log', `[darkweb] scan complete (${hits.length} hits).`);
      } catch (error) {
        sendStream('log', `[darkweb] error: ${error.message}`);
      }
    };
    run();
    const timer = setInterval(run, cadenceMs);
    streams.set(token, { stop: () => clearInterval(timer) });
    return token;
  }

  throw new Error(`Unknown stream ${name}`);
});

ipcMain.handle('stream:stop', async (_event, token) => {
  const handle = streams.get(token);
  if (handle?.stop) {
    handle.stop();
  }
  streams.delete(token);
});

ipcMain.on('window:ready', () => {
  sendStream('log', 'UI ready to receive telemetry.');
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
