import { chromium } from 'playwright';
import path from 'path';
import fs from 'fs';
import http from 'http';
import { fileURLToPath } from 'url';
import { assertUiHasContent } from './verify-ui.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const distIndex = path.join(projectRoot, 'dist', 'paranoid-av-ui', 'index.html');
const distRoot = path.dirname(distIndex);
const screenshotDir = path.join(projectRoot, 'screenshots');
const screenshotPath = path.join(screenshotDir, 'web.png');

if (!fs.existsSync(distIndex)) {
  throw new Error(`Build output missing at ${distIndex}. Run "npm run build" first.`);
}

fs.mkdirSync(screenshotDir, { recursive: true });

const headlessArgs = ['--allow-file-access-from-files', '--disable-features=IsolateOrigins,site-per-process'];

async function launchBrowser() {
  try {
    return await chromium.launch({ channel: 'msedge', headless: true, args: headlessArgs });
  } catch (error) {
    console.warn('[capture-web] Falling back to bundled Chromium:', error.message);
    return chromium.launch({ headless: true, args: headlessArgs });
  }
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.mjs': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf',
    '.map': 'application/json',
    '.webp': 'image/webp'
  };
  return map[ext] || 'application/octet-stream';
}

function startStaticServer(rootDir) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const method = (req.method || 'GET').toUpperCase();
      if (!['GET', 'HEAD'].includes(method)) {
        res.writeHead(405, { 'Content-Type': 'text/plain' });
        res.end('Method not allowed');
        return;
      }
      const requestUrl = new URL(req.url || '/', 'http://localhost');
      let relativePath = decodeURIComponent(requestUrl.pathname || '/');
      if (relativePath.endsWith('/')) {
        relativePath = `${relativePath}index.html`;
      }
      relativePath = relativePath.replace(/^[/\\]+/, '');
      if (!relativePath) {
        relativePath = 'index.html';
      }
      let targetPath = path.resolve(rootDir, relativePath);
      if (!targetPath.startsWith(rootDir)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
      if (!fs.existsSync(targetPath) || fs.statSync(targetPath).isDirectory()) {
        targetPath = path.join(rootDir, 'index.html');
      }
      fs.readFile(targetPath, (error, data) => {
        if (error) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Server error');
          return;
        }
        res.writeHead(200, {
          'Content-Type': getMimeType(targetPath),
          'Cache-Control': 'no-cache'
        });
        if (method === 'HEAD') {
          res.end();
          return;
        }
        res.end(data);
      });
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

async function capture() {
  const server = await startStaticServer(distRoot);
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const browser = await launchBrowser();
  const page = await browser.newPage();
  page.on('console', (msg) => console.log(`[web] console:${msg.type()}: ${msg.text()}`));
  page.on('pageerror', (error) => console.error('[web] pageerror:', error.message));
  await page.goto(`${baseUrl}/index.html`);
  await assertUiHasContent(page);
  await page.waitForTimeout(1500);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
  console.log(`Web screenshot saved to ${screenshotPath}`);
}

capture().catch((error) => {
  console.error(error);
  process.exit(1);
});
