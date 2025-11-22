import { _electron as electron } from 'playwright';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { assertUiHasContent } from './verify-ui.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const screenshotDir = path.join(projectRoot, 'screenshots');

const cliArgs = process.argv.slice(2);
const options = {
  appPath: undefined,
  executablePath: undefined,
  output: 'electron.png'
};

for (const arg of cliArgs) {
  if (arg.startsWith('--app=')) {
    options.appPath = arg.split('=')[1];
  } else if (arg.startsWith('--executable=')) {
    options.executablePath = arg.split('=')[1];
  } else if (arg.startsWith('--output=')) {
    options.output = arg.split('=')[1];
  } else if (arg.startsWith('--cwd=')) {
    options.appPath = arg.split('=')[1];
  }
}

const resolvedCwd = options.appPath ? path.resolve(options.appPath) : projectRoot;
const launchArgs = [options.appPath ? resolvedCwd : '.'];
const screenshotPath = path.isAbsolute(options.output)
  ? options.output
  : path.join(screenshotDir, options.output);

fs.mkdirSync(path.dirname(screenshotPath), { recursive: true });

async function capture() {
  const launchConfig = {
    args: launchArgs,
    cwd: resolvedCwd,
    env: {
      ...process.env,
      NODE_ENV: 'production'
    }
  };

  if (options.executablePath) {
    launchConfig.executablePath = options.executablePath;
  }

  const app = await electron.launch(launchConfig);
  const window = await app.firstWindow();
  await window.waitForLoadState('domcontentloaded');
  await assertUiHasContent(window);
  await window.waitForTimeout(1500);
  await window.screenshot({ path: screenshotPath, fullPage: true });
  await app.close();
  console.log(`Electron screenshot saved to ${screenshotPath}`);
}

capture().catch((error) => {
  console.error(error);
  process.exit(1);
});
