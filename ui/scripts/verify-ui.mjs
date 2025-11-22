import fs from 'fs';

async function dumpDebugHtml(page) {
  const tmpPath = process.env.PARANOID_UI_DEBUG_HTML;
  if (!tmpPath) {
    return;
  }
  try {
    const snapshot = await page.content();
    fs.writeFileSync(tmpPath, snapshot, 'utf8');
  } catch {
    // ignore write errors
  }
}

export async function assertUiHasContent(page) {
  try {
    await page.waitForSelector('.command-shell', { timeout: 20000 });
  } catch (error) {
    await dumpDebugHtml(page);
    throw error;
  }
  const moduleCount = await page.locator('.module-card').count();
  const navCount = await page.locator('.nav-item').count();
  if (moduleCount === 0 || navCount === 0) {
    await dumpDebugHtml(page);
    throw new Error(`UI content missing (modules=${moduleCount}, nav=${navCount}).`);
  }
}
