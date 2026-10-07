import path from 'node:path';
import type { Browser, BrowserContext, Page } from 'playwright';
import type { PhaseHook } from '../engine/engine.ts';
import type { BrowserProvider, BrowserSession } from '../checks/types.ts';

let chromium: typeof import('playwright').chromium | null = null;
try {
  chromium = (await import('playwright')).chromium;
} catch {
  chromium = null;
}

export interface BrowserLabOptions {
  headless?: boolean;
}

function safeName(name: string): string {
  return name.replace(/[^\w.-]+/g, '_').slice(0, 120) || 'screenshot';
}

function wrap(browser: Browser, scratchDir: string): BrowserProvider {
  return {
    available: () => browser.isConnected(),
    newSession: async (): Promise<BrowserSession> => {
      const context: BrowserContext = await browser.newContext();
      const page: Page = await context.newPage();
      return {
        screenshot: async (name) => {
          const file = path.join(scratchDir, `${safeName(name)}.png`);
          await page.screenshot({ path: file, fullPage: true });
          return file;
        },
        goto: async (url) => {
          await page.goto(url, { waitUntil: 'load', timeout: 15000 });
        },
        waitForNavigation: async (timeoutMs = 5000) => {
          try {
            await page.waitForNavigation({ waitUntil: 'load', timeout: timeoutMs });
            return true;
          } catch {
            return false;
          }
        },
        content: async () => page.content(),
        evaluate: <T,>(fn: string) => page.evaluate(fn) as Promise<T>,
        setCookies: async (cookies) => {
          await context.addCookies(cookies as unknown as Parameters<BrowserContext['addCookies']>[0]);
        },
        getCookies: async () => (await context.cookies()) as unknown as Array<Record<string, unknown>>,
        close: async () => {
          await context.close();
        },
      };
    },
  };
}

export function createBrowserLab(options: BrowserLabOptions = {}): PhaseHook {
  let browser: Browser | null = null;
  let scratchDir = process.cwd();

  return {
    phase: 'browser',
    async setup(io) {
      if (io.state.browser) return;
      if (!chromium) {
        io.log('browser lab: playwright not installed; browser checks stay UNVERIFIED');
        return;
      }
      scratchDir = io.scratchDir;
      try {
        browser = await chromium.launch({ headless: options.headless ?? true });
      } catch (error) {
        io.log(`browser lab: chromium launch failed: ${error instanceof Error ? error.message : String(error)}`);
        browser = null;
        return;
      }
      io.state.browser = wrap(browser, scratchDir);
      io.capabilities.add('browser');
      io.log('browser lab: chromium ready');
    },
    async teardown(io) {
      const b = browser;
      browser = null;
      io.state.browser = undefined;
      if (b?.isConnected()) await b.close().catch(() => undefined);
    },
  };
}
