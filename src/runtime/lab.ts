import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import type { PhaseHook } from '../engine/engine.ts';
import type { RuntimeHandle } from '../checks/types.ts';

export interface RuntimeLabOptions {
  command?: string[];
  readyTimeoutMs?: number;
  env?: Record<string, string>;
}

const MAX_LOG_LINES = 500;

async function resolveCommand(root: string): Promise<[string, ...string[]]> {
  try {
    const raw = await readFile(path.join(root, 'package.json'), 'utf8');
    const pkg = JSON.parse(raw) as { scripts?: Record<string, string> };
    const match = /^node\s+(\S+)/.exec((pkg.scripts?.start ?? '').trim());
    if (match?.[1]) return ['node', match[1]];
  } catch {
    // fall through to default entry
  }
  return ['node', 'server.js'];
}

export function createRuntimeLab(options: RuntimeLabOptions = {}): PhaseHook {
  let child: ChildProcess | null = null;
  const logs: string[] = [];

  return {
    phase: 'runtime',
    async setup(io) {
      if (io.state.runtime?.alive) return;
      const baseUrl = io.probes?.baseUrl;
      if (!baseUrl) {
        io.log('runtime lab: no probes.baseUrl; leaving runtime unavailable');
        return;
      }
      const url = new URL(baseUrl);
      const port = url.port || (url.protocol === 'https:' ? '443' : '80');
      const [cmd, ...args] = await resolveCommand(io.root);
      child = spawn(cmd, args, {
        cwd: io.root,
        env: { ...process.env, PORT: port, ...options.env },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const capture = (chunk: Buffer | string): void => {
        for (const line of String(chunk).split('\n')) {
          if (line.length === 0) continue;
          logs.push(line);
          if (logs.length > MAX_LOG_LINES) logs.shift();
        }
      };
      child.stdout?.on('data', capture);
      child.stderr?.on('data', capture);
      let exitCode: number | null | undefined;
      child.on('exit', (code) => {
        exitCode = code;
      });

      const deadline = Date.now() + (options.readyTimeoutMs ?? 15000);
      let ready = false;
      while (Date.now() < deadline && !io.signal.aborted) {
        if (exitCode !== undefined) break;
        try {
          await fetch(baseUrl, { signal: AbortSignal.timeout(1000) });
          ready = true;
          break;
        } catch {
          await delay(150);
        }
      }

      if (!ready) {
        const detail = exitCode !== undefined ? ` exited with code ${String(exitCode)}` : ' never answered';
        io.log(`runtime lab: app at ${baseUrl}${detail}`);
        child.kill('SIGKILL');
        child = null;
        return;
      }

      const spawned = child;
      const runtime: RuntimeHandle = {
        baseUrl,
        logs,
        alive: true,
        fetch: (p, init) => fetch(new URL(p, baseUrl).toString(), init),
        stop: async () => {
          if (!runtime.alive) return;
          runtime.alive = false;
          if (spawned.exitCode === null && !spawned.killed) {
            spawned.kill('SIGTERM');
            const hard = Date.now() + 3000;
            while (spawned.exitCode === null && Date.now() < hard) await delay(50);
            if (spawned.exitCode === null) spawned.kill('SIGKILL');
          }
        },
      };
      io.state.runtime = runtime;
      io.capabilities.add('runtime');
      io.log(`runtime lab: listening at ${baseUrl}`);
    },
    async teardown(io) {
      const runtime = io.state.runtime;
      if (runtime) await runtime.stop().catch(() => undefined);
      io.state.runtime = undefined;
      if (child && child.exitCode === null) child.kill('SIGKILL');
      child = null;
    },
  };
}
