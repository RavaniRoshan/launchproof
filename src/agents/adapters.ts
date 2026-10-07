import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import type {
  AgentAdapter, AgentCapabilities, AgentEvent, AgentResult, AgentSession, VerifierContext,
} from './gateway.ts';
import { buildVerifierInstruction } from './gateway.ts';

abstract class ProcessAdapter implements AgentAdapter {
  abstract readonly id: 'codex' | 'claude' | 'script';
  protected abstract command(): string[] | null;
  protected abstract versionFlag(): string[];

  private procs = new Map<string, { child: ChildProcess; output: string; startedAt: number; instruction: string }>();

  async connect(): Promise<{ ok: boolean; detail: string }> {
    const cmd = this.command();
    if (!cmd) return { ok: false, detail: `${this.id} CLI not configured` };
    return new Promise((resolve) => {
      const child = spawn(cmd[0]!, [...cmd.slice(1), ...this.versionFlag()], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout?.on('data', (c) => { out += String(c); });
      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
        resolve({ ok: false, detail: `${this.id} connect timed out` });
      }, 8000);
      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({ ok: false, detail: `${this.id} not found: ${err.message}` });
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve({ ok: true, detail: `${this.id} ${out.trim().slice(0, 120)}` });
        else resolve({ ok: false, detail: `${this.id} exited with code ${String(code)}` });
      });
    });
  }

  async discoverCapabilities(): Promise<AgentCapabilities> {
    const { ok, detail } = await this.connect();
    const gaps = ok ? [] : [detail, 'agent binary unavailable; fix-loop falls back to manual instructions'];
    return {
      id: this.id,
      available: ok,
      tools: ok ? ['read', 'edit', 'run-tests'] : [],
      networkAccess: false,
      streaming: true,
      approvals: true,
      gaps,
    };
  }

  async startSession(context: VerifierContext): Promise<AgentSession> {
    return {
      id: `sess_${Date.now().toString(36)}${randomBytes(3).toString('hex')}`,
      agentId: this.id,
      startedAt: new Date().toISOString(),
      context,
    };
  }

  async sendInstruction(session: AgentSession, instruction: string): Promise<void> {
    const cmd = this.command();
    if (!cmd) throw new Error(`${this.id} CLI not available`);
    const full = `${buildVerifierInstruction(session.context)}\n\nTask:\n${instruction}`;
    const child = spawn(cmd[0]!, cmd.slice(1), { stdio: ['pipe', 'pipe', 'pipe'] });
    this.procs.set(session.id, { child, output: '', startedAt: Date.now(), instruction: full });
    child.stdout?.on('data', (c) => {
      const slot = this.procs.get(session.id);
      if (slot) slot.output += String(c);
    });
    child.stderr?.on('data', (c) => {
      const slot = this.procs.get(session.id);
      if (slot) slot.output += String(c);
    });
    child.stdin?.write(full);
    child.stdin?.end();
  }

  async streamEvents(session: AgentSession, onEvent: (e: AgentEvent) => void): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) throw new Error(`unknown session ${session.id}`);
    await new Promise<void>((resolve) => {
      slot.child.on('exit', (code) => {
        onEvent({ type: 'done', at: new Date().toISOString(), message: `exit ${String(code)}`, data: { code } });
        resolve();
      });
      slot.child.on('error', (err) => {
        onEvent({ type: 'stderr', at: new Date().toISOString(), message: err.message });
        resolve();
      });
    });
  }

  async interrupt(session: AgentSession): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) return;
    try { slot.child.kill('SIGTERM'); } catch { /* ignore */ }
    await new Promise((r) => setTimeout(r, 500));
    try {
      if (slot.child.exitCode === null) slot.child.kill('SIGKILL');
    } catch { /* ignore */ }
  }

  async requestApproval(_session: AgentSession, _action: string): Promise<boolean> {
    // In headless/CLI mode there is no approver UI; the caller must gate on explicit flags.
    // The daemon/UI path overrides this via the approval callback before invoking the adapter.
    return false;
  }

  async collectResult(session: AgentSession): Promise<AgentResult> {
    const slot = this.procs.get(session.id);
    if (!slot) throw new Error(`unknown session ${session.id}`);
    return {
      sessionId: session.id,
      exitCode: slot.child.exitCode,
      output: slot.output.slice(0, 20000),
      changedFiles: [],
      durationMs: Date.now() - slot.startedAt,
    };
  }

  async closeSession(session: AgentSession): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) return;
    try {
      if (slot.child.exitCode === null) slot.child.kill('SIGKILL');
    } catch { /* ignore */ }
    this.procs.delete(session.id);
  }
}

export class CodexAdapter extends ProcessAdapter {
  readonly id = 'codex' as const;
  protected command(): string[] | null {
    return process.env.LAUNCHPROOF_CODEX_BIN ? [process.env.LAUNCHPROOF_CODEX_BIN] : ['codex', 'exec', '--sandbox', 'workspace-write'];
  }
  protected versionFlag(): string[] {
    return ['--version'];
  }
}

export class ClaudeAdapter extends ProcessAdapter {
  readonly id = 'claude' as const;
  protected command(): string[] | null {
    return process.env.LAUNCHPROOF_CLAUDE_BIN ? [process.env.LAUNCHPROOF_CLAUDE_BIN] : ['claude', '-p'];
  }
  protected versionFlag(): string[] {
    return ['--version'];
  }
}

/** Local script adapter: runs a user-provided command with the instruction on stdin. Always available. */
export class ScriptAdapter implements AgentAdapter {
  readonly id = 'script' as const;
  private procs = new Map<string, { child: ChildProcess; output: string; startedAt: number }>();

  async connect(): Promise<{ ok: boolean; detail: string }> {
    return { ok: true, detail: 'script adapter always available' };
  }

  async discoverCapabilities(): Promise<AgentCapabilities> {
    return { id: 'script', available: true, tools: ['run'], networkAccess: false, streaming: true, approvals: false, gaps: ['no agent reasoning; runs commands only'] };
  }

  async startSession(context: VerifierContext): Promise<AgentSession> {
    return { id: `sess_${Date.now().toString(36)}${randomBytes(3).toString('hex')}`, agentId: 'script', startedAt: new Date().toISOString(), context };
  }

  async sendInstruction(session: AgentSession, instruction: string): Promise<void> {
    const bin = process.env.LAUNCHPROOF_SCRIPT_BIN ?? 'sh';
    const child = spawn(bin, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    this.procs.set(session.id, { child, output: '', startedAt: Date.now() });
    child.stdout?.on('data', (c) => {
      const slot = this.procs.get(session.id);
      if (slot) slot.output += String(c);
    });
    child.stderr?.on('data', (c) => {
      const slot = this.procs.get(session.id);
      if (slot) slot.output += String(c);
    });
    child.stdin?.write(`${buildVerifierInstruction(session.context)}\n\n${instruction}`);
    child.stdin?.end();
  }

  async streamEvents(session: AgentSession, onEvent: (e: AgentEvent) => void): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) throw new Error(`unknown session ${session.id}`);
    await new Promise<void>((resolve) => {
      slot.child.on('exit', (code) => {
        onEvent({ type: 'done', at: new Date().toISOString(), message: `exit ${String(code)}` });
        resolve();
      });
      slot.child.on('error', (err) => {
        onEvent({ type: 'stderr', at: new Date().toISOString(), message: err.message });
        resolve();
      });
    });
  }

  async interrupt(session: AgentSession): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) return;
    try { slot.child.kill('SIGKILL'); } catch { /* ignore */ }
  }

  async requestApproval(): Promise<boolean> {
    return false;
  }

  async collectResult(session: AgentSession): Promise<AgentResult> {
    const slot = this.procs.get(session.id);
    if (!slot) throw new Error(`unknown session ${session.id}`);
    return { sessionId: session.id, exitCode: slot.child.exitCode, output: slot.output.slice(0, 20000), changedFiles: [], durationMs: Date.now() - slot.startedAt };
  }

  async closeSession(session: AgentSession): Promise<void> {
    const slot = this.procs.get(session.id);
    if (!slot) return;
    try {
      if (slot.child.exitCode === null) slot.child.kill('SIGKILL');
    } catch { /* ignore */ }
    this.procs.delete(session.id);
  }
}

export function adapterFor(id: 'codex' | 'claude' | 'script'): AgentAdapter {
  if (id === 'codex') return new CodexAdapter();
  if (id === 'claude') return new ClaudeAdapter();
  return new ScriptAdapter();
}
