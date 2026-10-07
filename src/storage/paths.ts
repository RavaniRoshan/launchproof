import { mkdir, readFile, rename, writeFile, appendFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

export function launchproofHome(): string {
  return process.env.LAUNCHPROOF_HOME || path.join(os.homedir(), '.launchproof');
}

export interface StoragePaths {
  root: string;
  projects: string;
  runs: string;
  evidence: string;
  policies: string;
  agents: string;
  cache: string;
  logs: string;
}

export function storagePaths(root = launchproofHome()): StoragePaths {
  return {
    root,
    projects: path.join(root, 'projects'),
    runs: path.join(root, 'runs'),
    evidence: path.join(root, 'evidence'),
    policies: path.join(root, 'policies'),
    agents: path.join(root, 'agents'),
    cache: path.join(root, 'cache'),
    logs: path.join(root, 'logs'),
  };
}

export async function ensureStorage(root = launchproofHome()): Promise<StoragePaths> {
  const paths = storagePaths(root);
  for (const dir of Object.values(paths)) {
    await mkdir(dir, { recursive: true });
  }
  return paths;
}

export async function writeJsonAtomic(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await rename(tmp, file);
}

export async function readJson<T>(file: string): Promise<T | null> {
  try {
    const raw = await readFile(file, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function appendJsonLine(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify(value)}\n`, 'utf8');
}

export async function readJsonLines<T>(file: string): Promise<T[]> {
  try {
    const raw = await readFile(file, 'utf8');
    return raw
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as T);
  } catch {
    return [];
  }
}

export async function listDirs(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory()).map((e) => e.name);
  } catch {
    return [];
  }
}

export async function removePath(target: string): Promise<void> {
  await rm(target, { recursive: true, force: true });
}
