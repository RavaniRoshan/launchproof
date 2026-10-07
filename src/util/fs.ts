import { mkdir, readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  '__pycache__',
  '.venv',
  'venv',
  '.launchproof',
  '.idea',
  '.vscode',
]);

export interface WalkOptions {
  maxFiles?: number;
  maxDepth?: number;
  extensions?: string[];
  ignoreDirs?: string[];
}

export async function walkFiles(root: string, options: WalkOptions = {}): Promise<string[]> {
  const maxFiles = options.maxFiles ?? 20000;
  const maxDepth = options.maxDepth ?? 12;
  const ignore = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const results: string[] = [];

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth || results.length >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (results.length >= maxFiles) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (ignore.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.github') continue;
        await walk(full, depth + 1);
      } else if (entry.isFile()) {
        if (options.extensions && !options.extensions.includes(path.extname(entry.name))) continue;
        results.push(path.relative(root, full));
      }
    }
  }

  await walk(root, 0);
  return results;
}

export async function readText(root: string, rel: string): Promise<string | null> {
  try {
    const full = path.join(root, rel);
    const info = await stat(full);
    if (!info.isFile() || info.size > 2_000_000) return null;
    return await readFile(full, 'utf8');
  } catch {
    return null;
  }
}

export async function exists(root: string, rel: string): Promise<boolean> {
  return existsSync(path.join(root, rel));
}

export async function listDir(root: string, rel: string): Promise<string[]> {
  try {
    const entries = await readdir(path.join(root, rel), { withFileTypes: true });
    return entries.map((e) => path.join(rel, e.name));
  } catch {
    return [];
  }
}

export function matchesAny(relPath: string, patterns: RegExp[]): boolean {
  return patterns.some((re) => re.test(relPath));
}
