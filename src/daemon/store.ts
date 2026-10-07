import path from 'node:path';
import { mkdir, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { launchproofHome, storagePaths, writeJsonAtomic, readJson } from '../storage/paths.ts';
import { newProjectId } from '../model/ids.ts';
import type { ProjectRef } from '../model/state.ts';

export interface ProjectRecord extends ProjectRef {
  contractPath?: string;
}

const PROJECTS_FILE = 'projects.json';

async function projectsFile(root = launchproofHome()): Promise<string> {
  const paths = storagePaths(root);
  await mkdir(paths.projects, { recursive: true });
  return path.join(paths.projects, PROJECTS_FILE);
}

export async function listProjects(root = launchproofHome()): Promise<ProjectRecord[]> {
  const file = await projectsFile(root);
  const data = await readJson<ProjectRecord[]>(file);
  return data ?? [];
}

export async function saveProjects(records: ProjectRecord[], root = launchproofHome()): Promise<void> {
  const file = await projectsFile(root);
  await writeJsonAtomic(file, records);
}

export async function registerProject(name: string, projectPath: string, root = launchproofHome()): Promise<ProjectRecord> {
  const abs = path.resolve(projectPath);
  const records = await listProjects(root);
  const existing = records.find((r) => path.resolve(r.path) === abs);
  if (existing) return existing;
  const record: ProjectRecord = {
    id: newProjectId(name),
    name,
    path: abs,
    createdAt: new Date().toISOString(),
  };
  records.push(record);
  await saveProjects(records, root);
  return record;
}

export async function getProject(idOrPath: string, root = launchproofHome()): Promise<ProjectRecord | null> {
  const records = await listProjects(root);
  const abs = path.resolve(idOrPath);
  return records.find((r) => r.id === idOrPath || path.resolve(r.path) === abs) ?? null;
}

export async function touchProjectRun(projectId: string, runId: string, root = launchproofHome()): Promise<void> {
  const records = await listProjects(root);
  const rec = records.find((r) => r.id === projectId);
  if (!rec) return;
  rec.lastRunId = runId;
  await saveProjects(records, root);
}

export async function listRuns(root = launchproofHome()): Promise<string[]> {
  const paths = storagePaths(root);
  try {
    const entries = await readdir(paths.runs, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory()).map((e) => e.name).sort().reverse();
  } catch {
    return [];
  }
}

export async function readRunReport(runId: string, root = launchproofHome()): Promise<unknown | null> {
  const paths = storagePaths(root);
  const file = path.join(paths.runs, runId, 'report.json');
  try {
    const raw = await readFile(file, 'utf8');
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

export async function removeRun(runId: string, root = launchproofHome()): Promise<void> {
  const paths = storagePaths(root);
  await rm(path.join(paths.runs, runId), { recursive: true, force: true });
}

export async function writeLogLine(message: string, root = launchproofHome()): Promise<void> {
  const paths = storagePaths(root);
  await mkdir(paths.logs, { recursive: true });
  const file = path.join(paths.logs, 'daemon.log');
  await writeFile(file, `${new Date().toISOString()} ${message}\n`, { flag: 'a' });
}
