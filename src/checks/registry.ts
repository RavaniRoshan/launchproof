import type { CheckDefinition } from './types.ts';
import { isCheckId } from '../model/types.ts';

export class CheckRegistry {
  private readonly byId = new Map<string, CheckDefinition>();

  constructor(checks: CheckDefinition[] = []) {
    for (const check of checks) this.register(check);
  }

  register(check: CheckDefinition): void {
    if (!isCheckId(check.id)) {
      throw new Error(`invalid check id: ${check.id}`);
    }
    if (this.byId.has(check.id)) {
      throw new Error(`duplicate check id: ${check.id}`);
    }
    this.byId.set(check.id, check);
  }

  get(id: string): CheckDefinition | undefined {
    return this.byId.get(id);
  }

  has(id: string): boolean {
    return this.byId.has(id);
  }

  all(): CheckDefinition[] {
    return [...this.byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  ids(): string[] {
    return this.all().map((c) => c.id);
  }

  byCategory(category: string): CheckDefinition[] {
    return this.all().filter((c) => c.category === category);
  }

  size(): number {
    return this.byId.size;
  }
}

let defaultRegistry: CheckRegistry | null = null;

export async function loadDefaultRegistry(): Promise<CheckRegistry> {
  if (defaultRegistry) return defaultRegistry;
  const { buildChecks } = await import('./index.ts');
  defaultRegistry = new CheckRegistry(buildChecks());
  return defaultRegistry;
}
