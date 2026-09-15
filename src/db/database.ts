import Database from 'better-sqlite3';
import { MIGRATIONS } from './schema.js';

export class GuardDatabase {
  readonly db: Database.Database;

  constructor(path: string = ':memory:') {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  private migrate(): void {
    const version = this.getSchemaVersion();

    for (let i = version; i < MIGRATIONS.length; i++) {
      this.db.exec(MIGRATIONS[i]);
    }
  }

  private getSchemaVersion(): number {
    try {
      const row = this.db
        .prepare(`SELECT value FROM guard_meta WHERE key = 'schema_version'`)
        .get() as { value: string } | undefined;
      return row ? parseInt(row.value, 10) : 0;
    } catch {
      // Table doesn't exist yet — version 0
      return 0;
    }
  }

  close(): void {
    this.db.close();
  }
}

export function createGuardDatabase(path?: string): GuardDatabase {
  return new GuardDatabase(path);
}
