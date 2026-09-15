import Database from 'better-sqlite3';
import type {
  Classification,
  ClassificationResult,
  DetectedEntity,
} from '../types.js';
import { CLASSIFICATION_SEVERITY } from '../types.js';

const CLASSIFICATION_PROMPT = `You are a data sensitivity classifier. Analyze the text below and identify any sensitive information.

Respond with ONLY a valid JSON object, no other text:
{"classification":"PUBLIC","entities":[]}

Classification levels:
- RESTRICTED: social security numbers, credit card numbers, private cryptographic keys, plaintext passwords with values
- SENSITIVE: email addresses, phone numbers, API keys/tokens, database connection strings, personal names paired with identifying data, medical or financial records
- INTERNAL: absolute file paths, internal hostnames, private IP addresses, internal project names
- PUBLIC: no sensitive information found

Entity types: ssn, credit_card, private_key, password, email, phone, api_key, token, connection_string, person_name, medical_record, financial_record, file_path, hostname, ip_address

Text to classify:
`;

export interface ModelClassifierConfig {
  /** Path to the sqlite-ai extension binary (e.g. /app/extensions/ai) */
  extension_path: string;
  /** Path to the GGUF model file */
  model_path: string;
  /** gpu_layers setting (0 for CPU-only, default 0) */
  gpu_layers?: number;
}

/**
 * Classifies content using a local GGUF model via the sqlite-ai extension.
 *
 * Uses a dedicated SQLite database (in-memory) with the sqlite-ai extension
 * loaded. The model stays resident after the first load.
 */
export class ModelClassifier {
  private db: Database.Database;
  private loaded = false;
  private busy = false;
  private callCount = 0;
  private readonly config: Required<ModelClassifierConfig>;

  constructor(config: ModelClassifierConfig) {
    this.config = {
      gpu_layers: 0,
      ...config,
    };

    this.db = new Database(':memory:');
  }

  /**
   * Load the sqlite-ai extension and GGUF model.
   * Call once at startup — the model stays resident in memory.
   */
  load(): void {
    if (this.loaded) return;

    console.log(`[model-classifier] Loading sqlite-ai extension from ${this.config.extension_path}`);
    this.db.loadExtension(this.config.extension_path);

    console.log(`[model-classifier] Loading model from ${this.config.model_path}`);
    this.db.exec(
      `SELECT llm_model_load('${escapeSql(this.config.model_path)}', 'gpu_layers=${this.config.gpu_layers},use_mmap=1')`
    );

    console.log(`[model-classifier] Creating text generation context`);
    this.db.exec(`SELECT llm_context_create_textgen()`);

    this.loaded = true;
    console.log(`[model-classifier] Ready`);
  }

  /**
   * Classify content using the local model.
   * Falls back gracefully if model inference fails.
   */
  classify(content: string): ClassificationResult | null {
    if (!this.loaded) return null;

    // sqlite-ai's text generation is not reentrant — serialize calls
    if (this.busy) {
      console.warn(`[model-classifier] Skipping: inference already in progress`);
      return null;
    }

    this.busy = true;
    try {
      // sqlite-ai's text generation context crashes on reuse (SIGSEGV).
      // Workaround: reload the entire model on a fresh database each call.
      // This costs ~500-800ms per call but avoids the native segfault.
      if (this.callCount > 0) {
        this.reload();
      }
      this.callCount++;

      const prompt = CLASSIFICATION_PROMPT + content.slice(0, 2000);

      const row = this.db
        .prepare(`SELECT llm_text_generate(?) as response`)
        .get(prompt) as { response: string } | undefined;

      if (!row?.response) return null;

      return parseModelResponse(row.response);
    } catch (err) {
      console.warn(`[model-classifier] Inference failed:`, err);
      return null;
    } finally {
      this.busy = false;
    }
  }

  /**
   * Reload the model on a fresh database to work around the sqlite-ai
   * SIGSEGV on context reuse.
   */
  private reload(): void {
    try { this.db.close(); } catch { /* ignore */ }
    this.db = new Database(':memory:');
    this.db.loadExtension(this.config.extension_path);
    this.db.exec(
      `SELECT llm_model_load('${escapeSql(this.config.model_path)}', 'gpu_layers=${this.config.gpu_layers},use_mmap=1')`
    );
    this.db.exec(`SELECT llm_context_create_textgen()`);
  }

  close(): void {
    try { this.db.close(); } catch { /* ignore */ }
  }
}

/**
 * Parse the JSON response from the model into a ClassificationResult.
 * Handles malformed responses gracefully.
 */
function parseModelResponse(response: string): ClassificationResult | null {
  try {
    // Extract JSON from the response (model may add surrounding text)
    const jsonMatch = response.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]) as {
      classification?: string;
      entities?: Array<{
        type?: string;
        value?: string;
        confidence?: number;
      }>;
    };

    const classification = normalizeClassification(parsed.classification);
    if (!classification) return null;

    const detected: DetectedEntity[] = (parsed.entities ?? [])
      .filter((e): e is { type: string; value: string; confidence?: number } =>
        typeof e.type === 'string' && typeof e.value === 'string'
      )
      .map(e => ({
        type: e.type,
        value: e.value,
        start: -1,  // model doesn't provide positions
        end: -1,
        confidence: e.confidence ?? 0.6,
      }));

    return {
      classification,
      detected,
      reasons: [`model classified as ${classification}`],
    };
  } catch {
    return null;
  }
}

function normalizeClassification(raw: string | undefined): Classification | null {
  if (!raw) return null;
  const upper = raw.toUpperCase().trim();
  if (upper in CLASSIFICATION_SEVERITY) return upper as Classification;
  return null;
}

function escapeSql(s: string): string {
  return s.replace(/'/g, "''");
}
