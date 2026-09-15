import Database from 'better-sqlite3';
import type {
  Classification,
  ClassificationResult,
  DetectedEntity,
} from '../types.js';
import { CLASSIFICATION_SEVERITY } from '../types.js';

const CLASSIFICATION_PROMPT = `You are a data sensitivity classifier for an egress firewall. Your job: decide what classification level a piece of text deserves, and identify specific sensitive entities.

Respond with ONLY a JSON object. No explanation, no markdown, no extra text.

Format: {"classification":"LEVEL","entities":[{"type":"TYPE","value":"MATCHED_TEXT","confidence":0.9}]}

Classification levels (pick the HIGHEST that applies):
  RESTRICTED — must never leave the device: SSNs, credit card numbers, private keys, raw passwords
  SENSITIVE  — should be redacted before cloud transmission: emails, phone numbers, API keys, tokens, connection strings, personal names + identifying context, medical records, financial records  
  INTERNAL   — low risk but reveals internal structure: file paths, internal hostnames, private IPs
  PUBLIC     — no sensitive content detected

Examples:

Text: "Quarterly revenue grew 15% driven by enterprise expansion."
{"classification":"PUBLIC","entities":[]}

Text: "Forward the deck to sarah.chen@acme.com before the board meeting."
{"classification":"SENSITIVE","entities":[{"type":"email","value":"sarah.chen@acme.com","confidence":0.95}]}

Text: "The patient, James Wilson (DOB 03/15/1982), was prescribed metformin for type 2 diabetes."
{"classification":"SENSITIVE","entities":[{"type":"person_name","value":"James Wilson","confidence":0.85},{"type":"medical_record","value":"prescribed metformin for type 2 diabetes","confidence":0.9}]}

Text: "My social is 456-78-9012 and my Visa ends in 4242."
{"classification":"RESTRICTED","entities":[{"type":"ssn","value":"456-78-9012","confidence":0.98},{"type":"credit_card","value":"Visa ends in 4242","confidence":0.7}]}

Text: "Deploy to /opt/render/project/src on staging.corp.internal"
{"classification":"INTERNAL","entities":[{"type":"file_path","value":"/opt/render/project/src","confidence":0.6},{"type":"hostname","value":"staging.corp.internal","confidence":0.7}]}

Text: "My mother's maiden name is Rodriguez and I was born in Springfield."
{"classification":"SENSITIVE","entities":[{"type":"security_answer","value":"mother's maiden name is Rodriguez","confidence":0.85}]}

Now classify this text:
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
  private readonly cache = new Map<string, { result: ClassificationResult; ts: number }>();
  private readonly cacheMaxAge = 300_000; // 5 minutes
  private readonly cacheMaxSize = 500;

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

    // Check cache first — avoids the expensive model reload + inference
    const cacheKey = hashForCache(content);
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.ts < this.cacheMaxAge) {
      return cached.result;
    }

    this.busy = true;
    try {
      // sqlite-ai's text generation context crashes on reuse (SIGSEGV).
      // Workaround: reload the entire model on a fresh database each call.
      if (this.callCount > 0) {
        this.reload();
      }
      this.callCount++;

      const prompt = CLASSIFICATION_PROMPT + content.slice(0, 2000);

      const row = this.db
        .prepare(`SELECT llm_text_generate(?) as response`)
        .get(prompt) as { response: string } | undefined;

      if (!row?.response) return null;

      const result = parseModelResponse(row.response);
      if (result) {
        // Evict oldest entries if cache is full
        if (this.cache.size >= this.cacheMaxSize) {
          const oldest = [...this.cache.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
          if (oldest) this.cache.delete(oldest[0]);
        }
        this.cache.set(cacheKey, { result, ts: Date.now() });
      }
      return result;
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

function hashForCache(content: string): string {
  let h = 0;
  for (let i = 0; i < content.length; i++) {
    h = ((h << 5) - h + content.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}
