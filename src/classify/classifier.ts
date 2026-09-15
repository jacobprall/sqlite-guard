import type {
  Classification,
  ClassificationResult,
  DetectedEntity,
  PatternDefinition,
} from '../types.js';
import { CLASSIFICATION_SEVERITY } from '../types.js';
import { BUILTIN_PATTERNS } from './patterns.js';
import type { ModelClassifier } from './model-classifier.js';

export class Classifier {
  private readonly patterns: PatternDefinition[];
  private modelClassifier: ModelClassifier | null = null;

  constructor(customPatterns: PatternDefinition[] = []) {
    this.patterns = [...BUILTIN_PATTERNS, ...customPatterns];
  }

  /**
   * Attach a model-based classifier. When present, both regex and model
   * run on every classify() call and the highest severity wins.
   */
  setModelClassifier(model: ModelClassifier): void {
    this.modelClassifier = model;
  }

  /**
   * Classify a string using regex patterns and (optionally) a local model.
   * Returns the highest-severity classification from either source.
   */
  classify(content: string): ClassificationResult {
    const regexResult = this.classifyRegex(content);

    if (!this.modelClassifier) return regexResult;

    const modelResult = this.modelClassifier.classify(content);
    if (!modelResult) return regexResult;

    return mergeResults(regexResult, modelResult);
  }

  /**
   * Classify using regex patterns only.
   */
  classifyRegex(content: string): ClassificationResult {
    const detected: DetectedEntity[] = [];
    const reasons: string[] = [];
    let highest: Classification = 'PUBLIC';

    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.pattern.exec(content)) !== null) {
        detected.push({
          type: pattern.type,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          confidence: pattern.confidence ?? 0.5,
        });

        if (CLASSIFICATION_SEVERITY[pattern.classification] > CLASSIFICATION_SEVERITY[highest]) {
          highest = pattern.classification;
          reasons.push(
            `${pattern.name}: matched "${truncate(match[0], 20)}" → ${pattern.classification}`
          );
        }
      }
    }

    if (detected.length === 0) {
      reasons.push('no sensitive patterns detected');
    }

    return { classification: highest, detected, reasons };
  }

  /**
   * Redact all detected entities in the content, replacing them with
   * type-labeled placeholders: [EMAIL], [SSN], [API_KEY], etc.
   */
  redact(content: string, detected: DetectedEntity[]): string {
    // Only redact entities with known positions (regex results)
    const positional = detected.filter(e => e.start >= 0 && e.end >= 0);
    if (positional.length === 0) return content;

    const sorted = [...positional].sort((a, b) => b.start - a.start);
    let result = content;

    for (const entity of sorted) {
      const placeholder = `[${entity.type.toUpperCase()}]`;
      result = result.slice(0, entity.start) + placeholder + result.slice(entity.end);
    }

    return result;
  }
}

/**
 * Merge regex and model classification results.
 * The highest severity wins. Entities from both sources are combined.
 */
function mergeResults(
  regex: ClassificationResult,
  model: ClassificationResult
): ClassificationResult {
  const regexSeverity = CLASSIFICATION_SEVERITY[regex.classification];
  const modelSeverity = CLASSIFICATION_SEVERITY[model.classification];

  const classification = regexSeverity >= modelSeverity
    ? regex.classification
    : model.classification;

  // Deduplicate entities by type+value
  const seen = new Set<string>();
  const detected: DetectedEntity[] = [];

  for (const entity of [...regex.detected, ...model.detected]) {
    const key = `${entity.type}:${entity.value}`;
    if (!seen.has(key)) {
      seen.add(key);
      detected.push(entity);
    }
  }

  const reasons = [
    ...regex.reasons.map(r => `[regex] ${r}`),
    ...model.reasons.map(r => `[model] ${r}`),
  ];

  return { classification, detected, reasons };
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '…' : s;
}
