import type {
  Classification,
  ClassificationResult,
  DetectedEntity,
  PatternDefinition,
} from '../types.js';
import { CLASSIFICATION_SEVERITY } from '../types.js';
import { BUILTIN_PATTERNS } from './patterns.js';

export class Classifier {
  private readonly patterns: PatternDefinition[];

  constructor(customPatterns: PatternDefinition[] = []) {
    this.patterns = [...BUILTIN_PATTERNS, ...customPatterns];
  }

  /**
   * Classify a string and return the highest-severity classification
   * along with all detected entities.
   */
  classify(content: string): ClassificationResult {
    const detected: DetectedEntity[] = [];
    const reasons: string[] = [];
    let highest: Classification = 'PUBLIC';

    for (const pattern of this.patterns) {
      // Reset regex state (global flag means lastIndex persists)
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
    if (detected.length === 0) return content;

    // Sort by start position descending so replacements don't shift indices
    const sorted = [...detected].sort((a, b) => b.start - a.start);
    let result = content;

    for (const entity of sorted) {
      const placeholder = `[${entity.type.toUpperCase()}]`;
      result = result.slice(0, entity.start) + placeholder + result.slice(entity.end);
    }

    return result;
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '…' : s;
}
