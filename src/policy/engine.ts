import type {
  PolicyDefinition,
  PolicyDecision,
  PolicyRule,
  Classification,
  Destination,
} from '../types.js';
import { CLASSIFICATION_SEVERITY } from '../types.js';
import { Classifier } from '../classify/classifier.js';

export class PolicyEngine {
  private policy: PolicyDefinition;
  private readonly classifier: Classifier;

  constructor(policy: PolicyDefinition, classifier: Classifier) {
    this.policy = policy;
    this.classifier = classifier;
  }

  updatePolicy(policy: PolicyDefinition): void {
    this.policy = policy;
  }

  getPolicy(): PolicyDefinition {
    return this.policy;
  }

  /**
   * Evaluate content against the active policy for a given destination.
   *
   * Returns the decision (allow/block/redact/ask/log_only), the matched
   * rule, classification result, and optionally redacted content.
   */
  evaluate(content: string, destination: Destination): PolicyDecision {
    const { classification, detected, reasons } = this.classifier.classify(content);

    const matchedRule = this.findMatchingRule(classification, destination);

    const action = matchedRule
      ? matchedRule.action
      : this.policy.default_action;

    const ruleIndex = matchedRule
      ? this.policy.rules.indexOf(matchedRule)
      : null;

    let redacted_content: string | null = null;
    if (action === 'redact') {
      redacted_content = this.classifier.redact(content, detected);
    }

    return {
      action,
      rule_index: ruleIndex,
      classification,
      destination,
      detected,
      redacted_content,
      reasons,
    };
  }

  /**
   * Find the first rule that matches the classification and destination.
   *
   * Rules are evaluated in order. The first match wins. This gives policy
   * authors explicit control over precedence.
   */
  private findMatchingRule(
    classification: Classification,
    destination: Destination
  ): PolicyRule | null {
    for (const rule of this.policy.rules) {
      if (!this.classificationMatches(rule, classification)) continue;
      if (!this.destinationMatches(rule, destination)) continue;
      return rule;
    }
    return null;
  }

  private classificationMatches(rule: PolicyRule, classification: Classification): boolean {
    const ruleClassifications = Array.isArray(rule.classification)
      ? rule.classification
      : [rule.classification];

    return ruleClassifications.some(
      rc => CLASSIFICATION_SEVERITY[rc] <= CLASSIFICATION_SEVERITY[classification]
    );
  }

  private destinationMatches(rule: PolicyRule, destination: Destination): boolean {
    if (!rule.destinations || rule.destinations.length === 0) return true;
    return rule.destinations.includes(destination);
  }
}
