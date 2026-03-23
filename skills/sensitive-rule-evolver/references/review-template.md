You are reviewing a proposed update to a sensitive information detection ruleset.

Base rules:
{{BASE_RULES_JSON}}

Proposed suggestion:
{{SUGGESTION_JSON}}

Static review findings:
{{STATIC_FINDINGS_JSON}}

Simulated validation after applying the proposal:
{{SIMULATED_VALIDATION_JSON}}

Return strict JSON with this schema:
{
  "summary": "short review summary",
  "approved": true,
  "findings": [
    {
      "rule_id": "optional rule id",
      "severity": "low|medium|high|critical",
      "source": "model-review",
      "title": "short finding title",
      "detail": "one paragraph describing the risk or why it is acceptable"
    }
  ]
}

Review rules:
- Be conservative about broad regexes, broad field rules, and broad ignore paths.
- Reject proposals that would likely increase false positives without clear recall gains.
- Prefer provider-specific credential patterns and assignment-aware field rules.
- If simulated validation misses the configured precision/recall/FDR gates, set approved to false.
- Do not suggest code changes. Review the proposal only.
