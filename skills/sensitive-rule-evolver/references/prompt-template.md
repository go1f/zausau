You are reviewing a sensitive information detection engine.

Current rules:
{{RULES_JSON}}

Validation evidence:
{{VALIDATION_JSON}}

Return strict JSON with this schema:
{
  "summary": "short summary",
  "notes": ["note 1", "note 2"],
  "proposed_rules": [
    {
      "id": "new-or-updated-rule-id",
      "name": "Rule name",
      "kind": "regex or field",
      "category": "category",
      "severity": "low|medium|high|critical",
      "description": "why this rule exists",
      "keywords": ["optional"],
      "patterns": ["optional regex"],
      "field_patterns": ["optional regex"],
      "value_patterns": ["optional regex"],
      "exclude_values": ["optional"],
      "exclude_value_patterns": ["optional regex"],
      "validation": "optional validator key",
      "min_entropy": 0,
      "require_assignment": true,
      "score": {
        "base": 0.0,
        "field_boost": 0.0,
        "entropy_boost": 0.0,
        "assignment_boost": 0.0
      }
    }
  ],
  "proposed_ignore_paths": ["optional path token"]
}

Constraints:
- Do not repeat the current rules unchanged.
- Prefer small edits that reduce false positives first.
- Avoid generic broad rules on `id`, `name`, `number`, or `value`.
- Keep every proposal compatible with a fast line-oriented Go scanner.
