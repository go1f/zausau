---
name: sensitive-rule-evolver
description: Use when iterating or reviewing sensitive-information detection rules, especially for reducing shallow false positives, improving secret and PII recall, and turning labeled scan results into updated rule proposals for the Go scanner in this repository.
---

# Sensitive Rule Evolver

This skill is for improving the sensitive-information scanner in this repository.

## Goals

- Improve recall for secrets, credentials, PII, biometrics, financial profile, social graph, location, and personal media fields.
- Reduce shallow and common false positives before adding new broad rules.
- Produce rule changes that stay externalized in config instead of hard-coding patterns into Go logic unless performance or correctness requires it.

## Required workflow

1. Read the current rule config in `configs/default-rules.json`.
2. Read validation evidence:
   - built-in manifest: `testdata/samples/manifest.json`
   - external dataset manifests under `testdata/datasets/` when present
   - model suggestions in `artifacts/rule-suggestions.json` when present
3. Separate misses into:
   - weak rule coverage
   - bad exclusions
   - weak assignment extraction
   - overly strict scoring
4. Separate false positives into:
   - placeholder or demo values
   - hashes, UUIDs, masked values, env references
   - generic field names without sensitive values
   - docs or fixtures that should be explicitly ignored
5. Prefer the smallest safe fix:
   - add or tighten `field_patterns`
   - add `exclude_values` or `exclude_value_patterns`
   - add validators
   - only widen regexes after checking likely noise impact
6. After proposing changes, run:
   - `go test ./...`
   - `go run ./cmd/senscan validate -manifest testdata/datasets/regression-manifest.json`
7. Run proposal review:
   - static lint on proposed rules
   - model reviewer on the proposal and simulated validation result
8. Only keep rule proposals that improve recall without blowing up false positives.

## Rule design guidance

- Prefer `field` rules for categories driven by field names and assigned values.
- Prefer `regex` rules for strong formats like JWT, PEM blocks, phones, and Chinese ID cards.
- Use `keywords` as cheap prefilters for expensive regexes.
- Use `min_entropy` only for values that should look random.
- Add shallow false-positive handling first:
  - placeholders such as `your_token_here`
  - demo/test/sample/fake values
  - masked strings
  - UUIDs and common hashes
  - variable references like `${TOKEN}`
- Avoid broad rules on generic names such as `number`, `name`, or `id` unless the value format is also strong.

## Model-assisted loop

- When using a local copilot-api model, provide:
  - compact current rule summary
  - validation report with false positives and misses
  - required JSON output schema
- Treat model output as a proposal, not ground truth.
- Validate every proposal against fixtures before merging it into `configs/default-rules.json`.
- Require proposal review artifacts before merging:
  - `artifacts/rule-suggestions.json`
  - `artifacts/rule-review.json`

## References

- Prompt template for the `learn` command:
  - `skills/sensitive-rule-evolver/references/prompt-template.md`
