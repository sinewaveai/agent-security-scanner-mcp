# Benchmark Results

Benchmark run: 2026-02-02 | Commit: `2f702d7` | Branch: `feb2`

## Approach

### Annotation-Based Corpus

The benchmark uses an annotation-based corpus where each code line is preceded by a comment describing the expected result:

- `# VULN: <rule-id-substring>` -- line should be flagged by the matching rule
- `# SAFE: <rule-id-substring>` -- line should **not** be flagged by the matching rule
- `# FP-PRONE: <rule-id-substring>` -- line is safe but known to trigger a false positive

The analyzer skips comment lines during scanning, so annotations are invisible to the detection engine. JavaScript files use `//` instead of `#`.

### Classification Logic

The benchmark runner (`benchmark_runner.py`) classifies each finding by matching it against annotations:

1. For each finding, check if the preceding line has a `VULN:` annotation with a matching rule ID substring. If so, it's a **true positive (TP)**.
2. If the preceding line has a `SAFE:` or `FP-PRONE:` annotation with a matching rule ID substring, it's a **false positive (FP)**.
3. Any `VULN:` annotation with no corresponding finding is a **false negative (FN)**.
4. Any `SAFE:` annotation with no corresponding finding is a **true negative (TN)**.
5. Findings on unannotated lines are tracked separately and do not affect precision/recall.

### Metrics

| Metric | Formula |
|--------|---------|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 Score | 2 * (Precision * Recall) / (Precision + Recall) |
| FP Rate | FP / (FP + TN) |
| Annotation Coverage | (TP + FP + FN + TN) / (TP + FP + FN + TN + unannotated) |

## Results

### Overall

| Metric | Value |
|--------|-------|
| Precision | 0.977 (43 TP / 44 flagged) |
| Recall | 1.000 (43 TP / 43 expected) |
| F1 Score | 0.989 |
| FP Rate | 2.9% (1 FP / 34 safe) |
| Annotation Coverage | 93.6% |

### Per-Language Breakdown

| Language | Precision | Recall | F1 | TP | FP | FN | TN |
|----------|-----------|--------|----|----|----|----|----|
| generic | 1.000 | 1.000 | 1.000 | 11 | 0 | 0 | 0 |
| javascript | 1.000 | 1.000 | 1.000 | 14 | 0 | 0 | 0 |
| python | 0.947 | 1.000 | 0.973 | 18 | 1 | 0 | 0 |

### Corpus Coverage

| File | VULN | SAFE | FP-PRONE |
|------|------|------|----------|
| `generic_secrets.txt` | 9 | 9 | 0 |
| `javascript_injection.js` | 9 | 7 | 0 |
| `javascript_xss.js` | 5 | 5 | 0 |
| `python_crypto.py` | 9 | 6 | 1 |
| `python_injection.py` | 11 | 6 | 0 |
| **Total** | **43** | **33** | **1** |

### Unannotated Findings (3)

These are findings on lines without annotations. They don't affect metrics but indicate where annotation coverage can be improved.

- `javascript_injection.js:11` -- `function-constructor` (duplicate match on same line)
- `javascript_injection.js:54` -- `insecure-hash-md5`
- `javascript_injection.js:57` -- `insecure-hash-sha1`

## False Positive Analysis

### The single FP: `python.lang.security.crypto.insecure-hash-md5`

**Location:** `benchmarks/corpus/python_crypto.py:21`

```python
# FP-PRONE: insecure-hash-md5 (checksum, not security)
checksum = hashlib.md5(file_bytes).hexdigest()
```

**Why it's flagged:** The regex pattern `hashlib\.md5` matches all uses of `hashlib.md5()`, regardless of whether the hash is used for security (password hashing, signatures) or non-security purposes (file checksums, cache keys).

**Why it's a false positive:** MD5 is being used here as a file checksum -- not for any security-sensitive operation. Using MD5 for checksums is a common and acceptable practice.

**Root cause:** Regex-based pattern matching cannot distinguish between security-sensitive and non-security uses of the same API. This is a fundamental limitation of the approach.

## Recommendations

1. **Context-aware rules or allowlisting** -- Consider adding heuristics to suppress `insecure-hash-md5` when the result is assigned to a variable named `checksum`, `digest`, or similar. Alternatively, support inline suppression comments.

2. **Expand FP-PRONE corpus** -- Add more `FP-PRONE` annotations for other patterns known to have false-positive-prone usage (e.g., `eval()` in build tools, `exec()` in migration scripts). This will track FP rate as rules evolve.

3. **Add Go and Java corpus files** -- The rule set includes `go.security.yaml` and `java.security.yaml`, but the benchmark corpus currently only covers Python, JavaScript, and generic secrets. Adding Go and Java corpus files would provide full language coverage.

4. **Annotate remaining unannotated findings** -- The 3 unannotated findings in `javascript_injection.js` should be annotated to reach 100% annotation coverage.
