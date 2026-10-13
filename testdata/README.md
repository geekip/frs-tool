# Test data

- `frs/empty-v1.golden.hex` is an independently specified FRS 1.0 empty-container byte vector.
- `frs/comprehensive-v1.golden.hex` freezes the deterministic writer output for same-name cross-kind sets, empty sets, merged and maximum IPv4 ranges, exact/suffix coexistence, keywords, compressed trie edges, and UTF-8 labels. The semantic values are declared independently in `internal/frs/frs_test.go`; real C-loader interoperability is checked separately rather than treating this writer-produced vector as independent proof.
- `input/mixed-rules.txt` exercises supported mixed line syntaxes, IPv6 filtering, and warning-only entries.
- `expected/mixed-rules.json` records the normalized outcomes by source line.
- `query-vectors.json` checks the reference IPv4 and domain matching semantics over those outcomes.

The empty container is valid at the binary-format layer. The future build command must still reject an all-empty result before publication.
