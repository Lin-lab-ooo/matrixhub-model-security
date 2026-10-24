# Portable32 finite-token regression

This package preserves every original v3 test function, assertion, case list and factory. Only the old absolute runtime configuration/startup block is replaced. token_loader.py remains exact original bytes; it SHA-binds then extracts only finite AST token definitions, never imports the whole scanner, Torch, pickle, a model or a serialization loader. No fixture bytes are generated.

Default: `python run_portable.py` describes with zero source reads/tests. Importing the test module only defines tests; it does not run them or read scanner files.

From the MatrixHub Go project root (the source/ directory), run:

`python tests/portable-token-tests/run_portable.py --execute --source deploy/security-scanner/scanner.py --source-sha <actual full production source SHA256>`

The frozen baseline fixture is relative to the runner (`fixtures/scanner-baseline-3619.py`,190947B,SHA3619a7f3e1f966cefa0a96dfa7d1e3c08895bbb690cf7bfd51bdf1a96bd5f2fe). Optional `--baseline <path> --baseline-sha <3619 full SHA>` selects another exact copy. Current source is mandatory, external to this test package, and SHA-checked before and after; no current candidate scanner is bundled or silently copied. Old HERE/scanner assertions resolve to the caller's actual source path through a small path binding.

Expected candidate source for this prepared change is5fa1c563389f6b70ce16d9a7c3e60fc7c5a452ede2871a231b7e386147500c57. Final production-checkout validation must be run against that actual checkout after integration. The included relocation proof runs copied test packages in two fresh ordinary temporary paths against the existing frozen source file only; it proves portability and does not claim an unmodified production checkout already adopted/passed this candidate.

Only finite in-memory VM tokens are used. No Torch/pickle import, serialize/deserialize, generated payload, network or Docker. This is32 development regressions, not independent holdout, AV, APP, population accuracy or deployment approval. ROOT owns DCO/Git integration separately.
