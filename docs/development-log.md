# ARCHER Development Log

ARCHER is a deterministic, repository-local static analysis framework for identifying evidence-backed potential authorization drift in Rust/Actix-Web applications. Its findings support developer review and do not automatically establish confirmed vulnerabilities.

## 1. Initial Prototype

### Objective
Establish a working Rust/Actix-Web analyzer and an end-to-end command-line path.

### Work Completed
Implemented repository scanning, route extraction, basic authorization detection, initial peer grouping, and initial drift detection.

### Result
The first prototype demonstrated the core flow from Rust source to a potential-drift CLI report.

### Limitation / Learning
Authorization evidence and peer grouping were initially broad, and route source locations were imprecise. These were prototype limitations requiring more source-aware analysis.

### Next Step
Improve route context, source locations, and authorization evidence before broadening evaluation.

## 2. Scope and Source-Location Improvements

### Objective
Improve route interpretation across Actix scopes and make analysis results easier to trace to source.

### Work Completed
Added nested Actix scope tracking, more precise route locations, deterministic repository traversal, and malformed-file handling so an unparsable Rust file can be reported while other files continue to be analyzed.

### Result
The analyzer gained more reliable route paths and source references, with more predictable behavior across repository scans.

### Limitation / Learning
Route extraction remains dependent on the Actix-Web syntax patterns the analyzer recognizes; unsupported patterns can affect route coverage.

### Next Step
Associate route classifications with explicit authorization evidence and improve structural peer selection.

## 3. Authorization Evidence

### Objective
Make authorization classifications explainable and source-backed.

### Work Completed
Developed recognition for handler-level authorization calls, authorization guards, and authorization middleware, with evidence associated with routes and handlers. Evidence concepts include mechanism, symbol, source file and line, handler, and strength. Identity extraction is treated as distinct from authorization enforcement.

### Result
The analysis direction shifted from unexplained authorization labels toward evidence-backed findings that can be reviewed against source.

### Limitation / Learning
Recognition is limited to authorization idioms and source patterns that the current analyzer can identify; identity presence alone cannot establish an authorization check.

### Next Step
Use the evidence together with route structure when forming peer groups and inferring repository-local invariants.

## 4. Peer-Group Improvements

### Objective
Compare routes that are structurally meaningful peers rather than grouping by a broad prefix alone.

### Work Completed
Refined peer grouping around scope, HTTP method, route shape, path-segment structure, and dynamic parameters. Context such as handler information can be considered where appropriate. Method separation avoids treating different operations as equivalent merely because their paths share a scope.

### Result
Peer comparisons became more structurally constrained. The work also established that routes such as login, register, and logout must not automatically be grouped as authorization peers simply because they share `/api`.

### Limitation / Learning
Conservative structural constraints can leave a route with too few authorized peers to support an inferred invariant.

### Next Step
Test the threshold and structural signals against a controlled benchmark with known expected behavior.

## 5. Real Repository Evaluation

### Objective
Exercise route extraction and authorization-evidence recognition on real Actix-Web repositories.

### Work Completed
Testing against real repositories exposed framework and route-pattern limitations that are not represented by the simplest prototype cases.

### Result
The evaluation motivated explicit attention to supported Actix-Web constructs and source patterns.

### Limitation / Learning
No repository counts or quantitative metrics are recorded in this development-log milestone; no numerical result is claimed here.

### Next Step
Use a controlled dataset with explicit ground truth to measure behavior reproducibly.

## 6. Controlled Benchmark

### Objective
Measure route-level detection against a known set of clean and drift cases.

### Work Completed
Ran ARCHER against 20 controlled Actix-Web repositories containing 73 routes and explicit ground truth.

### Result
The evaluation produced 5 findings: TP=5, FP=0, FN=1, and TN=67. Precision was 100%, recall was 83.33%, F1 was 90.91%, and false positives per 1,000 routes was 0.

### Limitation / Learning
One expected drift route was missed. These controlled results do not establish general production performance or comparison with other static analysis tools.

### Next Step
Analyze the false negative and investigate whether peer evidence can be used more effectively.

## 7. Current Limitation

### Objective
Document the main limitation identified by the controlled benchmark.

### Work Completed
Reviewed the missed parameterized route in `18_parameter_drift`: `GET /admin/payments/{id}` was extracted as unauthenticated but was not reported.

### Result
The matching peer group had only one protected route with the same method and route shape, below the current two-authorized-peer threshold.

### Limitation / Learning
The result identifies a peer-grouping / invariant-inference limitation and accounts for the benchmark's one false negative.

### Next Step
Study whether additional structural evidence can support cautious inference when only one authorized peer is available.

## 8. Next Milestone

### Objective
Investigate single-peer inference while preserving the benchmark's zero-false-positive result.

### Work Completed
The next experiment is defined; no improvement result is claimed at this stage.

### Result
A repeatable comparison criterion is established using the existing controlled benchmark.

### Limitation / Learning
Lowering the peer threshold may improve recall but could introduce false positives; the tradeoff must be measured rather than assumed.

### Next Step
Evaluate changes by rerunning the same 20 repositories and comparing precision, recall, F1, and false positives.

## 9. Analyzer Hardening

### Objective
Fix the extraction, evidence, and inference problems listed in `docs/improvement-plan.md` (IDs A1-D4), each with a regression test built from a probe fixture in `tests/fixtures/probes/`.

### Work Completed
Split `src/analyzer.rs` into `src/analyzer/{model,routes,handlers,evidence,drift}.rs` with no behaviour change (D4). Route extraction now re-roots `#[get]`-style handlers at the `.service(handler)` call that registers them (A1), expands `.configure(f)` under the caller's scope prefix and middleware (A2), recognizes `#[actix_web::get]` and `#[route(..., method = ...)]` (A3), registers `web::resource(path).to(handler)` (A4), and resolves string-constant paths while keeping unresolvable ones with a warning (A5). Discovery skips `target/`, hidden directories, and by default `tests/`, `examples/`, `benches/` (A6); unreadable files are reported instead of aborting (A7); routes are reported in source order (C5). Handler signatures (authorization extractors such as `AdminUser`) and authorization attribute macros (`#[protect]`, `#[has_roles]`) now count as evidence (B1, B2). Peers must share a full-path prefix (C1); only an endpoint's last segment marks it as an authentication route (C4); findings require a configurable dominance threshold and minimum support (C2). Findings are now categorized: routes with no authorization evidence remain `MissingAuthorization`, and routes whose best evidence tier (privilege > resource > identity) is below the tier a dominant share of their peers reach are reported as `WeakerAuthorization`, with both tiers and all evidence in the finding (C3). The CLI gained `--fail-on-findings` with exit codes 0/1/2 (D1), renders findings from the structured `finding_details`, which is now the only finding list in the JSON (D2), and prints readable evidence names (D3).

### Result
70 unit tests and 3 CLI tests pass, up from 51. Every probe fixture now produces the expected routes and findings.

### Limitation / Learning
The controlled benchmark could not be re-run: its 20 repositories were never committed, so no before/after metrics are available for these changes. Extractor and attribute evidence are naming heuristics; extractor implementations are not inspected. The tier ranking treats all privilege mechanisms as equivalent, so a route that checks a different role than its peers is not flagged.

### Next Step
Restore or rebuild the benchmark dataset, rerun it at the default thresholds, then sweep `--threshold` and `--min-support` and record precision, recall, and false positives for each setting.
