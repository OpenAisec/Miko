<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Complex System Analysis Techniques

On-demand reference for analyzing large, complex software systems during threat modeling. Covers architecture discovery, data/control flow tracing, call chain analysis, and program logic understanding.

**When to load**: P1 (Project Understanding) for systems with >50 modules, P2 (DFD Analysis) when manual code reading is insufficient, P4 (Security Design Review) for deep static analysis.

---

## 1. Architecture Discovery (P1 Enhancement)

### UC-01: Module-Level Architecture

**When**: Target project is large (>100 files) and architecture is not documented.

```
1. luoshu_status(repo="<target>")               → confirm indexed
2. luoshu_query_dfd()                            → system-level DFD candidates
3. luoshu_query_chain(symbol="<main>",
     edge_kind="IMPORTS", max_depth=2)           → top-level module structure
4. luoshu_export(format="mermaid")               → architecture diagram
```

**Output**: DFD candidate list + Mermaid diagram + import tree → feeds P1 module inventory.

**Integration with P1**: DFD candidates map directly to threat-modeling modules (M-001, M-002...). Cross-reference with `module_discovery.py` output for completeness — `luoshu_query_dfd` finds architectural components that pattern-matching may miss.

### UC-02: Full Symbol Diagnostic

**When**: Need complete context on a critical function (auth handler, data processor, API endpoint).

```
luoshu_diagnose(symbol="app.auth.login", max_depth=2, include_flow=true, include_dfd=true)
```

Returns bundled: search results + callers + callees + CFG + DFG + DFD context in one call.

---

## 2. Data Flow Tracing (P2 Enhancement)

### UC-03: Source-to-Sink Tracing

**When**: Need to trace where user input flows — the core of DFD data flow mapping.

```
1. luoshu_query_flow(symbol="handler.process_input", graph_kind="dfg")
   → intraprocedural DFG (within one function)

2. luoshu_query_chain(symbol="handler.process_input",
     edge_kind="CALLS", direction="outbound", max_depth=5)
   → transitive callees (potential data sinks)

3. (If cross-function flow needed) Joern via Bash:
   joern-parse --language python /path/to/repo
   joern
   joern> def src = cpg.call.name("request.get")
   joern> def snk = cpg.call.name("db.execute")
   joern> snk.reachableByFlows(src).l
```

**Output**: DFG + call chain + taint paths → feeds P2 data flow inventory (DF-001, DF-002...).

**Integration with P2**: Each taint path from source to sink = one data flow in the DFD. Luoshu provides the intraprocedural view; Joern provides the interprocedural view. Together they give complete data flow coverage.

### UC-04: Control Flow Analysis

**When**: Verifying that security checks are on all execution paths.

```
1. luoshu_query_flow(symbol="auth.validate_token", graph_kind="cfg")
   → CFG basic blocks and branch conditions

2. luoshu_export(format="dot", symbol="auth.validate_token", graph_kind="cfg")
   → DOT graph for visualization
```

**Output**: CFG with all paths → evidence for "all paths enforce authentication" (or "path X bypasses it").

---

## 3. Call Chain Analysis (P2/P3 Enhancement)

### UC-05: Function Call Graph

**When**: Mapping call relationships for DFD construction.

```
1. luoshu_query_calls(symbol="<func>")           → direct callers/callees
2. luoshu_query_chain(symbol="<func>",
     edge_kind="CALLS", direction="inbound",
     max_depth=3)                                 → 3-hop caller chain (attack surface)
3. luoshu_query_chain(symbol="<func>",
     edge_kind="CALLS", direction="outbound",
     max_depth=3)                                 → 3-hop callee chain (impact scope)
```

**Pitfalls**:
- `max_depth > 5` causes combinatorial explosion — start with 3
- `luoshu_query_calls` precision is `may` — over-approximate for dynamic dispatch
- Cross-validate with CGC `analyze_code_relationships(query_type="find_all_callers")` for completeness

### UC-06: Variable/Config Reference Tracking

**When**: Need to find all readers/writers of a security-critical variable.

```
1. luoshu_query_search(symbol="config.SECRET_KEY")
2. CGC analyze_code_relationships(query_type="who_modifies", target="SECRET_KEY")
3. luoshu_query_neighbors(fact_id=<from_step_1>, direction="inbound")
```

---

## 4. Security Static Analysis (P4 Enhancement)

### UC-07: CodeQL Security Pipeline

**When**: Automated security vulnerability scanning during P4 Security Design Review.

```
# One-shot (Luoshu-integrated)
luoshu_auto_codeql(languages=["python"], repo="<target>")

# Or full pipeline (custom queries)
1. codeql_database_create(language="python", source="<target>")
2. codeql_database_analyze(database="<db>", suite="python-security-extended")
3. sarif_list_rules(sarif="<results>")
4. sarif_extract_rule(sarif="<results>", rule_id="py/sql-injection")
```

**Integration with P4**: SARIF findings map to security gaps (GAP-001, GAP-002...). Each SARIF rule corresponds to a CWE, which maps to threat-modeling's existing CWE-CAPEC-ATT&CK knowledge base.

### UC-08: Dead Code & Complexity

**When**: Identifying high-risk code areas for focused security review.

```
1. CGC find_dead_code()                          → unreachable functions
2. CGC find_most_complex_functions(top_n=20)     → complexity hotspots
```

Dead code + high complexity = high-priority areas for P4 security review.

---

## 5. Handling Large Codebases

**Decomposition strategy** (for systems >200 files):
1. Use `luoshu_query_dfd` to identify top-level components first
2. Analyze each component independently with `luoshu_query_dfd(path="<component>")`
3. Set `limit=50` on all queries to prevent context overflow
4. Use P2's sub-agent traversal system for parallel component analysis
5. Merge results via `phase_data.py --p2-merge-traversal`

**Result limiting rules**:
- `limit=20` for initial exploration
- `limit=50` for focused component analysis
- `max_depth=3` for call chains (increase to 5 only when needed)
- Never query entire repo without path/component filter on large codebases
