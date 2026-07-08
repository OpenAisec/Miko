---
category: custom
name: medical-cybersecurity-report
description: Generate medical device cybersecurity registration deliverables from project input files. Use when Codex needs to read DOCX/PDF/PNG project evidence such as user manuals, SRS, design documents, architecture diagrams, FDA cybersecurity guidance, or prior reports, then produce a cybersecurity risk management report draft, project fact sheet, missing-information list, traceability content, STRIDE threat model, risk analysis, SBOM/security-transparency notes, or user-manual cybersecurity supplement.
---

# Medical Cybersecurity Report

Use this skill to produce high-completion cybersecurity registration drafts for medical device projects. Treat the output as a controlled draft: derive product-specific facts from evidence, mark unsupported claims as gaps, and require human review for final regulatory, quality, test, SBOM, and vulnerability conclusions.

Reusable scripts, references, and templates are stored in this skill folder. Project-specific generated deliverables are written only to the project output folder passed by `--output`.

## Required Workflow

1. Inventory the project folder. Identify input documents, output targets, prior reports, architecture images, and regulatory references.
2. Run `scripts/generate_report_package.py --input <project-input-dir> --output <output-dir>` to create deterministic extraction artifacts.
3. Read the generated `project_fact_sheet.md`, `evidence_index.md`, and `missing_information.md`.
4. Load only the needed references:
   - Use `references/workflow.md` for the full production workflow.
   - Use `references/report-section-rules.md` when drafting or revising report sections.
   - Use `references/regulatory-matrix.csv` when checking FDA cybersecurity coverage.
   - Use `references/medical-device-taxonomy.md` before adapting examples to classify the device generically.
   - Use `references/security-requirements-library.csv` when building SRS/SDD/SVV traceability.
   - Use `references/threat-library.md` when building STRIDE threats and mitigations.
   - Use `references/transparency-library.csv` when drafting user-facing cybersecurity content.
   - Use `references/risk-scoring-rules.md` when drafting risk-analysis rows or residual-risk language.
   - Use `references/cybersecurity-test-planning.md` when deciding when to start tests and what evidence is needed.
   - Use `references/prior-report-patterns.md` only as optional adaptation examples from completed reports.
   - Use `assets/full-report-template.md` as the target report structure for complete report drafts.
   - Use `references/review-checklist.md` before finalizing outputs.
5. Draft or revise the deliverables in this order:
   - Project fact sheet with evidence citations.
   - Missing information and assumptions list.
   - Cybersecurity Risk Management Report draft.
   - User manual cybersecurity supplement list.
   - Review checklist with unresolved items.
6. Do not invent test completion, SBOM contents, vulnerability scan results, unresolved anomaly status, or final regulatory compliance. If evidence is missing, write a gap.
7. Preserve source language where practical. For Chinese submissions, write Chinese report prose and keep regulatory terms such as SRS, SDD, SVV, SBOM, STRIDE, SPDF, QMSR, and CVE unchanged.

## Evidence Rules

- Every product-specific claim should be supported by a source file, extracted quote, table entry, figure name, or explicit user instruction.
- Distinguish three levels:
  - `Evidence-backed`: directly present in source files.
  - `Reasonable inference`: inferred from multiple evidence points; label it for review.
  - `Gap`: required by the workflow but not supported by inputs.
- Never change a "gap" into a factual statement merely to make the report look complete.
- Keep a user-manual supplement list whenever report transparency content describes user-facing security controls, update behavior, SBOM access, network requirements, backup/recovery, audit logs, EOL/EOS, or sensitive-data disposal.
- Prior completed reports are low-weight examples only. First classify the device generically, then use evidence and the generic libraries. Adapt prior examples only when the current device facts, interfaces, and controls match.

## Script Usage

Generate a package from one project:

```powershell
python C:\Users\Administrator\.codex\skills\medical-cybersecurity-report\scripts\generate_report_package.py `
  --input "E:\path\project\input" `
  --output "E:\path\project\generated-output"
```

Validate a generated package:

```powershell
python C:\Users\Administrator\.codex\skills\medical-cybersecurity-report\scripts\validate_package.py `
  --package "E:\path\project\generated-output"
```

Refresh the prior-report pattern library after a report is finalized:

```powershell
python C:\Users\Administrator\.codex\skills\medical-cybersecurity-report\scripts\extract_report_patterns.py `
  --input "E:\path\completed-reports" `
  --output-json C:\Users\Administrator\.codex\skills\medical-cybersecurity-report\references\prior-report-patterns.json `
  --output-md C:\Users\Administrator\.codex\skills\medical-cybersecurity-report\references\prior-report-patterns.md
```

## Expected Outputs

The package should contain:

- `evidence_index.md`: source files and extracted text locations.
- `image_evidence.md`: image evidence inventory, copied image paths, dimensions, and review instructions.
- `architecture_review.md`: worksheet for extracting assets, interfaces, trust boundaries, and data flows from architecture images.
- `architecture_visual_findings.md`: AI/human visual-review findings from architecture images; merge into the final report after completion.
- `data_flow_diagram.png`: report-ready data-flow diagram inserted into section 4.2 of the report.
- `evidence_map.md/json`: evidence snippets mapped to product facts, interfaces, roles, update, SBOM, and other topics.
- `project_requirements.md/json`: structured requirements extracted from SRS/requirements/design-input documents.
- `project_fact_sheet.md`: structured product facts and evidence pointers.
- `missing_information.md`: gaps, assumptions, and review questions.
- `asset_inventory.md`: structured hardware, software, firmware, data, and communication assets.
- `interface_inventory.md`: interface functionality, direction, endpoint, and evidence table.
- `security_requirement_candidates.md`: project-level cybersecurity requirement candidates with inclusion reason and review confidence.
- `security_requirements.md`: generated SRS/SDD/SVV candidate rows.
- `traceability_matrix.md`: generated SRS-SDD-SVV traceability matrix.
- `stride_threat_model.md`: generated STRIDE threat model tables.
- `attack_tree.md`: attack-tree draft derived from the identified device, interfaces, and assets.
- `risk_analysis.md`: generated risk-analysis worksheet based on identified threats.
- `risk_control_matrix.md`: original-case-style risk-to-control matrix for report table filling.
- `security_architecture.md`: security use cases and interface/security architecture views.
- `cybersecurity_test_plan.md`: generated test-start criteria and cybersecurity test plan.
- `cybersecurity_management_plan.md`: postmarket vulnerability, patch, and response-plan draft.
- `report_gap_analysis.md`: comparison against prior-case completion patterns and remaining automation gaps.
- `prior_report_matches.md`: matching examples from completed reports for adaptation.
- `cybersecurity_report_draft.md`: report draft in the standard structure.
- `cybersecurity_report_draft.docx`: editable Word draft when `python-docx` is available.
- `user_manual_supplement.md`: user-facing cybersecurity content to add to the manual.
- `review_checklist.md`: final review gates.

To update the prior-report pattern library after a new report is finalized, run `scripts/extract_report_patterns.py` against finalized report DOCX files and write to `references/prior-report-patterns.json` plus `references/prior-report-patterns.md`.

## Quality Gates

Before responding to the user:

- Confirm whether the package generated successfully.
- State which files were created.
- State whether major gaps remain.
- If tests/scripts failed, report the command and failure plainly.
