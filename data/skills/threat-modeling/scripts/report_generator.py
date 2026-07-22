#!/usr/bin/env python3
# Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

"""
Report Generator: Batch Markdown → HTML converter for threat modeling reports.

Converts Risk_Assessment_Report/*.md files to styled HTML with:
- Terminal aesthetic CSS (reused from md_to_html.py style)
- CJK font stack (Sarasa Term SC, Noto Sans Mono CJK SC, PingFang SC)
- Mermaid CDN rendering (client-side via mermaid.min.js)
- Severity color coding (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue)
- Navigation sidebar with report index
- Index page (index.html) linking all reports
- Print-friendly media queries

Usage:
    # Convert all reports in a Risk_Assessment_Report directory
    python report_generator.py --input /path/to/Risk_Assessment_Report

    # Convert with explicit output directory
    python report_generator.py --input /path/to/Risk_Assessment_Report --output /path/to/html

    # Convert single file
    python report_generator.py --file /path/to/report.md --output /path/to/output.html

    # Include detailed VR reports (if P8R was executed)
    python report_generator.py --input /path/to/Risk_Assessment_Report --detailed
"""

SCHEMA_VERSION = "3.2.0 (20260512a)"

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
import html as html_mod

try:
    import markdown
except ImportError:
    print("ERROR: 'markdown' package required. Install: pip install markdown", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# Mermaid CDN URL
# =============================================================================
MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"


# =============================================================================
# Severity Color Map
# =============================================================================
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",  # red
    "HIGH": "#fd7e14",      # orange
    "MEDIUM": "#ffc107",    # yellow
    "LOW": "#0d6efd",       # blue
}


# =============================================================================
# CSS: Terminal aesthetic with severity colors and sidebar
# =============================================================================
CSS_BASE = """
* { margin: 0; padding: 0; box-sizing: border-box; }

html {
    font-size: 14px;
    line-height: 1.6;
}

body {
    font-family: "Sarasa Term SC", "Noto Sans Mono CJK SC",
                 "PingFang SC", "Microsoft YaHei", "Hiragino Sans GB",
                 "Courier New", "Liberation Mono", "Consolas", monospace;
    color: #1a1a1a;
    background: #fafafa;
    display: flex;
    min-height: 100vh;
}

/* Sidebar navigation */
.sidebar {
    width: 260px;
    min-width: 260px;
    background: #2b2b2b;
    color: #e0e0e0;
    padding: 1.5rem 1rem;
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    overflow-y: auto;
    font-size: 0.82rem;
    z-index: 100;
}

.sidebar h3 {
    color: #fff;
    font-size: 0.95rem;
    margin-bottom: 0.8em;
    padding-bottom: 0.4em;
    border-bottom: 1px solid #555;
}

.sidebar ul {
    list-style: none;
    margin: 0;
    padding: 0;
}

.sidebar li { margin: 0.2em 0; }

.sidebar a {
    color: #b0b0b0;
    text-decoration: none;
    display: block;
    padding: 0.2em 0.4em;
    border-radius: 3px;
    transition: background 0.15s, color 0.15s;
}

.sidebar a:hover {
    background: #3a3a3a;
    color: #fff;
}

.sidebar a.active {
    background: #444;
    color: #fff;
    font-weight: bold;
}

.sidebar .section-label {
    color: #888;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 1em;
    margin-bottom: 0.3em;
    padding-left: 0.4em;
}

/* Main content */
.content {
    margin-left: 260px;
    max-width: 960px;
    padding: 2rem 2.5rem;
    flex: 1;
}

h1, h2, h3, h4 {
    font-weight: bold;
    margin-top: 2em;
    margin-bottom: 0.5em;
    border-bottom: 1px solid #ccc;
    padding-bottom: 0.3em;
}

h1 { font-size: 1.6rem; border-bottom: 2px solid #333; }
h2 { font-size: 1.35rem; }
h3 { font-size: 1.15rem; border-bottom: 1px dashed #ddd; }
h4 { font-size: 1rem; border-bottom: none; }

p { margin: 0.6em 0; }

/* Code blocks: preserve ASCII art */
pre {
    font-family: "Courier New", "Liberation Mono", monospace;
    background: #f0f0f0;
    border: 1px solid #ccc;
    border-left: 3px solid #888;
    padding: 0.8em 1em;
    margin: 1em 0;
    overflow-x: auto;
    white-space: pre;
    font-size: 0.85rem;
    line-height: 1.4;
}

code {
    font-family: "Courier New", "Liberation Mono", monospace;
    background: #eee;
    padding: 0.1em 0.3em;
    font-size: 0.9em;
}

pre code {
    background: none;
    padding: 0;
    font-size: inherit;
}

/* Mermaid diagram blocks */
pre.mermaid {
    background: #fff;
    border: 1px solid #ddd;
    border-left: 3px solid #6366f1;
    text-align: center;
}

/* Tables */
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 0.88rem;
}

th, td {
    border: 1px solid #bbb;
    padding: 0.35em 0.6em;
    text-align: left;
    vertical-align: top;
}

th {
    background: #e8e8e8;
    font-weight: bold;
}

tr:nth-child(even) { background: #f5f5f5; }

/* Severity color badges */
.severity-critical { color: #fff; background: """ + SEVERITY_COLORS["CRITICAL"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-high { color: #fff; background: """ + SEVERITY_COLORS["HIGH"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-medium { color: #000; background: """ + SEVERITY_COLORS["MEDIUM"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-low { color: #fff; background: """ + SEVERITY_COLORS["LOW"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }

/* Blockquotes */
blockquote {
    border-left: 3px solid #999;
    padding-left: 1em;
    margin: 1em 0;
    color: #444;
}

hr {
    border: none;
    border-top: 1px solid #ccc;
    margin: 2em 0;
}

ul, ol { margin: 0.5em 0 0.5em 1.5em; }
li { margin: 0.2em 0; }

strong { font-weight: bold; }
em { font-style: italic; }

a { color: #1a1a1a; text-decoration: underline; }

/* TOC styling */
.toc {
    background: #f0f0f0;
    border: 1px solid #ccc;
    padding: 1em 1.5em;
    margin: 1em 0;
}
.toc ul { list-style: none; margin-left: 0; }
.toc li { margin: 0.15em 0; }
.toc a { text-decoration: none; }
.toc a:hover { text-decoration: underline; }

/* Print-friendly */
@media print {
    .sidebar { display: none; }
    .content { margin-left: 0; max-width: 100%; padding: 1cm; font-size: 11px; }
    pre { border: 1px solid #999; page-break-inside: avoid; }
    h2, h3 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
}

/* Mobile responsive */
@media (max-width: 768px) {
    .sidebar { display: none; }
    .content { margin-left: 0; padding: 1rem; }
}
"""


# =============================================================================
# CSS for index page (no sidebar)
# =============================================================================
CSS_INDEX = """
* { margin: 0; padding: 0; box-sizing: border-box; }

html { font-size: 14px; line-height: 1.6; }

body {
    font-family: "Sarasa Term SC", "Noto Sans Mono CJK SC",
                 "PingFang SC", "Microsoft YaHei", "Hiragino Sans GB",
                 "Courier New", "Liberation Mono", "Consolas", monospace;
    color: #1a1a1a;
    background: #fafafa;
    max-width: 960px;
    margin: 0 auto;
    padding: 2rem 2.5rem;
}

h1 { font-size: 1.6rem; border-bottom: 2px solid #333; padding-bottom: 0.3em; margin-bottom: 1em; }
h2 { font-size: 1.35rem; margin-top: 2em; margin-bottom: 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }

a { color: #1a1a1a; }
a:hover { color: #555; }

.report-list { list-style: none; padding: 0; }
.report-list li {
    padding: 0.6em 0.8em;
    border-bottom: 1px solid #eee;
}
.report-list li:hover { background: #f5f5f5; }
.report-list a { text-decoration: none; display: block; }
.report-list .report-title { font-weight: bold; }
.report-list .report-meta { font-size: 0.82rem; color: #777; margin-top: 0.2em; }

.severity-critical { color: #fff; background: """ + SEVERITY_COLORS["CRITICAL"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-high { color: #fff; background: """ + SEVERITY_COLORS["HIGH"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-medium { color: #000; background: """ + SEVERITY_COLORS["MEDIUM"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }
.severity-low { color: #fff; background: """ + SEVERITY_COLORS["LOW"] + """; padding: 0.1em 0.5em; border-radius: 3px; font-weight: bold; font-size: 0.85em; }

.footer { margin-top: 3em; padding-top: 1em; border-top: 1px solid #ccc; font-size: 0.82rem; color: #888; }

@media print {
    body { max-width: 100%; padding: 1cm; font-size: 11px; }
}
"""


# =============================================================================
# Conversion Functions
# =============================================================================

def fix_toc_anchors(html: str) -> str:
    """Add custom anchor IDs matching TOC href slugs to headings.

    The markdown toc extension strips CJK chars from IDs, so we inject
    additional <a> anchor tags with the full slug into each heading.
    """
    toc_targets = re.findall(r'href="#([^"]+)"', html)

    for slug in toc_targets:
        num_match = re.match(r"^(\d+)", slug)
        if not num_match:
            continue
        num = num_match.group(1)
        pattern = rf'(<h2 id="[^"]*">)({re.escape(num)}\.\s)'
        match = re.search(pattern, html)
        if match:
            anchor = f'<a id="{slug}"></a>'
            html = html.replace(match.group(0), f'{match.group(1)}{anchor}{match.group(2)}')

    return html


def apply_severity_badges(html: str) -> str:
    """Replace severity keywords with colored badge spans."""
    replacements = [
        (r'\b(CRITICAL)\b', r'<span class="severity-critical">\1</span>'),
        (r'\b(Critical)\b(?!\s*\()', r'<span class="severity-critical">\1</span>'),
    ]
    # Only apply in table cells and specific contexts to avoid over-matching
    # We do a targeted replacement in <td> elements
    def replace_in_td(m):
        td_content = m.group(0)
        for pattern, repl in [
            (r'(?<![<\w])\b(CRITICAL)\b', r'<span class="severity-critical">\1</span>'),
            (r'(?<![<\w])\b(HIGH)\b', r'<span class="severity-high">\1</span>'),
            (r'(?<![<\w])\b(MEDIUM)\b', r'<span class="severity-medium">\1</span>'),
            (r'(?<![<\w])\b(LOW)\b', r'<span class="severity-low">\1</span>'),
        ]:
            td_content = re.sub(pattern, repl, td_content)
        return td_content

    html = re.sub(r'<td>.*?</td>', replace_in_td, html, flags=re.DOTALL)
    return html


def convert_mermaid_blocks(html: str) -> str:
    """Convert fenced mermaid code blocks to Mermaid-renderable divs.

    Looks for <pre><code class="language-mermaid">...</code></pre>
    and converts them to <pre class="mermaid">...</pre> for client-side rendering.
    """
    pattern = r'<pre><code class="language-mermaid">(.*?)</code></pre>'
    replacement = r'<pre class="mermaid">\1</pre>'
    return re.sub(pattern, replacement, html, flags=re.DOTALL)


def extract_title(html: str, fallback: str = "Security Report") -> str:
    """Extract title from first H1 tag.

    Returns plain text (HTML-decoded) so callers can safely re-escape for their context.
    This prevents double-encoding (e.g. &amp;amp;) when the title is later html.escape()'d.
    """
    match = re.search(r"<h1[^>]*>(.*?)</h1>", html)
    title = match.group(1) if match else fallback
    title = re.sub(r"<[^>]+>", "", title)
    return html_mod.unescape(title)


def build_sidebar_html(report_files: list[dict], current_file: str = "") -> str:
    """Build sidebar navigation HTML from report file list."""
    main_reports = [r for r in report_files if not r.get("is_detailed")]
    detailed_reports = [r for r in report_files if r.get("is_detailed")]

    lines = ['<nav class="sidebar">']
    lines.append('<h3>Report Navigator</h3>')

    # Main reports
    lines.append('<div class="section-label">Main Reports</div>')
    lines.append("<ul>")
    lines.append(f'<li><a href="index.html">Index</a></li>')
    for r in main_reports:
        active = ' class="active"' if r["html_name"] == current_file else ""
        lines.append(f'<li><a href="{html_mod.escape(r["html_name"], quote=True)}"{active}>{html_mod.escape(r["display_name"])}</a></li>')
    lines.append("</ul>")

    # Detailed reports
    if detailed_reports:
        lines.append('<div class="section-label">Detailed VR Reports</div>')
        lines.append("<ul>")
        for r in detailed_reports:
            active = ' class="active"' if r["html_name"] == current_file else ""
            lines.append(f'<li><a href="{html_mod.escape(r["html_name"], quote=True)}"{active}>{html_mod.escape(r["display_name"])}</a></li>')
        lines.append("</ul>")

    lines.append("</nav>")
    return "\n".join(lines)


def convert_md_to_html(
    md_path: Path,
    html_path: Path,
    report_files: list[dict] | None = None,
    current_file: str = "",
) -> dict:
    """Convert a Markdown file to styled HTML with sidebar navigation.

    Returns dict with metadata about the conversion.
    """
    md_text = md_path.read_text(encoding="utf-8")

    md_processor = markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "nl2br", "sane_lists"],
        extension_configs={"toc": {"title": ""}},
    )
    html_body = md_processor.convert(md_text)

    # Post-processing
    html_body = fix_toc_anchors(html_body)
    html_body = apply_severity_badges(html_body)
    html_body = convert_mermaid_blocks(html_body)

    title = extract_title(html_body, fallback=md_path.stem)

    # Build sidebar if report list provided
    sidebar_html = ""
    if report_files:
        sidebar_html = build_sidebar_html(report_files, current_file)

    # Check if mermaid is used
    has_mermaid = 'class="mermaid"' in html_body
    mermaid_script = ""
    if has_mermaid:
        mermaid_script = f"""
<script src="{MERMAID_CDN}"></script>
<script>mermaid.initialize({{startOnLoad: true, theme: 'neutral'}});</script>
"""

    html_doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_mod.escape(title)}</title>
<style>
{CSS_BASE}
</style>
{mermaid_script}
</head>
<body>
{sidebar_html}
<main class="content">
{html_body}
</main>
</body>
</html>
"""

    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html_doc, encoding="utf-8")

    return {
        "source": str(md_path),
        "output": str(html_path),
        "title": title,
        "lines": len(md_text.splitlines()),
        "size_kb": html_path.stat().st_size / 1024,
        "has_mermaid": has_mermaid,
    }


def generate_index_page(
    html_dir: Path,
    report_files: list[dict],
    project_name: str = "Threat Assessment",
) -> Path:
    """Generate index.html with links to all reports."""
    main_reports = [r for r in report_files if not r.get("is_detailed")]
    detailed_reports = [r for r in report_files if r.get("is_detailed")]

    lines = []
    lines.append(f"<h1>{html_mod.escape(project_name)} - Report Index</h1>")
    lines.append(f'<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')

    # Main reports section
    lines.append("<h2>Main Reports</h2>")
    lines.append('<ul class="report-list">')
    for r in main_reports:
        lines.append(f"""<li><a href="{html_mod.escape(r['html_name'], quote=True)}">
<div class="report-title">{html_mod.escape(r['display_name'])}</div>
<div class="report-meta">{html_mod.escape(r['md_name'])}</div>
</a></li>""")
    lines.append("</ul>")

    # Detailed VR reports section
    if detailed_reports:
        lines.append("<h2>Detailed Risk Analysis Reports</h2>")
        lines.append('<ul class="report-list">')
        for r in detailed_reports:
            lines.append(f"""<li><a href="{html_mod.escape(r['html_name'], quote=True)}">
<div class="report-title">{html_mod.escape(r['display_name'])}</div>
<div class="report-meta">{html_mod.escape(r['md_name'])}</div>
</a></li>""")
        lines.append("</ul>")

    lines.append(f'<div class="footer">STRIDE Threat Modeling Skill v{SCHEMA_VERSION}</div>')

    body = "\n".join(lines)
    html_doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_mod.escape(project_name)} - Report Index</title>
<style>
{CSS_INDEX}
</style>
</head>
<body>
{body}
</body>
</html>
"""

    index_path = html_dir / "index.html"
    index_path.write_text(html_doc, encoding="utf-8")
    return index_path


# =============================================================================
# Report Discovery
# =============================================================================

# Known main report suffixes in display order
MAIN_REPORT_ORDER = [
    "RISK-ASSESSMENT-REPORT",
    "RISK-INVENTORY",
    "MITIGATION-MEASURES",
    "PENETRATION-TEST-PLAN",
    "ARCHITECTURE-ANALYSIS",
    "DFD-DIAGRAM",
    "COMPLIANCE-REPORT",
    "ATTACK-PATH-VALIDATION",
]


def discover_reports(input_dir: Path, include_detailed: bool = False) -> list[dict]:
    """Discover markdown report files in the input directory.

    Returns list of dicts with: md_path, md_name, html_name, display_name, is_detailed
    """
    reports = []

    # Main reports (*.md in root, excluding phase working files)
    md_files = sorted(input_dir.glob("*.md"))
    for md_path in md_files:
        name = md_path.stem
        # Skip phase working reports (P1-*, P2-*, etc.) — they're intermediate
        if re.match(r"^P\d+-", name):
            continue
        reports.append({
            "md_path": md_path,
            "md_name": md_path.name,
            "html_name": f"{name}.html",
            "display_name": name.replace("-", " ").title(),
            "is_detailed": False,
        })

    # Sort main reports by known order
    def sort_key(r):
        name = r["md_path"].stem
        for i, suffix in enumerate(MAIN_REPORT_ORDER):
            if name.endswith(suffix):
                return i
        return len(MAIN_REPORT_ORDER)  # unknown reports at end

    reports.sort(key=sort_key)

    # Detailed VR reports
    if include_detailed:
        detailed_dir = input_dir / "detailed"
        if detailed_dir.is_dir():
            vr_files = sorted(detailed_dir.glob("VR-*.md"))
            for vr_path in vr_files:
                name = vr_path.stem
                reports.append({
                    "md_path": vr_path,
                    "md_name": vr_path.name,
                    "html_name": f"detailed/{name}.html",
                    "display_name": name,
                    "is_detailed": True,
                })

    return reports


# =============================================================================
# Batch Conversion
# =============================================================================

def batch_convert(
    input_dir: Path,
    output_dir: Path | None = None,
    include_detailed: bool = False,
) -> dict:
    """Convert all reports in input_dir to HTML.

    Returns summary dict with conversion statistics.
    """
    if output_dir is None:
        output_dir = input_dir / "html"

    output_dir.mkdir(parents=True, exist_ok=True)

    # Discover reports
    reports = discover_reports(input_dir, include_detailed=include_detailed)

    if not reports:
        print(f"WARNING: No markdown reports found in {input_dir}", file=sys.stderr)
        return {"total": 0, "converted": 0, "errors": []}

    print(f"Found {len(reports)} report(s) in {input_dir}")

    # Extract project name from first report filename
    project_name = "Threat Assessment"
    if reports:
        first_name = reports[0]["md_path"].stem
        # Try to extract project prefix (e.g., "OPEN-WEBUI" from "OPEN-WEBUI-RISK-ASSESSMENT-REPORT")
        for suffix in MAIN_REPORT_ORDER:
            if first_name.endswith(suffix):
                prefix = first_name[: -(len(suffix) + 1)]  # strip "-SUFFIX"
                if prefix:
                    project_name = prefix.replace("-", " ")
                break

    results = []
    errors = []

    # Convert each report
    for report in reports:
        html_path = output_dir / report["html_name"]
        try:
            result = convert_md_to_html(
                md_path=report["md_path"],
                html_path=html_path,
                report_files=reports,
                current_file=report["html_name"],
            )
            results.append(result)
            print(f"  [{len(results):2d}] {report['md_name']} → {report['html_name']} ({result['size_kb']:.1f} KB)")
        except (OSError, ValueError, UnicodeDecodeError) as e:
            errors.append({"file": report["md_name"], "error": str(e)})
            print(f"  ERROR: {report['md_name']}: {e}", file=sys.stderr)

    # Generate index page
    index_path = generate_index_page(output_dir, reports, project_name=project_name)
    print(f"\n  Index: {index_path}")

    summary = {
        "total": len(reports),
        "converted": len(results),
        "errors": errors,
        "output_dir": str(output_dir),
        "index": str(index_path),
        "total_size_kb": sum(r["size_kb"] for r in results),
        "mermaid_count": sum(1 for r in results if r["has_mermaid"]),
    }

    print(f"\nConversion complete: {summary['converted']}/{summary['total']} reports")
    print(f"  Total size: {summary['total_size_kb']:.1f} KB")
    if summary["mermaid_count"]:
        print(f"  Mermaid diagrams: {summary['mermaid_count']} report(s)")
    if errors:
        print(f"  Errors: {len(errors)}", file=sys.stderr)

    return summary


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Batch Markdown → HTML converter for threat modeling reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --input ./Risk_Assessment_Report
  %(prog)s --input ./Risk_Assessment_Report --detailed
  %(prog)s --file ./report.md --output ./report.html
""",
    )
    parser.add_argument(
        "--input", "-i",
        type=Path,
        help="Risk_Assessment_Report directory to convert (batch mode)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output directory (default: {input}/html) or output file (single mode)",
    )
    parser.add_argument(
        "--file", "-f",
        type=Path,
        help="Single markdown file to convert",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Include detailed VR reports from detailed/ subdirectory",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"report_generator.py {SCHEMA_VERSION}",
    )

    args = parser.parse_args()

    if args.file:
        # Single file mode
        if not args.file.exists():
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        output = args.output or args.file.with_suffix(".html")
        result = convert_md_to_html(args.file, output)
        print(f"Generated: {result['output']}")
        print(f"  Source: {result['source']} ({result['lines']} lines)")
        print(f"  Output: {result['size_kb']:.1f} KB")

    elif args.input:
        # Batch mode
        if not args.input.is_dir():
            print(f"ERROR: Directory not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        summary = batch_convert(
            input_dir=args.input,
            output_dir=args.output,
            include_detailed=args.detailed,
        )
        if summary["errors"]:
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
