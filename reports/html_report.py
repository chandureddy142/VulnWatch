import html
import json
import os
from typing import Any, Dict, Optional

from database.models import Scan


def _extract_recon(scan: Scan) -> Optional[Dict[str, Any]]:
    """Extract passive recon data stored in scan.response_headers['_recon'], if present."""
    if not scan.response_headers or "_recon" not in scan.response_headers:
        return None
    return scan.response_headers["_recon"]


def _render_recon_section(recon: Dict[str, Any]) -> str:
    """Render the Perimeter Reconnaissance & Asset Intelligence HTML section."""
    tls_info = recon.get("tls_info", {})
    redirect_chain = recon.get("redirect_chain", [])
    spf = recon.get("spf_record")
    dmarc = recon.get("dmarc_record")
    dkim = recon.get("dkim_selectors_found", [])
    tech = recon.get("detected_tech", [])
    subdomains = recon.get("ct_subdomains", [])
    ct_count = recon.get("ct_subdomain_count", 0)
    dangling = recon.get("dangling_cnames", [])

    uses_tls = tls_info.get("uses_tls", False)
    http_redirect = tls_info.get("http_to_https_redirect")
    hop_count = max(0, len(redirect_chain) - 1)
    final_dest = redirect_chain[-1]["url"] if redirect_chain else "—"

    dmarc_enforced = bool(dmarc) and "p=none" not in (dmarc or "").lower()

    def status_badge(ok: bool, ok_label: str = "PASS", fail_label: str = "MISSING") -> str:
        cls = "recon-status-ok" if ok else "recon-status-fail"
        label = ok_label if ok else fail_label
        return f'<span class="{cls}">{label}</span>'

    # ── TLS & Redirect Chain table ────────────────────────────────────────────
    tls_rows = f"""
        <tr><td class="recon-td-label">HTTPS / TLS Enabled</td>
            <td>{status_badge(uses_tls, "ACTIVE", "NOT USED")}</td></tr>
        <tr><td class="recon-td-label">HTTP → HTTPS Redirect</td>
            <td>{status_badge(bool(http_redirect), "ACTIVE", "NOT CONFIGURED")}</td></tr>
        <tr><td class="recon-td-label">Redirect Hops</td>
            <td><code>{hop_count}</code></td></tr>
        <tr><td class="recon-td-label">Final Destination</td>
            <td><code class="recon-mono">{html.escape(str(final_dest))}</code></td></tr>
    """

    if redirect_chain:
        chain_rows = "".join(
            f'<tr><td class="recon-chain-code">{html.escape(str(h.get("status_code", "")))} </td>'
            f'<td class="recon-chain-url"><code>{html.escape(h.get("url", ""))}</code></td></tr>'
            for h in redirect_chain
        )
        tls_rows += f"""
        <tr><td colspan="2" class="recon-td-sub">
            <div class="recon-sub-label">Redirect Chain</div>
            <table class="recon-chain-table">{chain_rows}</table>
        </td></tr>"""

    # ── DNS Email Security table ───────────────────────────────────────────────
    dmarc_display = "MISSING"
    dmarc_cls = "recon-status-fail"
    if dmarc:
        if "p=none" in dmarc.lower():
            dmarc_display = "p=none (NOT ENFORCED)"
            dmarc_cls = "recon-status-warn"
        else:
            dmarc_display = "ENFORCED"
            dmarc_cls = "recon-status-ok"

    dns_rows = f"""
        <tr><td class="recon-td-label">SPF Record</td>
            <td>{status_badge(bool(spf))}
            {f'<div class="recon-record-val"><code>{html.escape(spf[:120])}{"…" if len(spf) > 120 else ""}</code></div>' if spf else ""}
            </td></tr>
        <tr><td class="recon-td-label">DMARC Policy</td>
            <td><span class="{dmarc_cls}">{dmarc_display}</span>
            {f'<div class="recon-record-val"><code>{html.escape(dmarc[:120])}{"…" if len(dmarc) > 120 else ""}</code></div>' if dmarc else ""}
            </td></tr>
        <tr><td class="recon-td-label">DKIM Selectors Found</td>
            <td>{"<code>" + "</code>, <code>".join(html.escape(s) for s in dkim) + "</code>" if dkim else '<span class="recon-neutral">None detected</span>'}</td></tr>
    """

    # ── Tech Stack table ───────────────────────────────────────────────────────
    tech_rows = ""
    if tech:
        for t in tech:
            tech_rows += (
                f'<tr><td class="recon-td-label">{html.escape(t.get("label", ""))}</td>'
                f'<td><code class="recon-mono">{html.escape(str(t.get("tech", ""))[:80])}</code></td></tr>'
            )
    else:
        tech_rows = '<tr><td colspan="2" class="recon-neutral">No technology signals detected in response headers.</td></tr>'

    # ── Subdomain Inventory ────────────────────────────────────────────────────
    sub_chips = ""
    if subdomains:
        sub_chips = "".join(
            f'<code class="recon-chip">{html.escape(s)}</code>' for s in subdomains[:30]
        )
        if ct_count > 30:
            sub_chips += f'<span class="recon-more">+{ct_count - 30} more</span>'
    else:
        sub_chips = '<span class="recon-neutral">No CT log subdomains discovered.</span>'

    # ── Dangling CNAMEs ────────────────────────────────────────────────────────
    cname_block = ""
    if dangling:
        cname_rows = "".join(
            f'<tr>'
            f'<td><code class="recon-mono">{html.escape(d.get("subdomain", ""))}</code></td>'
            f'<td><code class="recon-mono recon-warn-text">{html.escape(d.get("cname_target", ""))}</code></td>'
            f'<td class="{"recon-status-fail" if "Does Not" in d.get("status", "") else "recon-status-warn"}">'
            f'{html.escape(d.get("status", "Unknown"))}</td>'
            f'</tr>'
            for d in dangling
        )
        cname_block = f"""
        <div class="recon-warning-box">
            <div class="recon-warning-title">⚠ Potential Dangling CNAME Records ({len(dangling)} detected)</div>
            <table class="recon-table recon-table-full" style="margin-top:8px;">
                <thead><tr>
                    <th class="recon-th">Subdomain</th>
                    <th class="recon-th">CNAME Target</th>
                    <th class="recon-th">Resolution Status</th>
                </tr></thead>
                <tbody>{cname_rows}</tbody>
            </table>
        </div>"""

    return f"""
    <section class="recon-section" id="recon-section">
        <h2 class="section-title">Perimeter Reconnaissance &amp; Asset Intelligence</h2>
        <p class="recon-intro">Passive, non-intrusive attack surface mapping gathered during the scan.
        Data sources: Certificate Transparency logs (crt.sh), DNS resolver, HTTP response headers.</p>

        <div class="recon-grid">

            <!-- TLS & Transport Security -->
            <div class="recon-card">
                <div class="recon-card-title">TLS &amp; Transport Security</div>
                <table class="recon-table"><tbody>{tls_rows}</tbody></table>
            </div>

            <!-- DNS Email Security -->
            <div class="recon-card">
                <div class="recon-card-title">DNS Email Authentication Posture</div>
                <table class="recon-table"><tbody>{dns_rows}</tbody></table>
            </div>

            <!-- Technology Stack -->
            <div class="recon-card">
                <div class="recon-card-title">Technology Stack Fingerprints</div>
                <table class="recon-table"><tbody>{tech_rows}</tbody></table>
            </div>

            <!-- Subdomain Inventory -->
            <div class="recon-card recon-card-full">
                <div class="recon-card-title">Certificate Transparency Subdomain Inventory
                    <span class="recon-count-badge">{ct_count} subdomains</span>
                </div>
                <div class="recon-chip-container">{sub_chips}</div>
            </div>

        </div>

        {cname_block}

    </section>
    """


def generate_html_report(scan: Scan, output_path: str) -> str:
    """Generates a standalone executive HTML report for offline web browser viewing.

    Includes a dedicated 'Perimeter Reconnaissance & Asset Intelligence' section
    with TLS posture, DNS email security, tech fingerprints, CT subdomain inventory,
    and dangling CNAME warnings — fully self-contained with no external dependencies.

    Args:
        scan: Scan model instance containing findings and metadata.
        output_path: File path where HTML output will be saved.

    Returns:
        The output file path string.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    scan_dict = scan.to_dict()
    findings = [f.to_dict() for f in scan.findings]

    recon = _extract_recon(scan)
    recon_html = _render_recon_section(recon) if recon else ""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnWatch Security Audit - {html.escape(scan.target_url)}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #64748b;
            --ok: #22c55e;
            --warn: #f59e0b;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem 2rem;
            margin-bottom: 2rem;
        }}
        .header h1 {{ margin: 0 0 0.5rem 0; font-size: 1.75rem; color: #38bdf8; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .summary-card .count {{ font-size: 2rem; font-weight: bold; margin-top: 0.25rem; }}
        .sev-critical {{ color: var(--critical); border-top: 4px solid var(--critical); }}
        .sev-high     {{ color: var(--high); border-top: 4px solid var(--high); }}
        .sev-medium   {{ color: var(--medium); border-top: 4px solid var(--medium); }}
        .sev-low      {{ color: var(--low); border-top: 4px solid var(--low); }}
        .sev-info     {{ color: var(--info); border-top: 4px solid var(--info); }}
        .section-title {{
            font-size: 1.3rem;
            font-weight: 700;
            color: #e2e8f0;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 0.5rem;
            margin: 2rem 0 1rem 0;
        }}
        /* ── Recon Section ── */
        .recon-section {{
            background: rgba(99,102,241,0.06);
            border: 1px solid rgba(99,102,241,0.25);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .recon-section .section-title {{ border-color: rgba(99,102,241,0.3); color: #a5b4fc; }}
        .recon-intro {{ color: var(--text-muted); font-size: 0.88rem; margin-bottom: 1.25rem; }}
        .recon-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .recon-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            border-radius: 7px;
            padding: 1rem;
        }}
        .recon-card-full {{ grid-column: 1 / -1; }}
        .recon-card-title {{
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.07em;
            color: var(--text-muted);
            padding-bottom: 0.6rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .recon-count-badge {{
            background: rgba(99,102,241,0.2);
            color: #a5b4fc;
            padding: 1px 7px;
            border-radius: 10px;
            font-size: 0.72rem;
            font-weight: 500;
        }}
        .recon-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        .recon-table-full {{ width: 100%; border-collapse: collapse; }}
        .recon-th {{
            text-align: left;
            padding: 6px 8px;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            background: rgba(255,255,255,0.03);
        }}
        .recon-td-label {{
            color: var(--text-muted);
            padding: 5px 8px 5px 0;
            width: 45%;
            vertical-align: top;
            font-size: 0.82rem;
        }}
        .recon-table td {{ padding: 5px 4px; vertical-align: top; }}
        .recon-table-full td {{ padding: 6px 8px; border-bottom: 1px solid var(--border-color); font-size: 0.85rem; }}
        .recon-status-ok   {{ color: #4ade80; font-weight: 600; font-size: 0.8rem; }}
        .recon-status-fail {{ color: #f87171; font-weight: 600; font-size: 0.8rem; }}
        .recon-status-warn {{ color: #fb923c; font-weight: 600; font-size: 0.8rem; }}
        .recon-neutral     {{ color: var(--text-muted); font-size: 0.82rem; }}
        .recon-mono {{ font-family: monospace; font-size: 0.82rem; word-break: break-all; }}
        .recon-record-val {{ margin-top: 3px; }}
        .recon-warn-text {{ color: #fca5a5; }}
        .recon-sub-label {{ font-size: 0.75rem; color: var(--text-muted); margin-bottom: 4px; font-weight: 600; }}
        .recon-chain-table {{ width: 100%; border-collapse: collapse; }}
        .recon-chain-table td {{ padding: 2px 4px; font-size: 0.78rem; }}
        .recon-chain-code {{
            color: #a5b4fc;
            font-weight: 700;
            font-family: monospace;
            white-space: nowrap;
            width: 40px;
        }}
        .recon-chain-url {{ color: var(--text-muted); font-family: monospace; word-break: break-all; }}
        .recon-chip-container {{ display: flex; flex-wrap: wrap; gap: 6px; }}
        .recon-chip {{
            padding: 2px 8px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-size: 0.78rem;
            font-family: monospace;
            color: var(--text-muted);
        }}
        .recon-more {{ font-size: 0.78rem; color: var(--text-muted); padding: 2px 4px; }}
        .recon-warning-box {{
            background: rgba(239,68,68,0.07);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 7px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        .recon-warning-title {{ color: #fca5a5; font-weight: 700; font-size: 0.9rem; }}
        .recon-td-sub {{ padding-top: 4px; }}
        /* ── Finding Cards ── */
        .finding-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .finding-title h3 {{ margin: 0; font-size: 1.1rem; }}
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.78rem;
            font-weight: bold;
            color: #fff;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        .badge-CRITICAL {{ background-color: var(--critical); }}
        .badge-HIGH     {{ background-color: var(--high); }}
        .badge-MEDIUM   {{ background-color: var(--medium); }}
        .badge-LOW      {{ background-color: var(--low); }}
        .badge-INFO     {{ background-color: var(--info); }}
        .field-label {{
            font-weight: bold;
            color: var(--text-muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            margin-top: 1rem;
            margin-bottom: 0.25rem;
        }}
        .evidence-box {{
            background-color: #090d16;
            border: 1px solid var(--border-color);
            padding: 0.75rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.82rem;
            color: #a5f3fc;
            overflow-x: auto;
            word-break: break-all;
        }}
        code {{ font-family: monospace; font-size: 0.88em; }}
        @media (max-width: 640px) {{
            .summary-grid {{ grid-template-columns: repeat(3, 1fr); }}
            .recon-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnWatch Executive Security Posture Audit</h1>
            <div>Target: <strong>{html.escape(scan.target_url)}</strong></div>
            <div class="meta-grid">
                <div>Scan ID: #{scan.id}</div>
                <div>Status: {html.escape(scan_dict['status'] or 'UNKNOWN')}</div>
                <div>Started: {html.escape(scan_dict['started_at'] or 'N/A')}</div>
                <div>Completed: {html.escape(scan_dict['completed_at'] or 'N/A')}</div>
            </div>
        </div>

        <h2 class="section-title">Executive Severity Summary</h2>
        <div class="summary-grid">
            <div class="summary-card sev-critical">
                <div>CRITICAL</div>
                <div class="count">{scan.critical_count}</div>
            </div>
            <div class="summary-card sev-high">
                <div>HIGH</div>
                <div class="count">{scan.high_count}</div>
            </div>
            <div class="summary-card sev-medium">
                <div>MEDIUM</div>
                <div class="count">{scan.medium_count}</div>
            </div>
            <div class="summary-card sev-low">
                <div>LOW</div>
                <div class="count">{scan.low_count}</div>
            </div>
            <div class="summary-card sev-info">
                <div>INFO</div>
                <div class="count">{scan.info_count}</div>
            </div>
        </div>

        {recon_html}

        <h2 class="section-title">Detailed Assessment Findings ({len(findings)})</h2>
    """

    for f in findings:
        evidence_str = (
            html.escape(json.dumps(f["evidence"], indent=2)) if f.get("evidence") else "None provided"
        )
        html_content += f"""
        <div class="finding-card">
            <div class="finding-title">
                <h3>{html.escape(f['title'])}</h3>
                <span class="badge badge-{f['severity']}">{html.escape(f['severity'])}</span>
            </div>
            <div><strong>Category:</strong> {html.escape(f['category'])} &nbsp;|&nbsp; <strong>Affected URL:</strong> <code>{html.escape(f['affected_url'])}</code></div>

            <div class="field-label">Description</div>
            <div>{html.escape(f['description'])}</div>

            <div class="field-label">Evidence</div>
            <div class="evidence-box">{evidence_str}</div>

            <div class="field-label">Remediation Action</div>
            <div>{html.escape(f['remediation'])}</div>
        </div>
        """

    html_content += """
    </div>
</body>
</html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
