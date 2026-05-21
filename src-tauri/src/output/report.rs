use std::path::Path;

use anyhow::Context;
use chrono::Utc;

use crate::core::state::{ScanMatch, ScanResult};

/// Generate a standalone HTML security report and return its absolute path.
pub fn generate_report(result: &ScanResult, reports_dir: &Path) -> Result<String, anyhow::Error> {
    let timestamp = result
        .completed_at
        .unwrap_or_else(Utc::now)
        .format("%Y%m%d_%H%M%S");
    let filename = format!("report_{}_{}.html", result.scan_id, timestamp);
    let report_path = reports_dir.join(&filename);

    let html = build_html(result);
    std::fs::write(&report_path, &html)
        .with_context(|| format!("Writing report to {:?}", report_path))?;

    log::info!("Report generated: {:?}", report_path);
    Ok(report_path.display().to_string())
}

fn build_html(result: &ScanResult) -> String {
    let match_count = result.matches.len();
    let scan_time = result
        .completed_at
        .unwrap_or_else(Utc::now)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let started = result.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let meta_json = serde_json::json!({
        "target": result.target_path,
        "scanId": result.scan_id,
        "matchCount": match_count,
    })
    .to_string();

    let threat_banner = if match_count == 0 {
        r#"<div class="banner safe">No threats detected</div>"#.to_string()
    } else {
        format!(
            r#"<div class="banner threat">{} threat(s) detected</div>"#,
            match_count
        )
    };

    let rows = build_match_rows(&result.matches);

    let filter_js = r#"
function filterTable() {
  const q = document.getElementById('filterInput').value.toLowerCase();
  document.querySelectorAll('tr.match-row').forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(q) ? '' : 'none';
    const id = row.getAttribute('data-id');
    const detail = document.getElementById('detail-' + id);
    if (detail) detail.style.display = 'none';
  });
}
function toggleDetail(id) {
  const el = document.getElementById('detail-' + id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
}
"#;

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>YARA Kiosk Security Report</title>
<script id="scan-meta" type="application/json">{meta_json}</script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0e1a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}}
.container{{max-width:1200px;margin:0 auto;padding:2rem}}
header{{border-bottom:1px solid #1e293b;padding-bottom:1.5rem;margin-bottom:1.5rem}}
header h1{{font-size:1.75rem;font-weight:700;color:#10b981;letter-spacing:.02em}}
header h1 span{{color:#64748b;font-size:1rem;font-weight:400;margin-left:.5rem}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1rem 0}}
.meta-card{{background:#0f172a;border:1px solid #1e293b;border-radius:.5rem;padding:1rem}}
.meta-card .label{{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
.meta-card .value{{font-size:1.1rem;font-weight:600;color:#e2e8f0;margin-top:.25rem;word-break:break-all}}
.banner{{border-radius:.5rem;padding:1rem 1.5rem;font-weight:600;margin:1.5rem 0;font-size:1.1rem}}
.banner.safe{{background:#052e16;border:1px solid #10b981;color:#10b981}}
.banner.threat{{background:#2d0a0a;border:1px solid #ef4444;color:#ef4444}}
.filter-bar{{margin:1rem 0}}
.filter-bar input{{width:100%;background:#0f172a;border:1px solid #334155;border-radius:.375rem;color:#e2e8f0;padding:.625rem 1rem;font-size:.95rem;outline:none}}
.filter-bar input:focus{{border-color:#10b981}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
thead th{{background:#0f172a;color:#94a3b8;font-weight:600;text-align:left;padding:.75rem 1rem;border-bottom:2px solid #1e293b;position:sticky;top:0}}
tr.match-row{{cursor:pointer;transition:background .15s}}
tr.match-row:hover{{background:#0f172a}}
tr.match-row td{{padding:.75rem 1rem;border-bottom:1px solid #1e293b;vertical-align:top}}
tr.match-row td.rule{{color:#f59e0b;font-weight:600}}
tr.match-row td.ns{{color:#64748b;font-size:.85rem}}
tr.match-row td.sha{{font-family:monospace;font-size:.8rem;color:#64748b;word-break:break-all}}
tr.match-row td.path{{font-family:monospace;font-size:.85rem;word-break:break-all}}
tr.detail-row{{display:none}}
tr.detail-row td{{background:#050a12;padding:1rem 1.5rem;border-bottom:1px solid #1e293b}}
tr.detail-row .hex-entry{{margin:.5rem 0;font-family:monospace;font-size:.8rem;color:#94a3b8}}
tr.detail-row .hex-entry .id{{color:#10b981;font-weight:700}}
tr.detail-row .hex-entry .offset{{color:#f59e0b}}
tr.detail-row .hex-entry .dump{{color:#cbd5e1;word-break:break-all;padding:.25rem .5rem;background:#0a0e1a;border-radius:.25rem;display:block;margin-top:.25rem}}
.no-matches{{text-align:center;padding:3rem;color:#64748b}}
footer{{margin-top:3rem;padding-top:1.5rem;border-top:1px solid #1e293b;text-align:center;color:#475569;font-size:.85rem}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>YARA Kiosk Security Report <span>v1.0</span></h1>
</header>
<div class="meta-grid">
<div class="meta-card">
<div class="label">Target Path</div>
<div class="value">{target}</div>
</div>
<div class="meta-card">
<div class="label">Scan Started</div>
<div class="value">{started}</div>
</div>
<div class="meta-card">
<div class="label">Completed</div>
<div class="value">{scan_time}</div>
</div>
<div class="meta-card">
<div class="label">Files Scanned</div>
<div class="value">{files_scanned}</div>
</div>
<div class="meta-card">
<div class="label">Total Matches</div>
<div class="value" style="color:{match_color}">{match_count}</div>
</div>
<div class="meta-card">
<div class="label">Scan ID</div>
<div class="value">{scan_id}</div>
</div>
</div>
{threat_banner}
<div class="filter-bar">
<input id="filterInput" type="text" placeholder="Filter by rule name or file path…" oninput="filterTable()"/>
</div>
{table_html}
<footer>Generated by Yara Kiosk &bull; Report is read-only</footer>
</div>
<script>{filter_js}</script>
</body>
</html>"#,
        meta_json = meta_json,
        target = html_escape(&result.target_path),
        started = started,
        scan_time = scan_time,
        files_scanned = result.files_scanned,
        match_count = match_count,
        match_color = if match_count == 0 { "#10b981" } else { "#ef4444" },
        scan_id = html_escape(&result.scan_id),
        threat_banner = threat_banner,
        table_html = rows,
        filter_js = filter_js,
    )
}

fn build_match_rows(matches: &[ScanMatch]) -> String {
    if matches.is_empty() {
        return r#"<div class="no-matches">No matching rules found — system appears clean.</div>"#
            .to_string();
    }

    let mut html = String::from(
        r#"<table>
<thead>
<tr>
<th>Rule Name</th>
<th>Namespace</th>
<th>File Path</th>
<th>SHA-256</th>
<th>String Matches</th>
</tr>
</thead>
<tbody>"#,
    );

    for (idx, m) in matches.iter().enumerate() {
        let id = idx.to_string();
        let offsets_count = m.offsets.len();

        html.push_str(&format!(
            r#"<tr class="match-row" data-id="{id}" onclick="toggleDetail('{id}')">
<td class="rule">{rule}</td>
<td class="ns">{ns}</td>
<td class="path">{path}</td>
<td class="sha">{sha}</td>
<td>{offsets} offset(s) — click to expand</td>
</tr>
<tr class="detail-row" id="detail-{id}">
<td colspan="5">{detail}</td>
</tr>"#,
            id = id,
            rule = html_escape(&m.rule_name),
            ns = html_escape(&m.namespace),
            path = html_escape(&m.file_path),
            sha = html_escape(&m.sha256),
            offsets = offsets_count,
            detail = build_detail(&m.offsets),
        ));
    }

    html.push_str("</tbody></table>");
    html
}

fn build_detail(offsets: &[crate::core::state::HexOffset]) -> String {
    if offsets.is_empty() {
        return "<em>No pattern data</em>".to_string();
    }
    let mut out = String::new();
    for o in offsets {
        out.push_str(&format!(
            r#"<div class="hex-entry">
<span class="id">{id}</span> at <span class="offset">0x{offset:08X}</span> ({len} bytes)
<span class="dump">{dump}</span>
</div>"#,
            id = html_escape(&o.identifier),
            offset = o.offset,
            len = o.length,
            dump = html_escape(&o.hex_dump),
        ));
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
