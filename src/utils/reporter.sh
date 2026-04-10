#!/usr/bin/env bash
# TRAKTR Reporter v2.0 -- Generates MD, JSON, and self-contained HTML reports
# Usage: source reporter.sh; generate_html_report <outdir>

# ═══════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════
generate_html_report() {
  local outdir="${1:-${OUTDIR:-/tmp}}"
  local findings="${outdir}/findings.json"
  local secrets="${outdir}/secrets.json"
  local target="${TARGET:-unknown}"
  local duration=$(( $(date +%s) - ${SCAN_START:-$(date +%s)} ))
  local total_findings; total_findings=$(jq 'length' "$findings" 2>/dev/null || echo 0)
  local total_secrets; total_secrets=$(jq 'length' "$secrets" 2>/dev/null || echo 0)
  local total_endpoints; total_endpoints=$(wc -l < "${outdir}/all_endpoints.txt" 2>/dev/null || echo 0)
  local total_params; total_params=$(wc -l < "${outdir}/active_params.txt" 2>/dev/null || echo 0)
  local high; high=$(jq '[.[]|select(.confidence=="HIGH")]|length' "$findings" 2>/dev/null || echo 0)
  local med; med=$(jq '[.[]|select(.confidence=="MEDIUM")]|length' "$findings" 2>/dev/null || echo 0)
  local low; low=$(jq '[.[]|select(.confidence=="LOW")]|length' "$findings" 2>/dev/null || echo 0)

  cat > "${outdir}/REPORT.html" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Traktr Scan Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;padding:20px}
.container{max-width:1100px;margin:0 auto}
h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:12px;margin-bottom:20px;font-size:1.8em}
h2{color:#79c0ff;margin:24px 0 12px;font-size:1.3em}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:2em;font-weight:700;display:block}
.stat .label{font-size:.85em;color:#8b949e}
.high .num{color:#f85149}.med .num{color:#d29922}.low .num{color:#58a6ff}.ok .num{color:#3fb950}
table{width:100%;border-collapse:collapse;margin:12px 0;background:#161b22;border-radius:8px;overflow:hidden}
th{background:#21262d;color:#79c0ff;padding:10px 12px;text-align:left;font-size:.85em;cursor:pointer;user-select:none}
th:hover{background:#30363d}
td{padding:10px 12px;border-top:1px solid #21262d;font-size:.9em;word-break:break-all}
tr:hover{background:#1c2128}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75em;font-weight:600}
.badge-high{background:#f8514922;color:#f85149;border:1px solid #f8514944}
.badge-med{background:#d2992222;color:#d29922;border:1px solid #d2992244}
.badge-low{background:#58a6ff22;color:#58a6ff;border:1px solid #58a6ff44}
.badge-confirmed{background:#f8514922;color:#f85149}.badge-possible{background:#8b949e22;color:#8b949e}
.poc{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;font-family:'Fira Code',monospace;font-size:.82em;color:#7ee787;margin:6px 0;white-space:pre-wrap;word-break:break-all;cursor:pointer;position:relative}
.poc:hover{border-color:#58a6ff}
.poc::after{content:'click to copy';position:absolute;top:4px;right:8px;font-size:.7em;color:#8b949e;opacity:0;transition:.2s}
.poc:hover::after{opacity:1}
details{margin:8px 0}
details summary{cursor:pointer;color:#58a6ff;font-size:.9em}
.filter-bar{margin:12px 0;display:flex;gap:8px;flex-wrap:wrap}
.filter-btn{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:4px 12px;border-radius:16px;cursor:pointer;font-size:.82em}
.filter-btn:hover,.filter-btn.active{background:#58a6ff22;border-color:#58a6ff;color:#58a6ff}
footer{text-align:center;color:#484f58;font-size:.8em;margin-top:40px;padding-top:16px;border-top:1px solid #21262d}
</style>
</head>
<body>
<div class="container">
<h1>Traktr Scan Report</h1>
HTMLHEAD

  # Summary section
  cat >> "${outdir}/REPORT.html" << HTMLSUMMARY
<div class="stats">
<div class="stat"><span class="num">${total_findings}</span><span class="label">Findings</span></div>
<div class="stat high"><span class="num">${high}</span><span class="label">HIGH</span></div>
<div class="stat med"><span class="num">${med}</span><span class="label">MEDIUM</span></div>
<div class="stat low"><span class="num">${low}</span><span class="label">LOW</span></div>
<div class="stat"><span class="num">${total_secrets}</span><span class="label">Secrets</span></div>
<div class="stat ok"><span class="num">${total_endpoints}</span><span class="label">Endpoints</span></div>
<div class="stat ok"><span class="num">${total_params}</span><span class="label">Parameters</span></div>
</div>
<table>
<tr><td><b>Target</b></td><td><code>${target}</code></td></tr>
<tr><td><b>Date</b></td><td>$(date '+%Y-%m-%d %H:%M:%S')</td></tr>
<tr><td><b>Duration</b></td><td>${duration}s</td></tr>
<tr><td><b>Mode</b></td><td>$([[ "${OSCP:-false}" == true ]] && echo "OSCP-Safe" || echo "Standard")$([[ "${STEALTH:-false}" == true ]] && echo " / Stealth" || true)</td></tr>
<tr><td><b>WAF</b></td><td>${WAF_DETECTED:-none}</td></tr>
<tr><td><b>Framework</b></td><td>${FRAMEWORK:-generic}</td></tr>
<tr><td><b>Requests</b></td><td>${REQUEST_COUNT:-0}</td></tr>
</table>
HTMLSUMMARY

  # Findings table
  if [[ "$total_findings" -gt 0 ]]; then
    cat >> "${outdir}/REPORT.html" << 'HTMLFHDR'
<h2>Findings</h2>
<div class="filter-bar">
<button class="filter-btn active" onclick="filterRows('all')">All</button>
<button class="filter-btn" onclick="filterRows('HIGH')">HIGH</button>
<button class="filter-btn" onclick="filterRows('MEDIUM')">MEDIUM</button>
<button class="filter-btn" onclick="filterRows('LOW')">LOW</button>
</div>
<table id="findings-table">
<thead><tr><th onclick="sortTable(0)">Type</th><th onclick="sortTable(1)">Confidence</th><th onclick="sortTable(2)">URL</th><th onclick="sortTable(3)">Param</th><th>Payload / Proof</th></tr></thead>
<tbody>
HTMLFHDR

    jq -r '.[] | @base64' "$findings" 2>/dev/null | while IFS= read -r row; do
      local decoded; decoded=$(echo "$row" | base64 -d 2>/dev/null) || continue
      local ftype; ftype=$(echo "$decoded" | jq -r '.type // "unknown"' 2>/dev/null)
      local conf; conf=$(echo "$decoded" | jq -r '.confidence // "LOW"' 2>/dev/null)
      local furl; furl=$(echo "$decoded" | jq -r '.url // .matched_at // "N/A"' 2>/dev/null)
      local fparam; fparam=$(echo "$decoded" | jq -r '.param // "N/A"' 2>/dev/null)
      local fpayload; fpayload=$(echo "$decoded" | jq -r '.payload // "N/A"' 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g')
      local fproof; fproof=$(echo "$decoded" | jq -r '.proof // .detail // ""' 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g' | head -c 200)
      local fcurl; fcurl=$(echo "$decoded" | jq -r '.curl // ""' 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g')
      local badge_class="badge-low"
      [[ "$conf" == "HIGH" ]] && badge_class="badge-high"
      [[ "$conf" == "MEDIUM" ]] && badge_class="badge-med"

      cat >> "${outdir}/REPORT.html" << HTMLROW
<tr data-conf="${conf}"><td>${ftype}</td><td><span class="badge ${badge_class}">${conf}</span></td><td><code>${furl}</code></td><td><code>${fparam}</code></td><td>
<code>${fpayload}</code><br><small>${fproof}</small>
$([ -n "$fcurl" ] && echo "<details><summary>PoC Command</summary><div class=\"poc\" onclick=\"navigator.clipboard.writeText(this.textContent)\">${fcurl}</div></details>" || true)
</td></tr>
HTMLROW
    done

    echo "</tbody></table>" >> "${outdir}/REPORT.html"
  else
    echo "<h2>Findings</h2><p>No findings above confidence threshold.</p>" >> "${outdir}/REPORT.html"
  fi

  # Secrets table
  if [[ "$total_secrets" -gt 0 ]]; then
    cat >> "${outdir}/REPORT.html" << 'HTMLSHDR'
<h2>Secrets Detected</h2>
<table><thead><tr><th>Type</th><th>Confidence</th><th>Value</th><th>Location</th></tr></thead><tbody>
HTMLSHDR
    jq -r '.[] | "<tr><td>\(.type)</td><td><span class=\"badge badge-\(.confidence|ascii_downcase)\">\(.confidence)</span></td><td><code>\(.value_redacted)</code></td><td>\(.location)</td></tr>"' \
      "$secrets" >> "${outdir}/REPORT.html" 2>/dev/null || true
    echo "</tbody></table>" >> "${outdir}/REPORT.html"
  fi

  # Discovered Endpoints table (always shown for manual testing)
  if [[ "$total_endpoints" -gt 0 ]]; then
    cat >> "${outdir}/REPORT.html" << 'HTMLEHDR'
<h2>Discovered Endpoints</h2>
<details open><summary>Click to expand/collapse</summary>
<table><thead><tr><th>URL</th></tr></thead><tbody>
HTMLEHDR
    head -100 "${outdir}/all_endpoints_paths.txt" 2>/dev/null | while IFS= read -r ep; do
      [[ -z "$ep" ]] && continue
      local safe_ep; safe_ep=$(echo "$ep" | sed 's/</\&lt;/g; s/>/\&gt;/g')
      echo "<tr><td><code>${safe_ep}</code></td></tr>" >> "${outdir}/REPORT.html"
    done
    echo "</tbody></table></details>" >> "${outdir}/REPORT.html"
    [[ "$total_endpoints" -gt 100 ]] && echo "<p><em>... and $((total_endpoints - 100)) more (see all_endpoints.txt)</em></p>" >> "${outdir}/REPORT.html"
  fi

  # Discovered Parameters table (always shown for manual testing)
  if [[ "$total_params" -gt 0 ]]; then
    cat >> "${outdir}/REPORT.html" << 'HTMLPHDR'
<h2>Discovered Parameters</h2>
<details open><summary>Click to expand/collapse</summary>
<table><thead><tr><th>Endpoint</th><th>Parameter</th><th>Method</th><th>Source</th><th>Tags</th></tr></thead><tbody>
HTMLPHDR
    head -100 "${outdir}/active_params.txt" 2>/dev/null | while IFS='|' read -r p_url p_param p_source p_method _; do
      [[ -z "$p_param" ]] && continue
      local safe_url; safe_url=$(echo "$p_url" | sed 's/</\&lt;/g; s/>/\&gt;/g')
      local tags=""
      echo "$p_param" | grep -qiE 'file|path|page|include|template|doc|load|read|dir|resource' && tags+='<span class="badge badge-high">LFI?</span> '
      echo "$p_param" | grep -qiE 'redirect|redir|next|return|goto|callback|dest|url' && tags+='<span class="badge badge-med">REDIR?</span> '
      echo "$p_param" | grep -qiE '^id$|user|email|name|password|token|key|secret|admin' && tags+='<span class="badge badge-low">IDOR?</span> '
      echo "<tr><td><code>${safe_url}</code></td><td><code>${p_param}</code></td><td>${p_method:-GET}</td><td>${p_source:-?}</td><td>${tags:-&mdash;}</td></tr>" >> "${outdir}/REPORT.html"
    done
    echo "</tbody></table></details>" >> "${outdir}/REPORT.html"
    [[ "$total_params" -gt 100 ]] && echo "<p><em>... and $((total_params - 100)) more (see active_params.txt)</em></p>" >> "${outdir}/REPORT.html"
  fi

  # JavaScript for filtering/sorting + footer
  cat >> "${outdir}/REPORT.html" << 'HTMLFOOT'
</div>
<footer>Generated by Traktr -- Intelligent Web Pentest Orchestrator</footer>
<script>
function filterRows(conf){
  document.querySelectorAll('.filter-btn').forEach(b=>{b.classList.remove('active')});
  event.target.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(r=>{
    r.style.display=(conf==='all'||r.dataset.conf===conf)?'':'none';
  });
}
function sortTable(n){
  const t=document.getElementById('findings-table'),rows=[...t.querySelectorAll('tbody tr')];
  const dir=t.dataset.sortDir==='asc'?'desc':'asc';t.dataset.sortDir=dir;
  rows.sort((a,b)=>{
    const x=a.cells[n].textContent.trim(),y=b.cells[n].textContent.trim();
    return dir==='asc'?x.localeCompare(y):y.localeCompare(x);
  });
  rows.forEach(r=>t.querySelector('tbody').appendChild(r));
}
</script>
</body></html>
HTMLFOOT
}
