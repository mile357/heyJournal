/**
 * HeyJournal — Client-Side Decrypted Exports & Printable Clinician Summary
 * All formatting happens strictly in the browser using already-decrypted data.
 */

import { computeSeriesStats, filterPointsByRange } from "./charts.js";

function triggerDownload(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    a.remove();
    URL.revokeObjectURL(url);
  }, 500);
}

function csvEscape(val) {
  const s = String(val ?? "");
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function htmlEscape(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function downloadDecryptedJson(entries, vaultMeta, username = "user") {
  const stamp = new Date().toISOString().slice(0, 10);
  const payload = {
    exportedAt: new Date().toISOString(),
    app: "HeyJournal",
    version: 1,
    username,
    settings: vaultMeta?.settings || {},
    metrics: vaultMeta?.metrics || [],
    entries: entries.map((e) => ({
      id: e.id,
      timestamp: e.data.timestamp,
      text: e.data.text || "",
      numericMetrics: e.data.numericMetrics || [],
      quizResults: e.data.quizResults || [],
      createdAt: e.createdAt,
      updatedAt: e.updatedAt,
    })),
  };
  triggerDownload(
    `heyjournal-export-${stamp}.json`,
    JSON.stringify(payload, null, 2),
    "application/json;charset=utf-8"
  );
}

export function downloadDecryptedCsv(entries) {
  const stamp = new Date().toISOString().slice(0, 10);
  // Collect all unique numeric metric names & quiz names for clean columns
  const numNames = new Set();
  const quizNames = new Set();
  for (const e of entries) {
    for (const m of e.data.numericMetrics || []) {
      numNames.add(m.unit ? `${m.name} (${m.unit})` : m.name);
    }
    for (const q of e.data.quizResults || []) {
      quizNames.add(q.quizName || q.quizId);
    }
  }
  const numCols = Array.from(numNames).sort();
  const quizCols = Array.from(quizNames).sort();

  const header = [
    "date",
    "timestamp",
    "entry_text",
    ...numCols,
    ...quizCols.flatMap((qn) => [`${qn} Score`, `${qn} Severity`]),
  ];

  const sorted = [...entries].sort(
    (a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime()
  );

  const rows = [header.map(csvEscape).join(",")];
  for (const e of sorted) {
    const dt = new Date(e.data.timestamp);
    const datePart = Number.isNaN(dt.getTime()) ? "" : dt.toISOString().slice(0, 10);
    const numMap = {};
    for (const m of e.data.numericMetrics || []) {
      const k = m.unit ? `${m.name} (${m.unit})` : m.name;
      numMap[k] = m.value;
    }
    const quizMap = {};
    for (const q of e.data.quizResults || []) {
      const k = q.quizName || q.quizId;
      quizMap[k] = q;
    }

    const row = [
      datePart,
      e.data.timestamp || "",
      e.data.text || "",
      ...numCols.map((c) => (numMap[c] !== undefined ? numMap[c] : "")),
      ...quizCols.flatMap((qn) => {
        const qr = quizMap[qn];
        return qr ? [qr.score, qr.band?.label || ""] : ["", ""];
      }),
    ];
    rows.push(row.map(csvEscape).join(","));
  }

  triggerDownload(`heyjournal-export-${stamp}.csv`, rows.join("\r\n"), "text/csv;charset=utf-8");
}

export function openPrintableClinicianSummary({
  entries,
  seriesList,
  rangeKey = "90d",
  username = "",
  includeJournalNotes = true,
}) {
  const rangeLabel =
    rangeKey === "30d"
      ? "Last 30 Days"
      : rangeKey === "90d"
      ? "Last 90 Days"
      : rangeKey === "1y"
      ? "Last 12 Months"
      : "All Recorded History";

  const generated = new Date().toLocaleString();

  const metricsRows = seriesList
    .map((s) => {
      const pts = filterPointsByRange(s.points, rangeKey);
      const stats = computeSeriesStats(pts);
      if (!stats) return "";
      const latestPt = pts[pts.length - 1];
      const deltaSign = stats.deltaPeriod > 0 ? "+" : "";
      const unitSuffix = s.unit === "%" ? "%" : s.unit ? ` ${s.unit}` : "";
      return `
        <tr>
          <td><strong>${htmlEscape(s.name)}</strong>${s.kind === "quiz" ? ' <span class="tag">Quiz</span>' : ""}</td>
          <td>${stats.count}</td>
          <td>${htmlEscape(String(Math.round(stats.latest * 10) / 10))}${htmlEscape(unitSuffix)}${
        latestPt?.bandLabel ? ` (${htmlEscape(latestPt.bandLabel)})` : ""
      }</td>
          <td>${htmlEscape(String(Math.round(stats.avg * 10) / 10))}${htmlEscape(unitSuffix)}</td>
          <td>${htmlEscape(String(Math.round(stats.min * 10) / 10))} – ${htmlEscape(
        String(Math.round(stats.max * 10) / 10)
      )}${htmlEscape(unitSuffix)}</td>
          <td>${deltaSign}${htmlEscape(String(Math.round(stats.deltaPeriod * 10) / 10))}${htmlEscape(unitSuffix)}</td>
        </tr>
      `;
    })
    .filter(Boolean)
    .join("");

  const quizHistoryItems = [];
  for (const e of entries) {
    const tsMs = new Date(e.data.timestamp).getTime();
    for (const q of e.data.quizResults || []) {
      quizHistoryItems.push({ tsMs, timestamp: e.data.timestamp, q });
    }
  }
  const filteredQuizzes = filterPointsByRange(
    quizHistoryItems.map((item) => ({ tsMs: item.tsMs, value: item.q.score, raw: item })),
    rangeKey
  ).reverse();

  const quizHistoryHtml = filteredQuizzes
    .map((pt) => {
      const { timestamp, q } = pt.raw;
      const subText = Array.isArray(q.subscales) && q.subscales.length > 0
        ? q.subscales.map((s) => `${s.name}: ${s.score}${s.band ? ` (${s.band.label})` : ""}`).join(" · ")
        : "";
      return `
        <tr>
          <td>${htmlEscape(new Date(timestamp).toLocaleDateString())}</td>
          <td><strong>${htmlEscape(q.quizName || q.quizId)}</strong></td>
          <td>${htmlEscape(String(q.score))}${q.maxScore ? ` / ${htmlEscape(String(q.maxScore))}` : ""} ${htmlEscape(q.unit || "")}</td>
          <td>${htmlEscape(q.band?.label || "—")}</td>
          <td class="muted">${htmlEscape(subText)}</td>
        </tr>
      `;
    })
    .join("");

  const recentNotesHtml = includeJournalNotes
    ? [...entries]
        .filter((e) => (e.data.text || "").trim().length > 0)
        .sort((a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime())
        .slice(0, 20)
        .map(
          (e) => `
          <div class="note-item">
            <div class="note-date">${htmlEscape(new Date(e.data.timestamp).toLocaleString())}</div>
            <div class="note-body">${htmlEscape(e.data.text).replace(/\n/g, "<br/>")}</div>
          </div>
        `
        )
        .join("")
    : "";

  const docHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>HeyJournal — Personal Health & Mood Summary</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111; margin: 32px; line-height: 1.45; }
    h1 { font-size: 24px; font-weight: 600; margin: 0 0 4px 0; }
    h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.06em; color: #444; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin: 24px 0 12px 0; }
    .meta { color: #555; font-size: 13px; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
    th { font-weight: 600; background: #f6f6f6; }
    .tag { display: inline-block; font-size: 10px; text-transform: uppercase; padding: 1px 6px; border: 1px solid #999; color: #444; margin-left: 6px; }
    .muted { color: #555; font-size: 12px; }
    .note-item { margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid #eee; page-break-inside: avoid; }
    .note-date { font-size: 12px; font-weight: 600; color: #444; margin-bottom: 4px; }
    .note-body { font-size: 13px; }
    .disclaimer { margin-top: 28px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 11px; color: #666; }
    .print-bar { margin-bottom: 18px; }
    .print-btn { padding: 8px 16px; font-size: 13px; cursor: pointer; background: #111; color: #fff; border: none; }
    @media print { .print-bar { display: none; } body { margin: 16px; } }
  </style>
</head>
<body>
  <div class="print-bar"><button class="print-btn" onclick="window.print()">Print / Save as PDF</button></div>
  <h1>HeyJournal — Longitudinal Summary</h1>
  <div class="meta">Account: ${htmlEscape(username)} · Period: ${htmlEscape(rangeLabel)} · Generated: ${htmlEscape(generated)}</div>

  <h2>Tracked Metrics Overview</h2>
  ${
    metricsRows
      ? `<table><thead><tr><th>Metric</th><th>Entries</th><th>Latest</th><th>Average</th><th>Range</th><th>Period Change</th></tr></thead><tbody>${metricsRows}</tbody></table>`
      : `<p class="muted">No tracked metric data points in this period.</p>`
  }

  <h2>Clinical Self-Assessment History</h2>
  ${
    quizHistoryHtml
      ? `<table><thead><tr><th>Date</th><th>Assessment</th><th>Score</th><th>Severity Band</th><th>Subscales</th></tr></thead><tbody>${quizHistoryHtml}</tbody></table>`
      : `<p class="muted">No completed clinical quizzes in this period.</p>`
  }

  ${
    recentNotesHtml
      ? `<h2>Recent Journal Excerpts (Up to 20)</h2>${recentNotesHtml}`
      : ""
  }

  <div class="disclaimer">
    Generated locally on the user's device from client-side decrypted HeyJournal records. Self-assessment scores are provided for longitudinal tracking and discussion with a qualified clinician and do not constitute a medical diagnosis.
  </div>
</body>
</html>`;

  const blob = new Blob([docHtml], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, "_blank", "noopener,noreferrer");
  if (!win) {
    // Fallback if popup blocked: trigger download of the printable HTML
    const stamp = new Date().toISOString().slice(0, 10);
    triggerDownload(`heyjournal-clinician-summary-${stamp}.html`, docHtml, "text/html;charset=utf-8");
  }
}
