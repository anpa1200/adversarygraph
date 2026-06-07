"""
Generates a multi-page PDF threat intelligence report using fpdf2.

Output sections:
  1. Cover page — metadata + statistics
  2. Executive summary — AI-generated summary text
  3. Extracted techniques — table sorted by confidence desc
  4. APT attribution — top matches with shared-technique breakdown
  5. Tactic coverage — per-tactic counts
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

# fpdf2 ≥ 2.7 API
from fpdf import FPDF

# ── Colour palette ─────────────────────────────────────────────────────────────
_RED   = (200, 18, 60)
_NAVY  = (15,  23, 42)
_GRAY  = (107, 114, 128)
_LIGHT = (243, 244, 246)
_WHITE = (255, 255, 255)
_AMBER = (245, 158, 11)
_BLUE  = (59,  130, 246)


class _Report(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_RED)
        self.cell(0, 7, "ThreatMapper - Threat Intelligence Report", align="R")
        self.ln(1)
        self.set_draw_color(*_RED)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-13)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_GRAY)
        self.cell(
            0, 8,
            f"Page {self.page_no()} | ThreatMapper | MITRE ATT&CK® Framework",
            align="C",
        )


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_analysis_report(data: dict[str, Any]) -> bytes:
    """
    data keys expected:
      session_id, provider, model, domain, summary,
      techniques:  [{attack_id, name, tactic, confidence, evidence}]
      apt_matches: [{group_attack_id, group_name, similarity, shared_count, shared_techniques}]
    """
    pdf = _Report(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=14, top=14, right=14)

    _cover(pdf, data)
    _summary(pdf, data)

    techniques = data.get("techniques", [])
    if techniques:
        _techniques_table(pdf, techniques)

    apt_matches = data.get("apt_matches", [])
    if apt_matches:
        _apt_attribution(pdf, apt_matches, techniques)

    tactic_data = _compute_tactic_coverage(techniques)
    if tactic_data:
        _tactic_coverage(pdf, tactic_data)

    return bytes(pdf.output())


def generate_layer_report(
    technique_ids: list[str],
    domain: str,
    technique_details: list[dict],
) -> bytes:
    """Lighter report: just the navigator layer (list of techniques with metadata)."""
    pdf = _Report(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=14, top=14, right=14)

    pdf.add_page()
    _heading(pdf, "Navigator Layer Report")
    _meta_row(pdf, "Domain", domain)
    _meta_row(pdf, "Techniques", str(len(technique_ids)))
    _meta_row(pdf, "Generated", _now())
    pdf.ln(6)

    rows = [["ID", "Name", "Tactics", "Platforms"]]
    for t in sorted(technique_details, key=lambda x: x.get("attack_id", "")):
        rows.append([
            t.get("attack_id", ""),
            t.get("name", "")[:40],
            ", ".join(t.get("tactics", []))[:30],
            ", ".join(t.get("platforms", []))[:25],
        ])

    _table(pdf, rows, col_widths=[22, 60, 55, 41])
    return bytes(pdf.output())


# ── Page builders ──────────────────────────────────────────────────────────────

def _cover(pdf: _Report, data: dict) -> None:
    pdf.add_page()

    # Red bar
    pdf.set_fill_color(*_RED)
    pdf.rect(0, 0, 210, 55, style="F")

    # Title
    pdf.set_xy(14, 14)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 12, "ThreatMapper", ln=True)

    pdf.set_x(14)
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(0, 8, "Threat Intelligence Analysis Report", ln=True)

    # Metadata box
    pdf.set_xy(14, 65)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "Analysis Metadata", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_draw_color(*_RED)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(2)

    for label, key in [
        ("Provider",  "provider"),
        ("Model",     "model"),
        ("Domain",    "domain"),
        ("Session ID","session_id"),
        ("Generated", None),
    ]:
        val = _now() if key is None else str(data.get(key, "—"))
        _meta_row(pdf, label, val)

    # Stats
    pdf.ln(6)
    techniques  = data.get("techniques", [])
    apt_matches = data.get("apt_matches", [])

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "Key Findings", ln=True)
    pdf.set_draw_color(*_RED)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(3)

    _stat_box(pdf, str(len(techniques)),
              "Techniques\nextracted")
    _stat_box(pdf, str(len(apt_matches)),
              "APT groups\nmatched")
    top_sim = f"{apt_matches[0]['similarity']*100:.0f}%" if apt_matches else "N/A"
    _stat_box(pdf, top_sim,
              "Top APT\nsimilarity")
    high_conf = sum(1 for t in techniques if t.get("confidence", 0) >= 0.8)
    _stat_box(pdf, str(high_conf),
              "High-confidence\nfindings")


def _summary(pdf: _Report, data: dict) -> None:
    pdf.add_page()
    _heading(pdf, "Executive Summary")

    summary = data.get("summary", "No summary available.")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 6, summary)
    pdf.ln(4)

    hints = data.get("apt_hints", [])
    if hints:
        _heading2(pdf, "Mentioned Threat Actors")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, ", ".join(hints), ln=True)


def _techniques_table(pdf: _Report, techniques: list[dict]) -> None:
    pdf.add_page()
    _heading(pdf, f"Extracted Techniques ({len(techniques)})")

    # Sort by confidence desc
    sorted_t = sorted(techniques, key=lambda t: t.get("confidence", 0), reverse=True)

    rows = [["ID", "Name", "Tactic", "Conf.", "Evidence"]]
    for t in sorted_t:
        rows.append([
            t.get("attack_id", ""),
            t.get("name", "")[:35],
            t.get("tactic", ""),
            f"{int(t.get('confidence', 0) * 100)}%",
            t.get("evidence", "")[:45],
        ])

    _table(pdf, rows, col_widths=[22, 52, 30, 14, 64])


def _apt_attribution(
    pdf: _Report,
    apt_matches: list[dict],
    techniques: list[dict],
) -> None:
    pdf.add_page()
    _heading(pdf, f"APT Group Attribution (top {min(len(apt_matches), 10)})")
    user_ids = {t.get("attack_id", "") for t in techniques}

    for i, m in enumerate(apt_matches[:10], start=1):
        sim = int(m.get("similarity", 0) * 100)
        shared = m.get("shared_techniques", [])

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_RED)
        pdf.cell(0, 7,
                 f"#{i}  {m.get('group_name', '?')}  "
                 f"({m.get('group_attack_id', '?')})  -  {sim}% similarity",
                 ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5,
                 f"Shared techniques: {m.get('shared_count', 0)}  |  "
                 f"Your coverage of their profile: {sim}%",
                 ln=True)
        if shared:
            ids_str = "  ".join(shared[:20])
            if len(shared) > 20:
                ids_str += f"  … +{len(shared) - 20} more"
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(*_GRAY)
            pdf.multi_cell(0, 4, ids_str)
            pdf.set_text_color(0, 0, 0)

        pdf.ln(3)
        if pdf.get_y() > 260:
            pdf.add_page()


def _tactic_coverage(pdf: _Report, tactic_data: list[dict]) -> None:
    pdf.add_page()
    _heading(pdf, "Tactic Coverage Breakdown")

    rows = [["Tactic", "Count", "High Conf.", "Med Conf.", "Low Conf."]]
    for row in tactic_data:
        rows.append([
            row["tactic"][:30],
            str(row["total"]),
            str(row["high"]),
            str(row["medium"]),
            str(row["low"]),
        ])

    _table(pdf, rows, col_widths=[60, 20, 30, 30, 30])


# ── Helpers ────────────────────────────────────────────────────────────────────

def _heading(pdf: _Report, text: str) -> None:
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*_RED)
    pdf.cell(0, 8, text, ln=True)
    pdf.set_draw_color(*_RED)
    pdf.line(14, pdf.get_y(), 196, pdf.get_y())
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def _heading2(pdf: _Report, text: str) -> None:
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*_NAVY)
    pdf.cell(0, 7, text, ln=True)
    pdf.set_text_color(0, 0, 0)


def _meta_row(pdf: _Report, label: str, value: str) -> None:
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(35, 6, f"{label}:")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, value, ln=True)


def _stat_box(pdf: _Report, value: str, label: str) -> None:
    x, y = pdf.get_x(), pdf.get_y()
    w, h = 42, 22
    pdf.set_fill_color(*_LIGHT)
    pdf.set_draw_color(220, 220, 220)
    pdf.rect(x, y, w, h, style="FD")
    pdf.set_xy(x, y + 2)
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*_RED)
    pdf.cell(w, 8, value, align="C", ln=True)
    pdf.set_x(x)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*_GRAY)
    pdf.multi_cell(w, 4, label, align="C")
    pdf.set_xy(x + w + 4, y)
    pdf.set_text_color(0, 0, 0)


def _table(pdf: _Report, rows: list[list[str]], col_widths: list[int]) -> None:
    header = rows[0]
    data   = rows[1:]

    # Header row
    pdf.set_fill_color(*_NAVY)
    pdf.set_text_color(*_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    for text, w in zip(header, col_widths):
        pdf.cell(w, 7, text, border=0, fill=True)
    pdf.ln()

    # Data rows
    pdf.set_text_color(0, 0, 0)
    for i, row in enumerate(data):
        if pdf.get_y() > 265:
            pdf.add_page()
            # Re-print header
            pdf.set_fill_color(*_NAVY)
            pdf.set_text_color(*_WHITE)
            pdf.set_font("Helvetica", "B", 8)
            for text, w in zip(header, col_widths):
                pdf.cell(w, 7, text, border=0, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)

        pdf.set_fill_color(*(_LIGHT if i % 2 == 0 else _WHITE))
        pdf.set_font("Helvetica", "", 8)
        for text, w in zip(row, col_widths):
            pdf.cell(w, 6, str(text)[:60], border=0, fill=True)
        pdf.ln()


def _compute_tactic_coverage(techniques: list[dict]) -> list[dict]:
    from collections import defaultdict
    by_tactic: dict[str, list[float]] = defaultdict(list)
    for t in techniques:
        by_tactic[t.get("tactic", "unknown")].append(float(t.get("confidence", 0.5)))

    result = []
    for tactic, confs in sorted(by_tactic.items()):
        result.append({
            "tactic":  tactic,
            "total":   len(confs),
            "high":    sum(1 for c in confs if c >= 0.8),
            "medium":  sum(1 for c in confs if 0.5 <= c < 0.8),
            "low":     sum(1 for c in confs if c < 0.5),
        })
    return result


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
