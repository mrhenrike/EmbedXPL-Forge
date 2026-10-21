#!/usr/bin/env python3
"""
Template — Convert markdown reports to PDF using reportlab.
Author: Andre Henrique (@mrhenrike) | Uniao Geek

INSTRUCTIONS:
1. Copy this file to reports/<target>/generate_pdfs.py
2. Edit the md_files dict in main() with your actual filenames
3. Run: python generate_pdfs.py
4. PDFs appear in the same directory as the .md files

Requirements: pip install reportlab
"""
import os
import re
import textwrap
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))


def md_to_elements(md_path, styles):
    """Parse markdown into reportlab flowable elements."""
    with open(md_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    elements = []
    in_code = False
    code_buf = []
    in_table = False
    table_rows = []

    def flush_code():
        nonlocal code_buf
        if code_buf:
            code_text = "".join(code_buf).rstrip()
            wrapped = "\n".join(
                textwrap.fill(line, width=90) if len(line) > 90 else line
                for line in code_text.split("\n")
            )
            elements.append(Spacer(1, 4 * mm))
            elements.append(Paragraph(
                f"<pre><font size=7 face='Courier'>{_esc(wrapped)}</font></pre>",
                styles["Code"]
            ))
            elements.append(Spacer(1, 4 * mm))
            code_buf = []

    def flush_table():
        nonlocal table_rows
        if not table_rows:
            return
        col_count = max(len(r) for r in table_rows)
        for i, row in enumerate(table_rows):
            while len(row) < col_count:
                row.append("")

        avail = 170 * mm
        col_w = avail / col_count
        t = Table(table_rows, colWidths=[col_w] * col_count)
        t_style = [
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#bdc3c7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i in range(1, len(table_rows)):
            if i % 2 == 0:
                t_style.append(("BACKGROUND", (0, i), (-1, i), HexColor("#ecf0f1")))
        t.setStyle(TableStyle(t_style))
        elements.append(Spacer(1, 3 * mm))
        elements.append(t)
        elements.append(Spacer(1, 3 * mm))
        table_rows = []

    def _esc(text):
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\n", "<br/>"))

    for raw_line in lines:
        line = raw_line.rstrip("\n")

        if line.startswith("```"):
            if in_code:
                in_code = False
                flush_code()
            else:
                if in_table:
                    flush_table()
                    in_table = False
                in_code = True
            continue
        if in_code:
            code_buf.append(line + "\n")
            continue

        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.match(r"^[-:]+$", c) for c in cells):
                in_table = True
                continue
            if not in_table and table_rows == []:
                in_table = True
            table_rows.append(cells)
            continue
        elif in_table:
            flush_table()
            in_table = False

        if not line.strip():
            elements.append(Spacer(1, 3 * mm))
            continue

        if line.startswith("# "):
            elements.append(Spacer(1, 6 * mm))
            elements.append(Paragraph(_esc(line[2:].strip()), styles["Title"]))
            elements.append(HRFlowable(width="100%", thickness=1,
                                       color=HexColor("#2c3e50")))
            elements.append(Spacer(1, 4 * mm))
            continue
        if line.startswith("## "):
            elements.append(Spacer(1, 5 * mm))
            elements.append(Paragraph(_esc(line[3:].strip()), styles["Heading2"]))
            elements.append(Spacer(1, 2 * mm))
            continue
        if line.startswith("### "):
            elements.append(Spacer(1, 4 * mm))
            elements.append(Paragraph(_esc(line[4:].strip()), styles["Heading3"]))
            elements.append(Spacer(1, 2 * mm))
            continue

        if line.strip() == "---":
            elements.append(Spacer(1, 3 * mm))
            elements.append(HRFlowable(width="100%", thickness=0.5,
                                       color=HexColor("#bdc3c7")))
            elements.append(Spacer(1, 3 * mm))
            continue

        if line.startswith("**"):
            clean = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", line)
            elements.append(Paragraph(clean, styles["Normal"]))
            continue

        if line.startswith("- ") or line.startswith("  - "):
            indent = "    " if line.startswith("  ") else ""
            text = line.lstrip(" -").strip()
            text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
            text = re.sub(r"`([^`]+)`", r"<font face='Courier' size=7>\1</font>", text)
            elements.append(Paragraph(f"{indent}* {text}", styles["Bullet"]))
            continue

        m = re.match(r"^(\d+)\.\s+(.*)", line)
        if m:
            text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", m.group(2))
            text = re.sub(r"`([^`]+)`", r"<font face='Courier' size=7>\1</font>", text)
            elements.append(Paragraph(f"{m.group(1)}. {text}", styles["Bullet"]))
            continue

        text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", line)
        text = re.sub(r"`([^`]+)`", r"<font face='Courier' size=7>\1</font>", text)
        elements.append(Paragraph(text, styles["Normal"]))

    if in_code:
        flush_code()
    if in_table:
        flush_table()

    return elements


def build_styles():
    ss = getSampleStyleSheet()
    if "Heading2" not in [s.name for s in ss.byName.values()]:
        ss.add(ParagraphStyle(
            name="Heading2", fontName="Helvetica-Bold", fontSize=12,
            textColor=HexColor("#2c3e50"), spaceAfter=4,
        ))
    else:
        ss["Heading2"].fontName = "Helvetica-Bold"
        ss["Heading2"].fontSize = 12
        ss["Heading2"].textColor = HexColor("#2c3e50")
    if "Heading3" not in [s.name for s in ss.byName.values()]:
        ss.add(ParagraphStyle(
            name="Heading3", fontName="Helvetica-Bold", fontSize=10,
            textColor=HexColor("#34495e"), spaceAfter=3,
        ))
    else:
        ss["Heading3"].fontName = "Helvetica-Bold"
        ss["Heading3"].fontSize = 10
        ss["Heading3"].textColor = HexColor("#34495e")
    for name, kw in [
        ("Bullet", dict(fontName="Helvetica", fontSize=8, leftIndent=12, spaceAfter=2)),
        ("Code", dict(fontName="Courier", fontSize=7, leftIndent=8, rightIndent=8,
                      backColor=HexColor("#f5f5f5"), borderWidth=0.5,
                      borderColor=HexColor("#dcdcdc"), borderPadding=4)),
        ("Title2", dict(fontName="Helvetica-Bold", fontSize=16,
                        textColor=HexColor("#2c3e50"), spaceAfter=6)),
    ]:
        if name not in ss.byName:
            ss.add(ParagraphStyle(name=name, **kw))
    ss["Normal"].fontSize = 8
    ss["Normal"].fontName = "Helvetica"
    ss["Normal"].leading = 11
    return ss


def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 6)
    canvas.setFillColor(HexColor("#7f8c8d"))
    canvas.drawString(20 * mm, 10 * mm,
                      f"Andre Henrique (@mrhenrike) | Uniao Geek — "
                      f"Responsible Disclosure — Page {doc.page}")
    canvas.drawRightString(190 * mm, 10 * mm, "CONFIDENTIAL — EMBARGO 90 DAYS")
    canvas.restoreState()


def convert(md_path, pdf_path):
    print(f"  {os.path.basename(md_path)} -> {os.path.basename(pdf_path)}")
    styles = build_styles()
    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=15 * mm, bottomMargin=20 * mm,
    )
    elements = md_to_elements(md_path, styles)
    doc.build(elements, onFirstPage=add_footer, onLaterPages=add_footer)
    print(f"    -> {os.path.getsize(pdf_path) // 1024} KB")


def main():
    # ================================================================
    # EDIT HERE: Map your .md filenames to desired .pdf output names
    # ================================================================
    md_files = {
        "MASTER_VULNERABILITY_REPORT.md": "MASTER_VULNERABILITY_REPORT.pdf",
        "EMAIL_VENDOR_PSIRT.md":          "EMAIL_VENDOR_PSIRT.pdf",
        "CERT_VINCE_VENDOR.md":           "CERT_VINCE_VENDOR.pdf",
        # Add more as needed:
        # "forensic_report.md":           "forensic_report.pdf",
        # "live_audit_report.md":         "live_audit_report.pdf",
    }
    # ================================================================

    print("[*] Generating PDFs...")
    for md, pdf in md_files.items():
        md_path = os.path.join(REPORT_DIR, md)
        pdf_path = os.path.join(REPORT_DIR, pdf)
        if os.path.exists(md_path):
            try:
                convert(md_path, pdf_path)
            except Exception as e:
                print(f"  ERROR {md}: {e}")
        else:
            print(f"  SKIP {md} (not found)")

    print(f"\n[*] Done. PDFs generated in:\n    {REPORT_DIR}")


if __name__ == "__main__":
    main()
