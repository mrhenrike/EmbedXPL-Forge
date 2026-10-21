#!/usr/bin/env python3
"""
Generate PDFs from Samsung Tizen vulnerability report Markdown files.
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import os
import sys
import tempfile

_project_tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)
tempfile.tempdir = _project_tmp

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.platypus import PageBreak, Preformatted
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
except ImportError:
    print("reportlab not found. Install with: pip install reportlab")
    sys.exit(1)

import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MD_FILES = {
    "MASTER_VULNERABILITY_REPORT.md":      "MASTER_VULNERABILITY_REPORT.pdf",
    "EMAIL_SAMSUNG_PSIRT.md":             "EMAIL_SAMSUNG_PSIRT.pdf",
    "CERT_VINCE_SAMSUNG.md":              "CERT_VINCE_SAMSUNG.pdf",
    "SAMSUNG_TV_PORTAL_SUBMISSION.md":    "SAMSUNG_TV_PORTAL_SUBMISSION.pdf",
}

COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#e67e22"),
    "medium":   colors.HexColor("#f39c12"),
    "low":      colors.HexColor("#27ae60"),
    "header":   colors.HexColor("#2c3e50"),
    "accent":   colors.HexColor("#2980b9"),
    "code_bg":  colors.HexColor("#f8f9fa"),
    "row_even": colors.HexColor("#ecf0f1"),
}


def build_styles():
    ss = getSampleStyleSheet()
    styles = {}

    def add_or_update(name, **kwargs):
        if name in ss:
            for k, v in kwargs.items():
                setattr(ss[name], k, v)
            styles[name] = ss[name]
        else:
            styles[name] = ParagraphStyle(name, **kwargs)
            ss.add(styles[name])

    add_or_update("Normal",   fontName="Helvetica", fontSize=9,  leading=14, spaceAfter=4)
    add_or_update("Heading1", fontName="Helvetica-Bold", fontSize=16, leading=20, spaceAfter=12, textColor=COLORS["header"])
    add_or_update("Heading2", fontName="Helvetica-Bold", fontSize=13, leading=17, spaceAfter=8,  textColor=COLORS["header"])
    add_or_update("Heading3", fontName="Helvetica-Bold", fontSize=11, leading=15, spaceAfter=6,  textColor=COLORS["accent"])

    for name, base_name, extra in [
        ("Code",      "Normal",  {"fontName": "Courier", "fontSize": 8, "leading": 11, "backColor": COLORS["code_bg"]}),
        ("Bold",      "Normal",  {"fontName": "Helvetica-Bold"}),
        ("Meta",      "Normal",  {"fontSize": 8, "textColor": colors.grey}),
        ("TableCell", "Normal",  {"fontSize": 8, "leading": 11}),
        ("TableHead", "Normal",  {"fontName": "Helvetica-Bold", "fontSize": 8, "textColor": colors.white}),
    ]:
        if name not in ss:
            parent = ss.get(base_name, ss["Normal"])
            ns     = ParagraphStyle(name, parent=parent, **extra)
            ss.add(ns)
        styles[name] = ss[name]

    return styles


def md_to_flowables(md_text: str, styles: dict) -> list:
    flowables = []
    lines = md_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("# "):
            flowables.append(Paragraph(line[2:].strip(), styles["Heading1"]))
            flowables.append(HRFlowable(width="100%", thickness=2, color=COLORS["header"]))
            flowables.append(Spacer(1, 0.2*cm))
        elif line.startswith("## "):
            flowables.append(Spacer(1, 0.3*cm))
            flowables.append(Paragraph(line[3:].strip(), styles["Heading2"]))
            flowables.append(HRFlowable(width="100%", thickness=1, color=COLORS["accent"]))
        elif line.startswith("### "):
            flowables.append(Spacer(1, 0.2*cm))
            flowables.append(Paragraph(line[4:].strip(), styles["Heading3"]))
        elif line.startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i])
                i += 1
            code_text = "\n".join(code_lines)
            flowables.append(Preformatted(code_text, styles["Code"]))
            flowables.append(Spacer(1, 0.15*cm))
        elif line.startswith("|"):
            # Table
            table_lines = []
            while i < len(lines) and lines[i].startswith("|"):
                table_lines.append(lines[i])
                i += 1
            i -= 1
            table_lines = [l for l in table_lines if not re.match(r"^\|[-| ]+\|$", l)]
            if table_lines:
                data = []
                for tl in table_lines:
                    cells = [c.strip() for c in tl.strip("|").split("|")]
                    data.append(cells)
                if data:
                    col_count = max(len(r) for r in data)
                    for r in data:
                        while len(r) < col_count:
                            r.append("")
                    header_row = [Paragraph(c, styles["TableHead"]) for c in data[0]]
                    body_rows  = [[Paragraph(c, styles["TableCell"]) for c in row] for row in data[1:]]
                    table_data = [header_row] + body_rows
                    col_w      = (17.5 * cm) / col_count
                    tbl        = Table(table_data, colWidths=[col_w] * col_count, repeatRows=1)
                    tbl.setStyle(TableStyle([
                        ("BACKGROUND",  (0,0), (-1,0),  COLORS["header"]),
                        ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
                        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
                        ("FONTSIZE",    (0,0), (-1,-1), 8),
                        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, COLORS["row_even"]]),
                        ("GRID",        (0,0), (-1,-1), 0.3, colors.lightgrey),
                        ("VALIGN",      (0,0), (-1,-1), "TOP"),
                        ("LEFTPADDING",  (0,0), (-1,-1), 4),
                        ("RIGHTPADDING", (0,0), (-1,-1), 4),
                        ("TOPPADDING",   (0,0), (-1,-1), 3),
                        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
                    ]))
                    flowables.append(tbl)
                    flowables.append(Spacer(1, 0.2*cm))
        elif line.startswith("- ") or line.startswith("* "):
            text = "• " + line[2:].strip()
            flowables.append(Paragraph(text, styles["Normal"]))
        elif line.startswith("**") and line.endswith("**"):
            flowables.append(Paragraph(f"<b>{line[2:-2]}</b>", styles["Normal"]))
        elif line.startswith("---"):
            flowables.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
            flowables.append(Spacer(1, 0.1*cm))
        elif line.strip() == "":
            flowables.append(Spacer(1, 0.15*cm))
        else:
            # Inline bold/code formatting
            text = line
            text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
            text = re.sub(r"`(.+?)`",        r"<font name='Courier'>\1</font>", text)
            text = re.sub(r"\[(.+?)\]\((.+?)\)", r'\1 (<font name="Courier" size="7">\2</font>)', text)
            flowables.append(Paragraph(text, styles["Normal"]))

        i += 1
    return flowables


def generate_pdf(md_path: str, pdf_path: str) -> None:
    with open(md_path, encoding="utf-8") as f:
        md_text = f.read()

    doc    = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
    )
    styles = build_styles()

    def header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(2*cm, A4[1] - 1.5*cm, "Samsung Tizen Smart TV — Security Research | CONFIDENTIAL")
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.5*cm, "Andre Henrique (@mrhenrike) | Uniao Geek")
        canvas.drawString(2*cm, 1.3*cm, f"Page {doc.page}")
        canvas.drawRightString(A4[0] - 2*cm, 1.3*cm, "Embargo: 2026-07-20 | security@uniaogeek.com")
        canvas.restoreState()

    story = md_to_flowables(md_text, styles)
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"  [+] {os.path.basename(pdf_path)}")


def create_poc_zip(base_dir: str) -> str:
    import zipfile
    import hashlib

    poc_dir    = os.path.join(base_dir, "pocs")
    zip_name   = "Samsung_Tizen_ZeroDay_PoC_TIZEN-2026_UniaoGeek.zip"
    zip_path   = os.path.join(base_dir, zip_name)
    report_pdf = os.path.join(base_dir, "MASTER_VULNERABILITY_REPORT.pdf")

    files_to_zip = [
        (os.path.join(poc_dir, "e2e_poc_tizen_smarthub.py"), "e2e_poc_tizen_smarthub.py"),
        (os.path.join(poc_dir, "tizen_smarthub_audit.py"),   "tizen_smarthub_audit.py"),
        (os.path.join(poc_dir, "tizen_upnp_audit.py"),       "tizen_upnp_audit.py"),
        (os.path.join(poc_dir, "samsung_firmware_analysis.py"), "samsung_firmware_analysis.py"),
        (os.path.join(poc_dir, "README.md"),                  "pocs/README.md"),
    ]
    if os.path.exists(report_pdf):
        files_to_zip.append((report_pdf, "MASTER_VULNERABILITY_REPORT.pdf"))

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for src, dst in files_to_zip:
            if os.path.exists(src):
                zf.write(src, dst)
            else:
                print(f"  [!] Missing: {src}")

    size_kb = os.path.getsize(zip_path) // 1024
    sha256  = hashlib.sha256(open(zip_path, "rb").read()).hexdigest()
    print(f"  [+] {zip_name} — {size_kb} KB — SHA256: {sha256[:16]}...")
    return zip_path


def main():
    print("\n[*] Samsung Tizen — PDF + ZIP Generator")
    print("="*50)

    styles = build_styles()

    for md_name, pdf_name in MD_FILES.items():
        md_path  = os.path.join(BASE_DIR, md_name)
        pdf_path = os.path.join(BASE_DIR, pdf_name)
        if not os.path.exists(md_path):
            print(f"  [!] Not found: {md_name}")
            continue
        print(f"  Generating {pdf_name}...")
        try:
            generate_pdf(md_path, pdf_path)
        except Exception as e:
            print(f"  [ERR] {pdf_name}: {e}")

    print("\n  Generating PoC ZIP...")
    create_poc_zip(BASE_DIR)
    print("\nDone.")


if __name__ == "__main__":
    main()
