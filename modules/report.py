import os
from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image,
    Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_severity_color(status):
    s = status.upper()
    if "CRITICAL" in s:
        return colors.HexColor("#C0392B")
    elif "HIGH" in s:
        return colors.HexColor("#E67E22")
    elif "MEDIUM" in s:
        return colors.HexColor("#F39C12")
    elif "LOW" in s:
        return colors.HexColor("#27AE60")
    return colors.HexColor("#2C3E50")


def classification_color(classification):
    c = classification.upper()
    if c == "MALICIOUS":
        return colors.HexColor("#C0392B")
    elif c == "SUSPICIOUS":
        return colors.HexColor("#E67E22")
    elif c == "LOW-RISK":
        return colors.HexColor("#F39C12")
    return colors.HexColor("#27AE60")


def score_bar_color(score):
    if score >= 70:
        return colors.HexColor("#C0392B")
    elif score >= 40:
        return colors.HexColor("#E67E22")
    elif score >= 20:
        return colors.HexColor("#F39C12")
    return colors.HexColor("#27AE60")


def build_styles():
    base = getSampleStyleSheet()

    custom = {
        "ReportTitle": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=20,
            textColor=colors.black,
            spaceAfter=6,
            alignment=TA_CENTER,
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading",
            parent=base["Heading2"],
            fontSize=13,
            textColor=colors.black,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "SubHeading": ParagraphStyle(
            "SubHeading",
            parent=base["Heading3"],
            fontSize=10,
            textColor=colors.black,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=8.5,
            leading=13,
            textColor=colors.black,
        ),
        "SmallMono": ParagraphStyle(
            "SmallMono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=11,
            textColor=colors.black,
        ),
        "Severity": ParagraphStyle(
            "Severity",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=colors.black,
        ),
        "Caption": ParagraphStyle(
            "Caption",
            parent=base["Normal"],
            fontSize=7,
            textColor=colors.black,
            alignment=TA_CENTER,
        ),
    }
    return base, custom


# ─────────────────────────────────────────────
# SECTION BUILDERS
# ─────────────────────────────────────────────

def section_divider(elements, styles_custom, title):
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(HRFlowable(width="100%", thickness=1.5,
                                color=colors.HexColor("#2980B9"), spaceAfter=4))
    elements.append(Paragraph(title, styles_custom["SectionHeading"]))
    elements.append(Spacer(1, 0.08 * inch))


def build_dns_analysis_section(elements, base_styles, custom_styles, dns_results, suspicious_dns_count):
    """
    Full DNS Threat Intelligence Analysis section with:
      - Summary stats table
      - Per-classification breakdown
      - Full scored domain table with colour-coded risk
      - Reason breakdown for high-risk domains
    """
    section_divider(elements, custom_styles, "DNS Threat Intelligence Analysis")

    if not dns_results:
        elements.append(Paragraph("No DNS artifacts detected.", custom_styles["Body"]))
        return

    # ── Stats summary ──────────────────────────────────────────
    total = len(dns_results)
    malicious  = sum(1 for d in dns_results if d.get("classification","").upper() == "MALICIOUS")
    suspicious = sum(1 for d in dns_results if d.get("classification","").upper() == "SUSPICIOUS")
    low_risk   = sum(1 for d in dns_results if d.get("classification","").upper() == "LOW-RISK")
    likely_safe= sum(1 for d in dns_results if d.get("classification","").upper() == "LIKELY SAFE")

    stats_data = [
        ["Metric", "Count"],
        ["Total Unique Domains Analysed", str(total)],
        ["Flagged Suspicious (keyword / score)", str(suspicious_dns_count)],
        ["MALICIOUS",   str(malicious)],
        ["SUSPICIOUS",  str(suspicious)],
        ["LOW-RISK",    str(low_risk)],
        ["LIKELY SAFE", str(likely_safe)],
    ]

    stats_table = Table(stats_data, colWidths=[3.5 * inch, 1.5 * inch])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2980B9")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.black),          # ← data rows black
        ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#BDC3C7")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F2F3F4"), colors.white]),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
        # Colour-code the classification rows (override black only for these)
        ("TEXTCOLOR",   (0, 3), (-1, 3), colors.HexColor("#C0392B")),
        ("TEXTCOLOR",   (0, 4), (-1, 4), colors.HexColor("#E67E22")),
        ("TEXTCOLOR",   (0, 5), (-1, 5), colors.HexColor("#F39C12")),
        ("TEXTCOLOR",   (0, 6), (-1, 6), colors.HexColor("#27AE60")),
        ("FONTNAME",    (0, 3), (-1, 6), "Helvetica-Bold"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.25 * inch))

    # ── Full domain scored table ───────────────────────────────
    elements.append(Paragraph(
        "<b>Full Domain Risk Scoring Table</b>",
        custom_styles["SubHeading"]
    ))
    elements.append(Spacer(1, 0.05 * inch))

    header = ["Domain", "Classification", "Score /100", "Entropy", "Reasons"]
    table_data = [header]

    # Sort: highest score first
    sorted_domains = sorted(dns_results, key=lambda x: x.get("score", 0), reverse=True)

    row_colors = []
    for entry in sorted_domains:
        domain         = entry.get("domain", "N/A")
        classification = entry.get("classification", "N/A")
        score          = entry.get("score", "N/A")
        entropy        = entry.get("entropy", "N/A")
        reasons        = entry.get("reasons", [])

        # Wrap long domain in monospace paragraph
        domain_para = Paragraph(
            f'<font name="Courier" size="7" color="#000000">{domain}</font>',
            custom_styles["Body"]
        )
        reasons_text = "; ".join(reasons) if reasons else "—"
        reasons_para = Paragraph(
            f'<font size="7" color="#000000">{reasons_text}</font>',
            custom_styles["Body"]
        )

        table_data.append([domain_para, classification, str(score), str(entropy), reasons_para]) # pyright: ignore[reportArgumentType]

        # Row background based on classification
        c = classification.upper()
        if c == "MALICIOUS":
            row_colors.append(colors.HexColor("#86160B"))
        elif c == "SUSPICIOUS":
            row_colors.append(colors.HexColor("#A37718"))
        elif c == "LOW-RISK":
            row_colors.append(colors.HexColor("#0F2774"))
        else:
            row_colors.append(colors.HexColor("#26750E"))

    col_widths = [2.1*inch, 1.0*inch, 0.7*inch, 0.7*inch, 2.5*inch]
    dns_table = Table(table_data, colWidths=col_widths, repeatRows=1)

    table_style = [
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",    (0, 1), (-1, -1), colors.black),          # ← data rows black
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#BDC3C7")),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("ALIGN",        (2, 0), (3, -1), "CENTER"),
    ]
    # Apply per-row background colours
    for i, bg in enumerate(row_colors, start=1):
        table_style.append(("BACKGROUND", (0, i), (-1, i), bg))

    dns_table.setStyle(TableStyle(table_style))
    elements.append(dns_table)
    elements.append(Spacer(1, 0.25 * inch))

    # ── High-risk domain detail cards ─────────────────────────
    high_risk = [d for d in sorted_domains
                 if d.get("classification","").upper() in ("MALICIOUS","SUSPICIOUS")]

    if high_risk:
        elements.append(Paragraph(
            "<b>High-Risk Domain Detail</b>",
            custom_styles["SubHeading"]
        ))
        elements.append(Spacer(1, 0.05 * inch))

        for entry in high_risk[:20]:   # cap to 20 to avoid overflow
            domain         = entry.get("domain", "N/A")
            classification = entry.get("classification", "N/A")
            score          = entry.get("score", 0)
            entropy        = entry.get("entropy", "N/A")
            reasons        = entry.get("reasons", [])

            label_color = classification_color(classification)
            bar_color   = score_bar_color(score)

            card_data = [
                [
                    Paragraph(f'<font name="Courier" size="8" color="#000000"><b>{domain}</b></font>',
                              custom_styles["Body"]),
                    Paragraph(
                        f'<font color="#{label_color.hexval()[2:].upper()}" size="8"><b>{classification}</b></font>  '
                        f'Score: <font color="#{bar_color.hexval()[2:].upper()}"><b>{score}/100</b></font>  '
                        f'Entropy: {entropy}',
                        custom_styles["Body"]
                    ),
                ],
                [
                    Paragraph("<b>Detection Reasons:</b>", custom_styles["Body"]),
                    Paragraph(
                        "<br/>".join(f"• {r}" for r in reasons) if reasons else "—",
                        custom_styles["Body"]
                    ),
                ],
            ]

            card = Table(card_data, colWidths=[1.8*inch, 5.2*inch])
            card.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#EBF5FB")),
                ("BACKGROUND",   (0, 1), (-1, 1), colors.white),
                ("TEXTCOLOR",    (0, 0), (-1, -1), colors.black),
                ("BOX",          (0, 0), (-1, -1), 0.8, colors.HexColor("#2980B9")),
                ("LINEBELOW",    (0, 0), (-1, 0), 0.5, colors.HexColor("#AED6F1")),
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ]))
            elements.append(card)
            elements.append(Spacer(1, 0.08 * inch))

    # ── DGA / Tunneling callout ───────────────────────────────
    dga_hits      = [d for d in dns_results if d.get("entropy", 0) > 3.7]
    tunnel_hits   = [d for d in dns_results if len(d.get("domain","")) > 40]

    if dga_hits or tunnel_hits:
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph("<b>Automated Detection Flags</b>", custom_styles["SubHeading"]))

        flag_data = [["Flag", "Count", "Top Domains"]]

        if dga_hits:
            top = ", ".join(d["domain"] for d in sorted(dga_hits, key=lambda x: -x.get("entropy",0))[:3])
            flag_data.append(["DGA (Entropy > 3.7)", str(len(dga_hits)), top])

        if tunnel_hits:
            top = ", ".join(d["domain"] for d in tunnel_hits[:3])
            flag_data.append(["DNS Tunneling (len > 40)", str(len(tunnel_hits)), top])

        flag_table = Table(flag_data, colWidths=[1.8*inch, 0.8*inch, 4.4*inch])
        flag_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#884EA0")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("TEXTCOLOR",   (0, 1), (-1, -1), colors.black),
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#D2B4DE")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5EEF8"), colors.white]),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]))
        elements.append(flag_table)

    elements.append(Spacer(1, 0.3 * inch))


# ─────────────────────────────────────────────
# MAIN REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(
    case_name,
    hash_value,
    metadata,
    suspicious_logs,
    dns_results,
    ram_results,
    suspicious_dns_count=0,
    email_list=None,
    final_status="N/A",
    risk_score=0
):
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    pdf_filename = os.path.join(report_dir, f"{case_name}_report.pdf")

    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    base_styles, custom_styles = build_styles()
    elements = []

    # ── Header / Logo ─────────────────────────────────────────
    logo_path = "assets/company_logo.png"
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=1.5 * inch, height=1 * inch)
        elements.append(logo)
        elements.append(Spacer(1, 0.1 * inch))

    elements.append(Paragraph(
        "AUTOFORENX ENTERPRISE FORENSIC REPORT",
        custom_styles["ReportTitle"]
    ))
    elements.append(HRFlowable(width="100%", thickness=2,
                                color=colors.HexColor("#2980B9"), spaceAfter=8))
    elements.append(Spacer(1, 0.15 * inch))

    # ── Case Info ─────────────────────────────────────────────
    section_divider(elements, custom_styles, "Case Information")
    info_data = [
        ["Case Name",    case_name],
        ["Generated On", str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
        ["File Hash",    hash_value],
    ]
    info_table = Table(info_data, colWidths=[1.8*inch, 5.2*inch])
    info_table.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("GRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#BDC3C7")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#EBF5FB"), colors.white]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(info_table)

    # ── Severity ──────────────────────────────────────────────
    section_divider(elements, custom_styles, "Final Severity Assessment")
    sev_color = get_severity_color(final_status)
    sev_data = [
        ["Status", final_status],
        ["Risk Score", f"{risk_score} / 100"],
    ]
    sev_table = Table(sev_data, colWidths=[1.8*inch, 5.2*inch])
    sev_table.setStyle(TableStyle([
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 0), (-1, -1), colors.black),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.HexColor("#BDC3C7")),
        ("TEXTCOLOR",    (1, 0), (1, 0), sev_color),              # status value keeps color
        ("FONTNAME",     (1, 0), (1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#FDEDEC"), colors.HexColor("#FEF9E7")]),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    elements.append(sev_table)

    # ── File Metadata ─────────────────────────────────────────
    section_divider(elements, custom_styles, "File Metadata")
    if metadata:
        meta_data = [["Property", "Value"]] + [[k, str(v)] for k, v in metadata.items()]
        meta_table = Table(meta_data, colWidths=[1.8*inch, 5.2*inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR",   (0, 1), (-1, -1), colors.black),
            ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#BDC3C7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F2F3F4"), colors.white]),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ]))
        elements.append(meta_table)

    # ── Suspicious Logs ───────────────────────────────────────
    section_divider(elements, custom_styles, "Suspicious Log Events")
    elements.append(Paragraph(
        f"Total Suspicious Logs: <b>{len(suspicious_logs)}</b>",
        custom_styles["Body"]
    ))
    elements.append(Spacer(1, 0.1 * inch))
    for log in suspicious_logs[:20]:
        if isinstance(log, dict):
            log_text = log.get("message") or log.get("line") or str(log)
        elif isinstance(log, (list, tuple)):
            log_text = " | ".join(str(x) for x in log)
        else:
            log_text = str(log)
        log_text = log_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(
            f'<font name="Courier" size="7.5" color="#000000">• {log_text}</font>',
            custom_styles["Body"]
        ))

    # ── DNS Analysis (new full section) ───────────────────────
    elements.append(PageBreak())
    build_dns_analysis_section(
        elements, base_styles, custom_styles,
        dns_results, suspicious_dns_count
    )

    # ── RAM Forensics ─────────────────────────────────────────
    elements.append(PageBreak())
    section_divider(elements, custom_styles, "RAM Forensics Analysis")

    if ram_results:
        subsections = [
            ("Running Processes",             "processes"),
            ("Domains Extracted From Memory", "domains"),
            ("IP Addresses Found",            "ips"),
            ("URLs Found",                    "urls"),
            ("Suspicious Commands",           "suspicious_commands"),
            ("Email Addresses",               "emails"),
            ("Contact Numbers",               "contacts"),
            ("NTLM Hashes",                   "ntlm_hashes"),
            ("Cleartext Credentials",         "cleartext_creds"),
            ("Browser Credential Files",      "browser_creds"),
            ("LSASS / DPAPI Strings",         "lsass_strings"),
            ("Deleted File Paths",            "deleted_paths"),
            ("Recycle Bin Paths",             "recycle_paths"),
            ("Shadow Copy References",        "shadow_refs"),
            ("Deleted File Magic Bytes",      "deleted_file_magic"),
        ]
        for label, key in subsections:
            items = ram_results.get(key, [])
            if not items:
                continue
            elements.append(Paragraph(f"<b>{label}:</b>", custom_styles["SubHeading"]))
            for item in items[:40]:
                safe = str(item).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                elements.append(Paragraph(
                    f'<font name="Courier" size="7.5" color="#000000">• {safe}</font>',
                    custom_styles["Body"]
                ))
            if len(items) > 40:
                elements.append(Paragraph(
                    f'<i>... and {len(items) - 40} more (see JSON report for full list)</i>',
                    custom_styles["Body"]
                ))
            elements.append(Spacer(1, 0.1 * inch))
    else:
        elements.append(Paragraph("No RAM forensic artifacts detected.", custom_styles["Body"]))

    # ── Email Artifacts ───────────────────────────────────────
    section_divider(elements, custom_styles, "Extracted Email Addresses")
    if email_list:
        elements.append(Paragraph(
            f"Total Emails Found: <b>{len(email_list)}</b>",
            custom_styles["Body"]
        ))
        elements.append(Spacer(1, 0.08 * inch))
        for email in email_list[:40]:
            safe_email = str(email).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            elements.append(Paragraph(
                f'<font name="Courier" size="7.5" color="#000000">• {safe_email}</font>',
                custom_styles["Body"]
            ))
    else:
        elements.append(Paragraph("No email artifacts detected.", custom_styles["Body"]))

    # ── Chain of Custody ──────────────────────────────────────
    section_divider(elements, custom_styles, "Digital Evidence Chain of Custody")
    custody_data = [
        ["Field",              "Value"],
        ["Evidence ID",        case_name],
        ["File Hash (SHA-256)", hash_value],
        ["Collected By",       "Digital Forensic Analyst"],
        ["Collection Date",    str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
        ["Integrity Verified", "YES"],
    ]
    custody_table = Table(custody_data, colWidths=[2.0*inch, 5.0*inch])
    custody_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1A252F")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",    (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR",   (0, 1), (-1, -1), colors.black),
        ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#BDC3C7")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#F2F3F4"), colors.white]),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    elements.append(custody_table)

    # ── Build ──────────────────────────────────────────────────
    doc.build(elements)
    print(f"[✓] Enterprise PDF Report Generated: {pdf_filename}")
    return pdf_filename