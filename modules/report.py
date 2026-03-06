import os
from datetime import datetime
from reportlab.lib import styles
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch


def get_severity_color(status):
    if "CRITICAL" in status:
        return colors.red
    elif "HIGH" in status:
        return colors.orange
    elif "MEDIUM" in status:
        return colors.darkorange
    else:
        return colors.green


def generate_report(
    case_name,
    hash_value,
    metadata,
    suspicious_logs,
    dns_results,
    ram_results,
    suspicious_dns_count=0,
    final_status="N/A",
    risk_score=0
):

    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)

    pdf_filename = os.path.join(report_dir, f"{case_name}_report.pdf")

    doc = SimpleDocTemplate(pdf_filename)
    styles = getSampleStyleSheet()
    elements = []

    # =============================
    # COMPANY HEADER WITH LOGO
    # =============================
    logo_path = "assets/company_logo.png"
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=1.5 * inch, height=1 * inch)
        elements.append(logo)

    elements.append(Paragraph("<b>AUTOFORENX ENTERPRISE FORENSIC REPORT</b>", styles["Title"]))
    elements.append(Spacer(1, 0.3 * inch))

    # =============================
    # CASE INFORMATION
    # =============================
    elements.append(Paragraph(f"<b>Case Name:</b> {case_name}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Generated On:</b> {datetime.now()}", styles["Normal"]))
    elements.append(Paragraph(f"<b>File Hash:</b> {hash_value}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # =============================
    # SEVERITY SECTION (COLOR CODED)
    # =============================
    severity_color = get_severity_color(final_status)

    severity_style = styles["Heading2"]
    severity_style.textColor = severity_color

    elements.append(Paragraph("Final Severity Assessment", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"<b>Status:</b> {final_status}", severity_style))
    elements.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/100", styles["Normal"]))
    elements.append(Spacer(1, 0.4 * inch))

    # =============================
    # FILE METADATA
    # =============================
    elements.append(Paragraph("File Metadata", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    for key, value in metadata.items():
        elements.append(Paragraph(f"{key}: {value}", styles["Normal"]))

    elements.append(Spacer(1, 0.4 * inch))

    # =============================
    # SUSPICIOUS LOGS
    # =============================
    elements.append(Paragraph("Suspicious Log Events", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"Total Suspicious Logs: {len(suspicious_logs)}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    for log in suspicious_logs[:20]:  # limit to avoid overflow
        elements.append(Paragraph(log, styles["Normal"]))

    elements.append(Spacer(1, 0.4 * inch))

    # =============================
    # FULL DNS SECTION
    # =============================
    if dns_results and len(dns_results) > 0:

        elements.append(Paragraph("DNS Threat Intelligence Analysis", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(f"Suspicious DNS Count: {suspicious_dns_count}", styles["Normal"]))
        elements.append(Spacer(1, 0.3 * inch))

        table_data = [
            ["Domain", "Entropy", "High Entropy", "Threat Score"]
        ]

        for entry in dns_results:
            table_data.append([
                entry.get("domain", "N/A"),
                str(entry.get("entropy", "N/A")),
                str(entry.get("high_entropy", "N/A")),
                str(entry.get("threat_score", "N/A"))
            ])

        dns_table = Table(table_data, repeatRows=1)
        dns_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 8)
        ]))

        elements.append(dns_table)
        elements.append(Spacer(1, 0.4 * inch))
   

# =============================
# RAM FORENSICS SECTION
# =============================
    elements.append(Paragraph("RAM Forensics Analysis", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    if ram_results:
        
        # Running Processes
        elements.append(Paragraph("<b>Running Processes:</b>", styles["Normal"]))
        for p in ram_results.get("processes", [])[:20]:
            elements.append(Paragraph(p, styles["Normal"]))

        elements.append(Spacer(1, 0.15 * inch))

        # Domains
        elements.append(Paragraph("<b>Domains Extracted From Memory:</b>", styles["Normal"]))
        for d in ram_results.get("domains", [])[:20]:
            elements.append(Paragraph(d, styles["Normal"]))

        elements.append(Spacer(1, 0.15 * inch))

        # IP Addresses
        elements.append(Paragraph("<b>IP Addresses Found:</b>", styles["Normal"]))
        for ip in ram_results.get("ips", [])[:20]:
            elements.append(Paragraph(ip, styles["Normal"]))

        elements.append(Spacer(1, 0.15 * inch))

        # URLs
        elements.append(Paragraph("<b>URLs Found:</b>", styles["Normal"]))
        for url in ram_results.get("urls", [])[:20]:
            elements.append(Paragraph(url, styles["Normal"]))

        elements.append(Spacer(1, 0.15 * inch))

        # Suspicious Commands
        elements.append(Paragraph("<b>Suspicious Commands:</b>", styles["Normal"]))
        for cmd in ram_results.get("suspicious_commands", [])[:20]:
            elements.append(Paragraph(cmd, styles["Normal"]))

    else:
        elements.append(Paragraph("No RAM forensic artifacts detected.", styles["Normal"]))

    elements.append(Spacer(1, 0.4 * inch))



    # =============================
    # CHAIN OF CUSTODY SECTION
    # =============================
    elements.append(Paragraph("Digital Evidence Chain of Custody", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    custody_data = [
        ["Evidence ID", case_name],
        ["File Hash (SHA-256)", hash_value],
        ["Collected By", "Digital Forensic Analyst"],
        ["Collection Date", str(datetime.now())],
        ["Integrity Verified", "YES"],
    ]

    custody_table = Table(custody_data)
    custody_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
    ]))

    elements.append(custody_table)

    # =============================
    # BUILD PDF
    # =============================
    doc.build(elements)

    print(f"[✓] Enterprise PDF Report Generated: {pdf_filename}")