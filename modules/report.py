from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Paragraph
from reportlab.platypus import Spacer
from reportlab.platypus import ListFlowable, ListItem

def generate_report(case_name, hash_value, metadata, suspicious_lines):
    doc = SimpleDocTemplate(f"cases/{case_name}.pdf")
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("AutoForenX Forensic Report", styles['Title']))
    elements.append(Spacer(1, 0.5 * inch))

    elements.append(Paragraph(f"SHA-256 Hash: {hash_value}", styles['Normal']))
    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("File Metadata:", styles['Heading2']))
    for key, value in metadata.items():
        elements.append(Paragraph(f"{key}: {value}", styles['Normal']))

    elements.append(Spacer(1, 0.3 * inch))

    elements.append(Paragraph("Suspicious Log Entries:", styles['Heading2']))
    for line in suspicious_lines:
        elements.append(Paragraph(line, styles['Normal']))

    doc.build(elements)