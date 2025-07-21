import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor

from tkinter import Tk
from tkinter.filedialog import asksaveasfilename

from Database.db_connection import DatabaseConnection


def generate_report(scan_id: int, is_custom: bool = False) -> str:
    # Connect to DB
    db = DatabaseConnection()
    db.connect()

    if is_custom:
        query = "SELECT scanned_url, scan_timestamp, scan_data FROM custom_scans WHERE scan_id = %s"
    else:
        query = "SELECT scanned_url, scan_timestamp, scan_data FROM scan_results WHERE scan_id = %s"
    result = db.fetch_one(query, (scan_id,))
    db.close()

    if not result:
        raise ValueError("Scan ID not found in database.")

    url, timestamp, scan_data = result

    if isinstance(scan_data, str):
        scan_data = json.loads(scan_data)

    # Ask where to save
    root = Tk()
    root.withdraw()
    filename = asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Save Security Report As",
        initialfile=f"scan_report_{scan_id}.pdf"
    )
    root.destroy()

    if not filename:
        print("User canceled save dialog.")
        return ""

    # Document setup
    doc = SimpleDocTemplate(filename, pagesize=A4,
                            rightMargin=50, leftMargin=50,
                            topMargin=50, bottomMargin=50)

    # Styles
    styles = getSampleStyleSheet()

    header_style = ParagraphStyle(
        'Header',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=HexColor("#0B5394"),
        spaceAfter=20
    )

    subheader_style = ParagraphStyle(
        'SubHeader',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=HexColor("#3D85C6"),
        spaceAfter=10
    )

    meta_style = ParagraphStyle(
        'Meta',
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        spaceAfter=10
    )

    content_style = ParagraphStyle(
        'Content',
        fontName='Helvetica',
        fontSize=11,
        leading=14,
        alignment=TA_LEFT,
        textColor=HexColor("#333333"),
        spaceAfter=6
    )

    story = []

    # Header
    story.append(Paragraph("🔐 Security Scan Report", header_style))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", meta_style))
    story.append(Paragraph(f"<b>Scanned URL:</b> {url}", meta_style))
    story.append(Paragraph(f"<b>Timestamp:</b> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
    story.append(Spacer(1, 0.2 * inch))

    # Helper to render nested data
    def render_dict(data, indent=0):
        elements = []
        indent_space = "&nbsp;" * (4 * indent)
        for key, value in data.items():
            if isinstance(value, dict):
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b>", content_style))
                elements.extend(render_dict(value, indent + 1))
            elif isinstance(value, list):
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b>", content_style))
                for i, item in enumerate(value, start=1):
                    elements.append(Paragraph(f"{indent_space}&nbsp;&nbsp;- <i>Item {i}:</i>", content_style))
                    if isinstance(item, dict):
                        elements.extend(render_dict(item, indent + 2))
                    else:
                        elements.append(Paragraph(f"{indent_space * 2}{item}", content_style))
            else:
                elements.append(Paragraph(f"{indent_space}<b>{key}:</b> {value}", content_style))
        return elements

    # Render scan data
    for section, findings in scan_data.items():
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(f"📄 {section.replace('_', ' ').title()}", subheader_style))

        if isinstance(findings, dict):
            story.extend(render_dict(findings))
        elif isinstance(findings, list):
            for idx, item in enumerate(findings, start=1):
                story.append(Paragraph(f"<b>Item {idx}</b>", content_style))
                if isinstance(item, dict):
                    story.extend(render_dict(item))
                else:
                    story.append(Paragraph(str(item), content_style))
        else:
            story.append(Paragraph(str(findings), content_style))

        story.append(Spacer(1, 0.2 * inch))

    # Build PDF
    doc.build(story)
    return filename
