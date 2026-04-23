import csv
import os
from datetime import datetime
from typing import List


def _default_path(ext: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(os.path.expanduser("~"), "Desktop", f"netguard_{ts}.{ext}")


def export_csv(devices, filepath: str = None) -> str:
    filepath = filepath or _default_path("csv")
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP", "MAC", "Hostname", "Vendor", "Open Ports",
                    "RTSP", "Is Camera", "Risk Level", "Risk Score",
                    "Rep Score", "Whitelisted", "Risk Reasons"])
        for d in devices:
            reasons = "; ".join(getattr(d, "risk_reasons", []))
            w.writerow([
                d.ip, d.mac, d.hostname, d.vendor,
                ",".join(map(str, d.open_ports)),
                d.rtsp_status, d.is_camera, d.risk_level,
                d.risk_score, d.rep_score, d.is_whitelisted,
                reasons,
            ])
    return filepath


def export_pdf(devices, alerts=None, filepath: str = None) -> str:
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    )

    filepath = filepath or _default_path("pdf")
    doc = SimpleDocTemplate(filepath, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "ng_title", parent=styles["Title"],
        textColor=colors.HexColor("#0a3d62"), fontSize=20
    )
    story.append(Paragraph("NetGuard — Network Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.25 * inch))

    # Summary
    danger = sum(1 for d in devices if d.risk_level == "DANGER")
    suspicious = sum(1 for d in devices if d.risk_level == "SUSPICIOUS")
    cameras = sum(1 for d in devices if d.is_camera)
    summary = Table(
        [["Total", "Cameras", "Suspicious", "Danger"],
         [str(len(devices)), str(cameras), str(suspicious), str(danger)]],
        colWidths=[1.8 * inch] * 4,
    )
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a3d62")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
    ]))
    story.append(summary)
    story.append(Spacer(1, 0.25 * inch))

    # Device table
    story.append(Paragraph("Device Details", styles["Heading2"]))
    hdrs = ["IP", "MAC", "Hostname", "Vendor", "Ports", "RTSP", "Risk"]
    rows = [hdrs] + [
        [d.ip, d.mac, d.hostname[:22], d.vendor[:22],
         ",".join(map(str, d.open_ports[:5])),
         "Yes" if d.rtsp_status else "No",
         d.risk_level]
        for d in devices
    ]
    risk_colors_map = {
        "DANGER": colors.red, "SUSPICIOUS": colors.orange, "SAFE": colors.green
    }
    dev_table = Table(
        rows,
        colWidths=[1.1*inch, 1.4*inch, 1.7*inch, 1.7*inch, 1.1*inch, 0.65*inch, 0.95*inch],
    )
    cmd = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a3d62")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]
    for i, d in enumerate(devices, 1):
        c = risk_colors_map.get(d.risk_level, colors.grey)
        cmd += [("TEXTCOLOR", (6, i), (6, i), c),
                ("FONTNAME", (6, i), (6, i), "Helvetica-Bold")]
    dev_table.setStyle(TableStyle(cmd))
    story.append(dev_table)

    # Alerts
    if alerts:
        story.append(Spacer(1, 0.25 * inch))
        story.append(Paragraph("Security Alerts", styles["Heading2"]))
        a_rows = [["Time", "Type", "Description", "Severity"]] + [
            [a.timestamp, a.alert_type, a.description[:55], a.severity]
            for a in alerts
        ]
        a_table = Table(a_rows, colWidths=[0.9*inch, 1.3*inch, 5*inch, 0.9*inch])
        a_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(a_table)

    doc.build(story)
    return filepath
