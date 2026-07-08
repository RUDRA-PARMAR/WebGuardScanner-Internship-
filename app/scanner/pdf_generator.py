import datetime
import io
import html
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total page counts and draw
    professional headers and footers on all pages (suppressing headers on page 1).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        self.saveState()
        
        # Primary colors
        primary_color = colors.HexColor('#1A237E') # Navy Blue
        gray_text = colors.HexColor('#666666')
        border_color = colors.HexColor('#E0E0E0')
        
        # Suppress header on page 1
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(primary_color)
            self.drawString(54, self._pagesize[1] - 40, "WEBGUARD AUTOMATED SECURITY SCAN REPORT")
            self.setFont("Helvetica", 8)
            self.setFillColor(gray_text)
            self.drawRightString(self._pagesize[0] - 54, self._pagesize[1] - 40, f"Target: {self.get_scan_url()}")
            self.setStrokeColor(border_color)
            self.setLineWidth(0.5)
            self.line(54, self._pagesize[1] - 45, self._pagesize[0] - 54, self._pagesize[1] - 45)

        # Footer on all pages
        self.setStrokeColor(border_color)
        self.setLineWidth(0.5)
        self.line(54, 50, self._pagesize[0] - 54, 50)
        
        self.setFont("Helvetica", 8)
        self.setFillColor(gray_text)
        self.drawString(54, 35, "CONFIDENTIAL - INTERNAL SECURITY REPORT")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(self._pagesize[0] - 54, 35, page_text)
        
        self.restoreState()

    def get_scan_url(self):
        # Retrieve target URL stored dynamically on the canvas if present
        return getattr(self, 'scan_url', 'WebGuard')


def get_severity_color(severity):
    severity = severity.lower()
    if severity == "critical":
        return colors.HexColor("#D32F2F") # Deep Red
    elif severity == "high":
        return colors.HexColor("#E65100") # Dark Orange
    elif severity == "medium":
        return colors.HexColor("#FBC02D") # Yellow/Gold
    elif severity == "low":
        return colors.HexColor("#1976D2") # Blue
    elif severity == "info":
        return colors.HexColor("#388E3C") # Green
    else:
        return colors.HexColor("#757575") # Gray


def get_risk_rating_badge_style(rating):
    rating = rating.lower()
    if rating == "critical":
        return "#D32F2F", "#FFEBEE"
    elif rating == "high":
        return "#E65100", "#FFF3E0"
    elif rating == "medium":
        return "#FBC02D", "#FFFDE7"
    elif rating == "low":
        return "#1976D2", "#E3F2FD"
    elif rating == "safe":
        return "#388E3C", "#E8F5E9"
    else:
        return "#757575", "#F5F5F5"


def generate_pdf_report(report):
    """
    Generates a structured, beautiful PDF report from the unified scan report dictionary.
    Returns:
        bytes: The generated PDF binary data.
    """
    buffer = io.BytesIO()
    
    # Page dimensions and document template setup
    # Margins: Left=0.75in, Right=0.75in, Top=0.75in, Bottom=0.75in
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    # Inject target URL into NumberedCanvas to make it dynamic in the running header
    def make_canvas(*args, **kwargs):
        canvas_obj = NumberedCanvas(*args, **kwargs)
        canvas_obj.scan_url = report.get("url", "WebGuard")
        return canvas_obj

    # Theme and Styles configuration
    styles = getSampleStyleSheet()
    
    primary_color = colors.HexColor("#1A237E") # Navy
    text_color = colors.HexColor("#212121")
    light_bg = colors.HexColor("#F5F5F5")
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=primary_color,
        alignment=0, # Left-aligned
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#666666"),
        spaceAfter=20
    )
    
    section_title_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=text_color,
        spaceAfter=8
    )

    finding_title_style = ParagraphStyle(
        'FindingTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=primary_color
    )

    finding_text_style = ParagraphStyle(
        'FindingText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=text_color
    )

    finding_heading_style = ParagraphStyle(
        'FindingHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#424242")
    )
    
    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0D47A1")
    )
    
    story = []
    
    # -------------------------------------------------------------------------
    # 1. Header & Title Block
    # -------------------------------------------------------------------------
    story.append(Paragraph("WebGuard Security Scan Report", title_style))
    scan_time_str = report.get("timestamp", datetime.datetime.now().isoformat())
    try:
        dt = datetime.datetime.fromisoformat(scan_time_str)
        formatted_date = dt.strftime("%B %d, %Y at %I:%M %p")
    except Exception:
        formatted_date = scan_time_str
        
    story.append(Paragraph(f"Automated Website Vulnerability & Configuration Assessment &bull; Scanned on {formatted_date}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # -------------------------------------------------------------------------
    # 2. Executive Summary Metrics Table
    # -------------------------------------------------------------------------
    rating = report.get("risk_rating", "Safe")
    text_color_badge, bg_color_badge = get_risk_rating_badge_style(rating)
    
    summary_data = [
        [
            Paragraph("<b>Target URL:</b>", body_style),
            Paragraph(f"<font color='#0D47A1'><b>{html.escape(report.get('url', ''))}</b></font>", body_style)
        ],
        [
            Paragraph("<b>Risk Rating:</b>", body_style),
            Paragraph(f"<b><font color='{text_color_badge}'>{rating.upper()}</font></b>", body_style)
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5*inch, 5.0*inch])
    summary_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BACKGROUND', (0,0), (-1,-1), light_bg),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#E0E0E0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#EEEEEE')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # -------------------------------------------------------------------------
    # 3. Severity Distribution Table
    # -------------------------------------------------------------------------
    counts = report.get("severity_counts", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    
    dist_headers = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL FINDINGS"]
    dist_values = [
        str(counts.get("critical", 0)),
        str(counts.get("high", 0)),
        str(counts.get("medium", 0)),
        str(counts.get("low", 0)),
        str(counts.get("info", 0)),
        str(report.get("total_findings", 0))
    ]
    
    dist_data = [
        [Paragraph(f"<font color='white'><b>{h}</b></font>", body_style) for h in dist_headers],
        [Paragraph(f"<b>{v}</b>", body_style) for v in dist_values]
    ]
    
    dist_table = Table(dist_data, colWidths=[1.08*inch, 1.08*inch, 1.08*inch, 1.08*inch, 1.08*inch, 1.1*inch])
    dist_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BACKGROUND', (0,0), (0,0), get_severity_color("critical")),
        ('BACKGROUND', (1,0), (1,0), get_severity_color("high")),
        ('BACKGROUND', (2,0), (2,0), get_severity_color("medium")),
        ('BACKGROUND', (3,0), (3,0), get_severity_color("low")),
        ('BACKGROUND', (4,0), (4,0), get_severity_color("info")),
        ('BOX', (0,0), (-1,-1), 1, primary_color),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BDBDBD')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(dist_table)
    story.append(Spacer(1, 15))

    # -------------------------------------------------------------------------
    # 4. Target Host and Environment Details
    # -------------------------------------------------------------------------
    story.append(Paragraph("Target Infrastructure Details", section_title_style))
    target_details = report.get("target_details", {})
    dns_info = target_details.get("dns", {})
    reach_info = target_details.get("reachability", {})
    trans_info = target_details.get("transport_security", {})
    
    details_rows = [
        [Paragraph("<b>DNS Status</b>", body_style), Paragraph("Resolved successfully" if dns_info.get("resolved") else "DNS Resolution Failed", body_style)],
        [Paragraph("<b>IP Address</b>", body_style), Paragraph(dns_info.get("ip_address", "N/A"), body_style)],
        [Paragraph("<b>HTTP Status Code</b>", body_style), Paragraph(str(reach_info.get("status_code", "N/A")), body_style)],
        [Paragraph("<b>Server Header</b>", body_style), Paragraph(html.escape(reach_info.get("server", "Not disclosed")), body_style)],
        [Paragraph("<b>HTTPS Scheme</b>", body_style), Paragraph("Yes" if trans_info.get("is_https") else "No", body_style)],
    ]
    
    ssl_tls = report.get("ssl_tls")
    if ssl_tls:
        details_rows.extend([
            [Paragraph("<b>TLS Version</b>", body_style), Paragraph(ssl_tls.get("version") or "N/A", body_style)],
            [Paragraph("<b>Cipher Suite</b>", body_style), Paragraph(ssl_tls.get("cipher_suite") or "N/A", body_style)],
            [Paragraph("<b>Certificate Expiry</b>", body_style), Paragraph(f"{ssl_tls.get('days_remaining')} days remaining" if ssl_tls.get('days_remaining') is not None else "N/A", body_style)],
            [Paragraph("<b>Self-Signed Certificate</b>", body_style), Paragraph("Yes" if ssl_tls.get("self_signed") else "No", body_style)]
        ])
        
    details_table = Table(details_rows, colWidths=[2.2*inch, 4.3*inch])
    details_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#EEEEEE')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#BDBDBD')),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 20))

    # -------------------------------------------------------------------------
    # 5. Detailed Findings & Recommendations
    # -------------------------------------------------------------------------
    story.append(Paragraph("Security Assessment Findings & Vulnerabilities", section_title_style))
    
    findings = report.get("findings", [])
    if not findings:
        story.append(Paragraph("<b>No security issues were identified during this assessment.</b>", body_style))
        story.append(Paragraph("The target website adheres to security best practices for checked configurations.", body_style))
    else:
        # Sort findings: Critical -> High -> Medium -> Low -> Info
        sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: sev_priority.get(x.get("severity", "info").lower(), 5))
        
        for idx, f in enumerate(sorted_findings):
            f_severity = f.get("severity", "Info")
            sev_color = get_severity_color(f_severity)
            
            # Sub-table card layout for each finding to avoid separation across pages
            finding_content = [
                [
                    Paragraph(f"<b>{idx + 1}. {html.escape(f.get('check', ''))}</b>", finding_title_style),
                    Paragraph(f"<font color='white'><b>{f_severity.upper()}</b></font>", ParagraphStyle('Badge', parent=body_style, alignment=2)) # Right aligned
                ],
                [
                    Paragraph("<b>Vulnerability Description:</b>", finding_heading_style),
                    Paragraph(html.escape(f.get("description") or "No description provided."), finding_text_style)
                ]
            ]
            
            # Recommendation (if available)
            rec = f.get("recommendation")
            if rec:
                finding_content.append([
                    Paragraph("<b>Remediation Recommendation:</b>", finding_heading_style),
                    Paragraph(html.escape(rec), finding_text_style)
                ])
                
            # Details or code blocks (if available in finding)
            if "details" in f and f["details"]:
                det_text = str(f["details"])
                finding_content.append([
                    Paragraph("<b>Technical Details:</b>", finding_heading_style),
                    Paragraph(html.escape(det_text), code_style)
                ])
                
            finding_table = Table(finding_content, colWidths=[2.2*inch, 4.3*inch])
            finding_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('SPAN', (0,0), (0,0)), # Check name span
                # Span finding header row entirely across
                ('SPAN', (0,0), (1,0)),
                # Span all subsequent body rows
                ('SPAN', (1,1), (-1,1)),
                ('SPAN', (1,2), (-1,2)) if len(finding_content) > 2 else ('VALIGN', (0,0), (0,0), 'TOP'),
                ('SPAN', (1,3), (-1,3)) if len(finding_content) > 3 else ('VALIGN', (0,0), (0,0), 'TOP'),
                
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ECEFF1')),
                ('LINELEFT', (0,0), (0,-1), 4, sev_color), # Colored vertical border on the left
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CFD8DC')),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            
            # Wrap in KeepTogether to ensure it doesn't break awkwardly
            story.append(KeepTogether([finding_table, Spacer(1, 10)]))
            
    # Build Document
    doc.build(story, canvasmaker=make_canvas)
    
    # Return binary contents
    pdf_data = buffer.getvalue()
    buffer.close()
    return pdf_data
