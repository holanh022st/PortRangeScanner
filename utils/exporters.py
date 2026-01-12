"""
Export functionality for scan results.

Supports multiple formats:
- CSV
- JSON
- XML
- PDF
- HTML
"""

import json
import csv
from datetime import datetime
from typing import List
from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom

from models.scan_result import ScanResult, ScanSession
from utils.logger import app_logger


class CSVExporter:
    """Export scan results to CSV format."""
    
    @staticmethod
    def export(results: List[ScanResult], file_path: str, session: ScanSession = None) -> bool:
        """
        Export results to CSV file.
        
        Args:
            results: List of scan results
            file_path: Output file path
            session: Optional scan session metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Host', 'Port', 'State', 'Protocol', 'Service', 'Version',
                    'Risk Level', 'Response Time (s)', 'Timestamp', 'Banner', 'Notes'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    writer.writerow({
                        'Host': result.host,
                        'Port': result.port,
                        'State': result.state,
                        'Protocol': result.protocol,
                        'Service': result.service or '',
                        'Version': result.version or '',
                        'Risk Level': result.risk_level,
                        'Response Time (s)': f"{result.response_time:.3f}",
                        'Timestamp': result.timestamp.isoformat(),
                        'Banner': result.banner or '',
                        'Notes': result.notes or '',
                    })
            
            app_logger.info(f"CSV export successful: {file_path}")
            return True
        
        except Exception as e:
            app_logger.error(f"CSV export failed: {e}")
            return False


class JSONExporter:
    """Export scan results to JSON format."""
    
    @staticmethod
    def export(results: List[ScanResult], file_path: str, session: ScanSession = None) -> bool:
        """
        Export results to JSON file.
        
        Args:
            results: List of scan results
            file_path: Output file path
            session: Optional scan session metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            data = {
                "export_time": datetime.now().isoformat(),
                "total_results": len(results),
            }
            
            if session:
                data["session"] = session.to_dict()
            
            data["results"] = [result.to_dict() for result in results]
            
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, ensure_ascii=False)
            
            app_logger.info(f"JSON export successful: {file_path}")
            return True
        
        except Exception as e:
            app_logger.error(f"JSON export failed: {e}")
            return False


class XMLExporter:
    """Export scan results to XML format."""
    
    @staticmethod
    def export(results: List[ScanResult], file_path: str, session: ScanSession = None) -> bool:
        """
        Export results to XML file (NIST-compatible format).
        
        Args:
            results: List of scan results
            file_path: Output file path
            session: Optional scan session metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            root = ET.Element('scan_report')
            root.set('version', '1.0')
            root.set('export_time', datetime.now().isoformat())
            
            # Metadata
            metadata = ET.SubElement(root, 'metadata')
            if session:
                ET.SubElement(metadata, 'scan_name').text = session.name
                ET.SubElement(metadata, 'user').text = session.user
                ET.SubElement(metadata, 'start_time').text = session.start_time.isoformat()
                if session.end_time:
                    ET.SubElement(metadata, 'end_time').text = session.end_time.isoformat()
                ET.SubElement(metadata, 'justification').text = session.justification
            
            ET.SubElement(metadata, 'total_results').text = str(len(results))
            
            # Results
            results_elem = ET.SubElement(root, 'results')
            
            for result in results:
                result_elem = ET.SubElement(results_elem, 'result')
                
                ET.SubElement(result_elem, 'host').text = result.host
                ET.SubElement(result_elem, 'port').text = str(result.port)
                ET.SubElement(result_elem, 'state').text = result.state
                ET.SubElement(result_elem, 'protocol').text = result.protocol
                
                if result.service:
                    ET.SubElement(result_elem, 'service').text = result.service
                if result.version:
                    ET.SubElement(result_elem, 'version').text = result.version
                
                ET.SubElement(result_elem, 'risk_level').text = result.risk_level
                ET.SubElement(result_elem, 'response_time').text = f"{result.response_time:.3f}"
                ET.SubElement(result_elem, 'timestamp').text = result.timestamp.isoformat()
                
                if result.banner:
                    ET.SubElement(result_elem, 'banner').text = result.banner
                if result.notes:
                    ET.SubElement(result_elem, 'notes').text = result.notes
            
            # Pretty print
            xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
            
            with open(file_path, 'w', encoding='utf-8') as xmlfile:
                xmlfile.write(xml_str)
            
            app_logger.info(f"XML export successful: {file_path}")
            return True
        
        except Exception as e:
            app_logger.error(f"XML export failed: {e}")
            return False


class HTMLExporter:
    """Export scan results to interactive HTML report."""
    
    @staticmethod
    def export(results: List[ScanResult], file_path: str, session: ScanSession = None) -> bool:
        """
        Export results to HTML file.
        
        Args:
            results: List of scan results
            file_path: Output file path
            session: Optional scan session metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            html = HTMLExporter._generate_html(results, session)
            
            with open(file_path, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write(html)
            
            app_logger.info(f"HTML export successful: {file_path}")
            return True
        
        except Exception as e:
            app_logger.error(f"HTML export failed: {e}")
            return False
    
    @staticmethod
    def _generate_html(results: List[ScanResult], session: ScanSession = None) -> str:
        """Generate HTML content."""
        
        # Count results by state
        open_count = sum(1 for r in results if r.state == "Open")
        closed_count = sum(1 for r in results if r.state == "Closed")
        filtered_count = sum(1 for r in results if r.state == "Filtered")
        
        # Count by risk
        critical_count = sum(1 for r in results if r.risk_level == "Critical")
        high_count = sum(1 for r in results if r.risk_level == "High")
        medium_count = sum(1 for r in results if r.risk_level == "Medium")
        low_count = sum(1 for r in results if r.risk_level == "Low")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Port Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            color: white;
        }}
        .stat-box h3 {{
            margin: 0;
            font-size: 32px;
        }}
        .stat-box p {{
            margin: 5px 0 0 0;
            opacity: 0.9;
        }}
        .open {{ background-color: #28a745; }}
        .closed {{ background-color: #dc3545; }}
        .filtered {{ background-color: #ffc107; }}
        .critical {{ background-color: #dc143c; }}
        .high {{ background-color: #ff6347; }}
        .medium {{ background-color: #ffa500; }}
        .low {{ background-color: #32cd32; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #007bff;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .risk-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Port Scanner Report</h1>
        
        <div class="metadata">
            <p><strong>Export Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Results:</strong> {len(results)}</p>
"""
        
        if session:
            html += f"""
            <p><strong>Scan Name:</strong> {session.name}</p>
            <p><strong>User:</strong> {session.user}</p>
            <p><strong>Targets:</strong> {', '.join(session.targets[:5])}{'...' if len(session.targets) > 5 else ''}</p>
            <p><strong>Ports:</strong> {session.ports}</p>
"""
        
        html += f"""
        </div>
        
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box open">
                <h3>{open_count}</h3>
                <p>Open Ports</p>
            </div>
            <div class="stat-box closed">
                <h3>{closed_count}</h3>
                <p>Closed Ports</p>
            </div>
            <div class="stat-box filtered">
                <h3>{filtered_count}</h3>
                <p>Filtered Ports</p>
            </div>
        </div>
        
        <h2>Risk Assessment</h2>
        <div class="stats">
            <div class="stat-box critical">
                <h3>{critical_count}</h3>
                <p>Critical Risk</p>
            </div>
            <div class="stat-box high">
                <h3>{high_count}</h3>
                <p>High Risk</p>
            </div>
            <div class="stat-box medium">
                <h3>{medium_count}</h3>
                <p>Medium Risk</p>
            </div>
            <div class="stat-box low">
                <h3>{low_count}</h3>
                <p>Low Risk</p>
            </div>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>State</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for result in results:
            risk_class = result.risk_level.lower().replace(" ", "-")
            html += f"""
                <tr>
                    <td>{result.host}</td>
                    <td>{result.port}</td>
                    <td>{result.state}</td>
                    <td>{result.protocol}</td>
                    <td>{result.service or '-'}</td>
                    <td>{result.version or '-'}</td>
                    <td><span class="risk-badge {risk_class}">{result.risk_level}</span></td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by Enterprise Port Scanner</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html


class PDFExporter:
    """Export scan results to PDF format (placeholder)."""
    
    @staticmethod
    def export(results: List[ScanResult], file_path: str, session: ScanSession = None) -> bool:
        """
        Export results to PDF file.
        
        Note: This is a simplified implementation. Full PDF generation
        would require reportlab library with charts and formatting.
        
        Args:
            results: List of scan results
            file_path: Output file path
            session: Optional scan session metadata
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title = Paragraph("Port Scanner Report", styles['Title'])
            elements.append(title)
            elements.append(Spacer(1, 12))
            
            # Metadata
            if session:
                meta_text = f"""
                <b>Scan Name:</b> {session.name}<br/>
                <b>User:</b> {session.user}<br/>
                <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
                <b>Total Results:</b> {len(results)}
                """
                meta = Paragraph(meta_text, styles['Normal'])
                elements.append(meta)
                elements.append(Spacer(1, 12))
            
            # Summary table
            data = [['Host', 'Port', 'State', 'Service', 'Risk']]
            for result in results[:50]:  # Limit to first 50 for PDF
                data.append([
                    result.host,
                    str(result.port),
                    result.state,
                    result.service or '-',
                    result.risk_level,
                ])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            elements.append(table)
            
            doc.build(elements)
            
            app_logger.info(f"PDF export successful: {file_path}")
            return True
        
        except ImportError:
            app_logger.error("ReportLab not available for PDF export")
            return False
        except Exception as e:
            app_logger.error(f"PDF export failed: {e}")
            return False
