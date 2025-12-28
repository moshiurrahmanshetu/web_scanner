"""
Flask Web Application - Mini Web Vulnerability Scanner
Main entry point for the web-based scanner
"""



import pdfkit
import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from db_config import DatabaseManager
from scanner.sqli_scanner import SQLIScanner
from scanner.xss_scanner import XSSScanner


PDF_CONFIG = pdfkit.configuration(
    wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
)

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'  # Change this in production

# Initialize database manager
db = DatabaseManager()

# Create necessary directories
os.makedirs('reports', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('templates', exist_ok=True)


def initialize_database():
    """Initialize database connection and tables"""
    try:
        # Create database if it doesn't exist
        if not db.create_database():
            return False
        
        # Connect to database
        if not db.connect():
            return False
        
        # Create tables
        if not db.create_tables():
            return False
        
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False


def perform_scan(target_url):
    """
    Perform vulnerability scan on target URL
    
    Args:
        target_url: URL to scan
        
    Returns:
        dict: Scan results with scan_id and vulnerabilities
    """
    # Validate URL
    if not target_url or not target_url.startswith(('http://', 'https://')):
        return {'error': 'Invalid URL. Must start with http:// or https://'}
    
    # Ensure database connection
    try:
        if not db.connection or not db.connection.is_connected():
            if not db.connect():
                return {'error': 'Failed to connect to database. Please check MySQL is running and credentials are correct.'}
        
        # Verify cursor exists
        if not db.cursor:
            if not db.connect():
                return {'error': 'Failed to establish database cursor. Please check MySQL connection.'}
    except Exception as e:
        return {'error': f'Database connection error: {str(e)}. Please check MySQL is running.'}
    
    try:
        # Initialize scanners
        sqli_scanner = SQLIScanner()
        xss_scanner = XSSScanner()
        
        # Save scan to database
        scan_id = db.save_scan(target_url)
        if not scan_id:
            return {'error': 'Failed to save scan to database. Please check database connection and ensure tables exist.'}
        
        # Run SQL Injection scan
        sqli_vulns = sqli_scanner.scan_url(target_url)
        
        # Run XSS scan
        xss_vulns = xss_scanner.scan_url(target_url)
        
        # Combine vulnerabilities
        all_vulnerabilities = sqli_vulns + xss_vulns
        
        # Save vulnerabilities to database
        for vuln in all_vulnerabilities:
            db.save_vulnerability(
                scan_id,
                vuln['type'],
                vuln.get('parameter', 'N/A'),
                vuln['severity'],
                vuln['payload']
            )
        
        return {
            'scan_id': scan_id,
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': all_vulnerabilities,
            'total_vulnerabilities': len(all_vulnerabilities)
        }
    
    except Exception as e:
        return {'error': f'Scan error: {str(e)}'}


def generate_json_report(scan_result):
    """Generate JSON report"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'reports/scan_report_{timestamp}.json'
    
    report = {
        'scan_id': scan_result['scan_id'],
        'scan_time': scan_result['scan_time'],
        'target_url': scan_result['target_url'],
        'total_vulnerabilities': scan_result['total_vulnerabilities'],
        'vulnerabilities': scan_result['vulnerabilities']
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    return filename


def generate_html_report(scan_result):
    """Generate HTML report"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'reports/scan_report_{timestamp}.html'
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Scan Report - {scan_result['scan_id']}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
            .vuln-card {{ margin-bottom: 20px; border-left: 4px solid; }}
            .severity-high {{ border-left-color: #dc3545; }}
            .severity-medium {{ border-left-color: #ffc107; }}
            .severity-low {{ border-left-color: #28a745; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Web Vulnerability Scan Report</h1>
                <p class="mb-0">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="card mb-4">
                <div class="card-header bg-primary text-white">
                    <h3>Scan Information</h3>
                </div>
                <div class="card-body">
                    <p><strong>Scan ID:</strong> {scan_result['scan_id']}</p>
                    <p><strong>Target URL:</strong> {scan_result['target_url']}</p>
                    <p><strong>Scan Time:</strong> {datetime.fromisoformat(scan_result['scan_time']).strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Total Vulnerabilities:</strong> {scan_result['total_vulnerabilities']}</p>
                </div>
            </div>
            
            <h2>Detected Vulnerabilities</h2>
    """
    
    if scan_result['vulnerabilities']:
        for i, vuln in enumerate(scan_result['vulnerabilities'], 1):
            severity_class = f"severity-{vuln['severity'].lower()}"
            badge_color = {
                'HIGH': 'danger',
                'MEDIUM': 'warning',
                'LOW': 'success'
            }.get(vuln['severity'], 'secondary')
            
            html_content += f"""
            <div class="card vuln-card {severity_class}">
                <div class="card-body">
                    <h4>Vulnerability #{i}: {vuln['type']}</h4>
                    <p><strong>Severity:</strong> <span class="badge bg-{badge_color}">{vuln['severity']}</span></p>
                    <p><strong>Parameter:</strong> {vuln.get('parameter', 'N/A')}</p>
                    <p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>
                    {f"<p><strong>Test URL:</strong> <a href='{vuln.get('url', '#')}' target='_blank'>{vuln.get('url', 'N/A')[:100]}</a></p>" if 'url' in vuln else ''}
                </div>
            </div>
            """
    else:
        html_content += """
            <div class="alert alert-success">
                <h4>No Vulnerabilities Detected</h4>
                <p>The target URL appears to be secure against the tested attacks.</p>
            </div>
        """
    
    html_content += """
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename


@app.route('/')
def index():
    """Home/Dashboard page"""
    try:
        # Get recent scans for dashboard
        if not db.connection or not db.connection.is_connected():
            if not db.connect():
                recent_scans = []
            else:
                recent_scans = db.get_scan_history(limit=5)
        else:
            recent_scans = db.get_scan_history(limit=5)
    except Exception as e:
        print(f"Error getting scan history: {e}")
        recent_scans = []
    
    return render_template('index.html', recent_scans=recent_scans)


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan page - form to input URL and start scan"""
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        
        if not target_url:
            flash('Please enter a target URL', 'error')
            return redirect(url_for('scan'))
        
        # Perform scan
        scan_result = perform_scan(target_url)
        
        if 'error' in scan_result:
            flash(scan_result['error'], 'error')
            return redirect(url_for('scan'))
        
        # Redirect to results page
        return redirect(url_for('results', scan_id=scan_result['scan_id']))
    
    return render_template('scan.html')


@app.route('/results/<int:scan_id>')
def results(scan_id):
    """Results page showing scan results"""
    try:
        if not db.connect():
            flash('Database connection error', 'error')
            return redirect(url_for('index'))
        
        # Get scan details
        db.cursor.execute("SELECT scan_id, target_url, scan_time FROM scans WHERE scan_id = %s", (scan_id,))
        scan_data = db.cursor.fetchone()
        
        if not scan_data:
            flash('Scan not found', 'error')
            if db.connection and db.connection.is_connected():
                db.disconnect()
            return redirect(url_for('index'))
        
        scan_id_db, target_url, scan_time = scan_data
        
        # Get vulnerabilities
        db.cursor.execute("""
            SELECT vuln_type, parameter, severity, payload 
            FROM vulnerabilities 
            WHERE scan_id = %s
            ORDER BY 
                CASE severity 
                    WHEN 'HIGH' THEN 1 
                    WHEN 'MEDIUM' THEN 2 
                    WHEN 'LOW' THEN 3 
                END
        """, (scan_id,))
        
        vulnerabilities_data = db.cursor.fetchall()
        
        vulnerabilities = []
        for vuln_data in vulnerabilities_data:
            vuln_type, parameter, severity, payload = vuln_data
            vulnerabilities.append({
                'type': vuln_type,
                'parameter': parameter,
                'severity': severity,
                'payload': payload
            })
        
        # Don't disconnect - keep connection for potential reuse
        
        # Handle datetime conversion
        if isinstance(scan_time, datetime):
            scan_time_str = scan_time.isoformat()
        elif hasattr(scan_time, 'isoformat'):
            scan_time_str = scan_time.isoformat()
        else:
            scan_time_str = str(scan_time)
        
        # Prepare result data
        scan_result = {
            'scan_id': scan_id_db,
            'target_url': target_url,
            'scan_time': scan_time_str,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }
        
        # Calculate severity breakdown
        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
        medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM')
        low_count = sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        
        return render_template('results.html', 
                             scan_result=scan_result,
                             high_count=high_count,
                             medium_count=medium_count,
                             low_count=low_count)
    
    except Exception as e:
        flash(f'Error retrieving results: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/history')
def history():
    """Scan history page"""
    try:
        if not db.connect():
            flash('Database connection error', 'error')
            return redirect(url_for('index'))
        
        # Get all scans
        db.cursor.execute("""
            SELECT scan_id, target_url, scan_time,
                   (SELECT COUNT(*) FROM vulnerabilities WHERE vulnerabilities.scan_id = scans.scan_id) as vuln_count
            FROM scans 
            ORDER BY scan_time DESC
        """)
        
        scans = db.cursor.fetchall()
        # Don't disconnect - keep connection for potential reuse
        
        scan_list = []
        for scan in scans:
            scan_id, target_url, scan_time, vuln_count = scan
            scan_list.append({
                'scan_id': scan_id,
                'target_url': target_url,
                'scan_time': scan_time,
                'vuln_count': vuln_count
            })
        
        return render_template('history.html', scans=scan_list)
    
    except Exception as e:
        flash(f'Error retrieving history: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/download_report/<int:scan_id>/<format_type>')
def download_report(scan_id, format_type):
    """Download scan report in JSON or HTML format"""
    try:
        # Ensure database connection
        if not db.connection or not db.connection.is_connected():
            if not db.connect():
                flash('Database connection error', 'error')
                return redirect(url_for('index'))
        
        # Get scan details
        db.cursor.execute("SELECT scan_id, target_url, scan_time FROM scans WHERE scan_id = %s", (scan_id,))
        scan_data = db.cursor.fetchone()
        
        if not scan_data:
            flash('Scan not found', 'error')
            db.disconnect()
            return redirect(url_for('index'))
        
        scan_id_db, target_url, scan_time = scan_data
        
        # Get vulnerabilities
        db.cursor.execute("""
            SELECT vuln_type, parameter, severity, payload 
            FROM vulnerabilities 
            WHERE scan_id = %s
        """, (scan_id,))
        
        vulnerabilities_data = db.cursor.fetchall()
        
        vulnerabilities = []
        for vuln_data in vulnerabilities_data:
            vuln_type, parameter, severity, payload = vuln_data
            vulnerabilities.append({
                'type': vuln_type,
                'parameter': parameter,
                'severity': severity,
                'payload': payload
            })
        
        db.disconnect()
        
        # Handle datetime conversion
        if isinstance(scan_time, datetime):
            scan_time_str = scan_time.isoformat()
        elif hasattr(scan_time, 'isoformat'):
            scan_time_str = scan_time.isoformat()
        else:
            scan_time_str = str(scan_time)
        
        # Prepare result data
        scan_result = {
            'scan_id': scan_id_db,
            'target_url': target_url,
            'scan_time': scan_time_str,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }
        
        if format_type == 'json':
            filename = generate_json_report(scan_result)
            return send_file(filename, as_attachment=True, download_name=f'scan_report_{scan_id}.json')
        
        elif format_type == 'html':
            filename = generate_html_report(scan_result)
            return send_file(filename, as_attachment=True, download_name=f'scan_report_{scan_id}.html')
        
        # PDF
        elif format_type == "pdf":
            pdfkit.from_file(
                html_path,
                pdf_path,
                configuration=PDF_CONFIG
            )
            return send_file(pdf_path, as_attachment=True)
        
        else:
            flash('Invalid format type', 'error')
            return redirect(url_for('results', scan_id=scan_id))
    
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('results', scan_id=scan_id))


if __name__ == '__main__':
    # Initialize database on startup
    if initialize_database():
        print("Database initialized successfully")
    else:
        print("Warning: Database initialization failed. Please check your MySQL connection.")
    
    # Run Flask app
    app.run(debug=True, host='127.0.0.1', port=5000)

