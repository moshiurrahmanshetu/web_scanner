# Mini Web Vulnerability Scanner & Attack Detector (Web Application)

A comprehensive **web-based** Python application that detects SQL Injection and Cross-Site Scripting (XSS) vulnerabilities in web applications. Built with Flask and Bootstrap 5, featuring a modern, user-friendly interface.

## 🌟 Features

- **Web-Based Interface**: Modern, responsive UI built with Flask and Bootstrap 5
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities using error-based detection
- **XSS Detection**: Identifies reflected Cross-Site Scripting vulnerabilities
- **Severity Classification**: Categorizes vulnerabilities as HIGH, MEDIUM, or LOW
- **MySQL Integration**: Stores scan history and results in MySQL database
- **Report Generation**: Downloadable reports in JSON and HTML formats
- **Scan History**: View and manage all previous scans
- **Real-time Results**: Instant display of scan results with detailed information

## 📁 Project Structure

```
mini_web_scanner/
│
├── app.py                    # Flask application (main entry point)
├── db_config.py              # MySQL database configuration
├── payloads.py               # SQLi & XSS payloads
├── requirements.txt          # Python dependencies
├── database_setup.sql        # Database setup script
├── README.md                 # This file
│
├── scanner/
│   ├── __init__.py
│   ├── sqli_scanner.py      # SQL Injection scanner
│   └── xss_scanner.py       # XSS scanner
│
├── templates/                # HTML templates
│   ├── base.html            # Base template
│   ├── index.html           # Home/Dashboard page
│   ├── scan.html            # Scan form page
│   ├── results.html         # Results display page
│   └── history.html         # Scan history page
│
├── static/                   # Static files (CSS, JS)
│   └── style.css            # Custom styles
│
├── reports/                  # Generated scan reports (auto-created)
└── logs/                     # Scan logs (auto-created)
```

## 🚀 Prerequisites

1. **Python 3.7 or higher**
   - Download from: https://www.python.org/downloads/
   - Verify installation: `python --version`

2. **MySQL Server (XAMPP recommended)**
   - Download XAMPP from: https://www.apachefriends.org/
   - Install and start MySQL service

3. **pip** (Python package manager)
   - Usually comes with Python installation

## 📦 Installation & Setup

### Step 1: Install Python Dependencies

Open terminal/command prompt in the project directory and run:

```bash
pip install -r requirements.txt
```

This will install:
- `Flask` (Web framework)
- `mysql-connector-python` (MySQL database connector)
- `requests` (HTTP library for web requests)

### Step 2: Setup MySQL Database

#### Option A: Using phpMyAdmin (XAMPP)

1. Start XAMPP and ensure MySQL is running
2. Open phpMyAdmin: http://localhost/phpmyadmin
3. Click on "SQL" tab
4. Copy and paste the contents of `database_setup.sql`
5. Click "Go" to execute

#### Option B: Using MySQL Command Line

```bash
mysql -u root -p < database_setup.sql
```

(Enter your MySQL password when prompted)

#### Option C: Manual Setup

1. Create database:
   ```sql
   CREATE DATABASE web_scanner_db;
   ```

2. Create tables (run in MySQL):
   ```sql
   USE web_scanner_db;
   
   CREATE TABLE scans (
       scan_id INT AUTO_INCREMENT PRIMARY KEY,
       target_url VARCHAR(500) NOT NULL,
       scan_time DATETIME NOT NULL
   );
   
   CREATE TABLE vulnerabilities (
       vuln_id INT AUTO_INCREMENT PRIMARY KEY,
       scan_id INT NOT NULL,
       vuln_type VARCHAR(50) NOT NULL,
       parameter VARCHAR(200),
       severity VARCHAR(20) NOT NULL,
       payload TEXT,
       FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
   );
   ```

### Step 3: Configure Database Connection

Edit `db_config.py` if your MySQL credentials are different:

```python
def __init__(self, host='localhost', user='root', password='', database='web_scanner_db'):
```

**Default settings (XAMPP):**
- Host: `localhost`
- User: `root`
- Password: `` (empty)
- Database: `web_scanner_db`

If you have a password, change it:
```python
def __init__(self, host='localhost', user='root', password='your_password', database='web_scanner_db'):
```

## 🎯 How to Run

1. **Navigate to project directory:**
   ```bash
   cd mini_web_scanner
   ```

2. **Run the Flask application:**
   ```bash
   python app.py
   ```

3. **Open your web browser:**
   - Navigate to: http://127.0.0.1:5000
   - The web interface will be available

4. **Start scanning:**
   - Click "Start New Scan" or go to the Scan page
   - Enter target URL with query parameters
   - Click "Start Scan"
   - View results and download reports

## 📖 Usage Guide

### Starting a Scan

1. Navigate to the **Scan** page
2. Enter a target URL (must include query parameters)
   - Example: `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
3. Click **"Start Scan"**
4. Wait for the scan to complete (may take a few moments)
5. View detailed results on the results page

### Viewing Results

- **Scan Information**: Shows scan ID, target URL, scan time, and total vulnerabilities
- **Severity Breakdown**: Visual breakdown of HIGH, MEDIUM, and LOW severity vulnerabilities
- **Vulnerability Details**: 
  - Vulnerability type (SQL Injection / XSS)
  - Parameter name
  - Payload used
  - Severity level
- **Download Reports**: Get JSON or HTML formatted reports

### Scan History

- View all previous scans
- Access results from any previous scan
- Download reports for any scan
- See vulnerability counts for each scan

## 🧪 Testing the Scanner

### Recommended Test Environment

**DVWA (Damn Vulnerable Web Application)**

1. Download DVWA: https://github.com/digininja/DVWA
2. Install in XAMPP htdocs folder
3. Access: http://localhost/dvwa
4. Scan URLs:
   - SQL Injection: `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
   - XSS: `http://localhost/dvwa/vulnerabilities/xss_r/?name=test`

### Example Test URLs

- `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
- `http://localhost/dvwa/vulnerabilities/xss_r/?name=test`
- `http://localhost/test.php?id=1&name=admin`

## 🔒 Ethical Use & Disclaimer

⚠️ **IMPORTANT: This tool is for EDUCATIONAL and ETHICAL purposes ONLY.**

- **DO NOT** scan websites without explicit permission
- **ONLY** test on:
  - Your own websites
  - Local test environments (e.g., DVWA, WebGoat)
  - Authorized penetration testing targets
- Unauthorized scanning of websites is **ILLEGAL** and may result in criminal prosecution
- The authors are not responsible for misuse of this tool

## 🐛 Troubleshooting

### Database Connection Error

**Problem:** "Database connection error"

**Solutions:**
1. Ensure MySQL/XAMPP is running
2. Check database credentials in `db_config.py`
3. Verify database `web_scanner_db` exists
4. Check MySQL port (default: 3306)

### Module Not Found Error

**Problem:** "ModuleNotFoundError: No module named 'flask'"

**Solution:**
```bash
pip install -r requirements.txt
```

### Port Already in Use

**Problem:** "Address already in use"

**Solution:**
- Change port in `app.py`:
  ```python
  app.run(debug=True, host='127.0.0.1', port=5001)  # Use different port
  ```

### No Vulnerabilities Detected

**Possible reasons:**
- Target website is properly secured
- URL has no query parameters to test
- Website uses different parameter structure
- Payloads need to be customized for specific application

### Flask App Not Starting

**Check:**
1. Python version: `python --version` (should be 3.7+)
2. All dependencies installed: `pip list`
3. Database connection working
4. No syntax errors in code

## 📊 Web Application Features

### Pages

1. **Home/Dashboard** (`/`)
   - Welcome page with feature overview
   - Recent scans display
   - Quick access to start new scan

2. **Scan Page** (`/scan`)
   - URL input form
   - Scan initiation
   - Tips and guidelines

3. **Results Page** (`/results/<scan_id>`)
   - Detailed scan results
   - Vulnerability listing
   - Report downloads
   - Severity breakdown

4. **History Page** (`/history`)
   - Complete scan history
   - Quick access to results
   - Report downloads

### Report Formats

- **JSON Report**: Structured data for programmatic processing
- **HTML Report**: Formatted, printable report with styling

## 🔧 Technical Details

### SQL Injection Detection
- Tests 20+ SQL injection payloads
- Checks for SQL error patterns in responses
- Tests both GET and POST methods
- Detects error-based SQL injection

### XSS Detection
- Tests 15+ XSS payloads
- Checks for payload reflection in responses
- Determines severity based on encoding/context
- Detects reflected XSS vulnerabilities

### Severity Levels
- **HIGH**: Critical vulnerabilities that can lead to data breach or system compromise
- **MEDIUM**: Significant vulnerabilities that require attention
- **LOW**: Minor issues that may have limited impact

## 📝 API Endpoints

- `GET /` - Home/Dashboard page
- `GET /scan` - Scan form page
- `POST /scan` - Submit scan request
- `GET /results/<scan_id>` - View scan results
- `GET /history` - View scan history
- `GET /download_report/<scan_id>/<format>` - Download report (json/html)

## 🎨 UI Features

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Bootstrap 5**: Modern, professional styling
- **Color-coded Severity**: Visual indicators for vulnerability severity
- **Real-time Feedback**: Loading states and progress indicators
- **Flash Messages**: User-friendly error and success notifications

## 🔄 Migration from CLI Version

If you were using the CLI version (`web_vuln_scanner.py`):

1. The scanning logic remains the same
2. All database tables are compatible
3. Existing scan data will be visible in the web interface
4. Simply run `app.py` instead of `web_vuln_scanner.py`

## 📚 Additional Resources

- Flask Documentation: https://flask.palletsprojects.com/
- Bootstrap 5 Documentation: https://getbootstrap.com/docs/5.3/
- MySQL Documentation: https://dev.mysql.com/doc/
- DVWA: https://github.com/digininja/DVWA

## 📄 License

This project is for educational purposes only. Use responsibly and ethically.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all prerequisites are installed
3. Ensure database is properly configured
4. Review error messages for specific issues
5. Check Flask console output for detailed errors

---

**Remember: Always use this tool ethically and with proper authorization!**

**Access the web application at: http://127.0.0.1:5000**
