# Quick Start Guide

## Prerequisites Checklist

- [ ] Python 3.7+ installed
- [ ] MySQL/XAMPP installed and running
- [ ] MySQL service started in XAMPP

## Installation Steps

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup MySQL Database

**Option A: Using phpMyAdmin**
1. Open http://localhost/phpmyadmin
2. Click "SQL" tab
3. Copy-paste contents of `database_setup.sql`
4. Click "Go"

**Option B: Using Command Line**
```bash
mysql -u root -p < database_setup.sql
```

### 3. Configure Database (if needed)

Edit `db_config.py` line 12 if you have a MySQL password:
```python
def __init__(self, host='localhost', user='root', password='YOUR_PASSWORD', database='web_scanner_db'):
```

### 4. Run the Scanner
```bash
python web_vuln_scanner.py
```

## Testing the Scanner

### Test on Local Vulnerable Web App

**Recommended:** Use DVWA (Damn Vulnerable Web Application)

1. Download DVWA: https://github.com/digininja/DVWA
2. Install in XAMPP htdocs folder
3. Access: http://localhost/dvwa
4. Scan URL: `http://localhost/dvwa/vulnerabilities/sqli/?id=1`

### Example Test URLs

- `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
- `http://localhost/dvwa/vulnerabilities/xss_r/?name=test`
- `http://localhost/test.php?id=1&name=admin`

## Common Issues

**"Error connecting to MySQL"**
- Ensure MySQL is running in XAMPP
- Check password in `db_config.py`
- Verify database exists

**"ModuleNotFoundError"**
- Run: `pip install -r requirements.txt`

**"No vulnerabilities detected"**
- Ensure URL has query parameters (e.g., `?id=1`)
- Test on a vulnerable application (DVWA recommended)

## Project Structure

```
mini_web_scanner/
├── web_vuln_scanner.py    # Main file - RUN THIS
├── db_config.py           # Database settings
├── payloads.py            # Attack payloads
├── scanner/               # Scanner modules
│   ├── sqli_scanner.py
│   └── xss_scanner.py
├── reports/              # Generated reports (auto-created)
└── logs/                 # Logs (auto-created)
```

## Important Notes

⚠️ **ETHICAL USE ONLY**
- Only scan websites you own or have permission to test
- Use local test environments (DVWA, WebGoat)
- Unauthorized scanning is illegal

## Need Help?

1. Check `README.md` for detailed documentation
2. Verify all prerequisites are installed
3. Check MySQL connection settings
4. Ensure target URL has query parameters

