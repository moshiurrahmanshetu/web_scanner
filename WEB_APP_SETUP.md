# Web Application Setup Guide

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup Database
- Start MySQL/XAMPP
- Run `database_setup.sql` in phpMyAdmin or MySQL command line

### 3. Configure Database (if needed)
Edit `db_config.py` if you have a MySQL password:
```python
def __init__(self, host='localhost', user='root', password='YOUR_PASSWORD', database='web_scanner_db'):
```

### 4. Run the Application
```bash
python app.py
```

### 5. Access the Web Interface
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

## Project Structure

```
mini_web_scanner/
├── app.py                 # Flask application (RUN THIS)
├── db_config.py          # Database configuration
├── payloads.py            # Attack payloads
├── scanner/              # Scanner modules
│   ├── sqli_scanner.py
│   └── xss_scanner.py
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── scan.html
│   ├── results.html
│   └── history.html
├── static/               # CSS/JS files
│   └── style.css
└── reports/             # Generated reports
```

## Features

- ✅ Web-based interface (Flask + Bootstrap 5)
- ✅ SQL Injection detection
- ✅ XSS detection
- ✅ MySQL database integration
- ✅ Downloadable reports (JSON & HTML)
- ✅ Scan history
- ✅ Responsive design

## Troubleshooting

**Port already in use?**
Change port in `app.py`:
```python
app.run(debug=True, host='127.0.0.1', port=5001)
```

**Database connection error?**
- Check MySQL is running
- Verify credentials in `db_config.py`
- Ensure database exists

**Module not found?**
```bash
pip install -r requirements.txt
```

## Ethical Use

⚠️ **ONLY scan websites you own or have permission to test!**

