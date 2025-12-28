"""
Setup Verification Script
Checks if all prerequisites and configurations are correct
"""

import sys
import os


def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} (Need 3.7+)")
        return False


def check_dependencies():
    """Check if required packages are installed"""
    print("\nChecking Python dependencies...")
    required = ['mysql.connector', 'requests']
    all_ok = True
    
    for package in required:
        try:
            if package == 'mysql.connector':
                __import__('mysql.connector')
                print(f"  ✓ {package} (OK)")
            elif package == 'requests':
                __import__('requests')
                print(f"  ✓ {package} (OK)")
        except ImportError:
            print(f"  ✗ {package} (NOT INSTALLED)")
            all_ok = False
    
    if not all_ok:
        print("\n  Install missing packages with: pip install -r requirements.txt")
    
    return all_ok


def check_database_connection():
    """Check MySQL database connection"""
    print("\nChecking database connection...")
    try:
        from db_config import DatabaseManager
        db = DatabaseManager()
        
        if db.create_database():
            print("  ✓ Database creation (OK)")
        else:
            print("  ✗ Database creation (FAILED)")
            return False
        
        if db.connect():
            print("  ✓ Database connection (OK)")
            
            if db.create_tables():
                print("  ✓ Tables creation (OK)")
            else:
                print("  ✗ Tables creation (FAILED)")
                db.disconnect()
                return False
            
            db.disconnect()
            return True
        else:
            print("  ✗ Database connection (FAILED)")
            print("  → Check if MySQL/XAMPP is running")
            print("  → Verify credentials in db_config.py")
            return False
    
    except Exception as e:
        print(f"  ✗ Database check failed: {e}")
        return False


def check_project_structure():
    """Check if all required files exist"""
    print("\nChecking project structure...")
    required_files = [
        'web_vuln_scanner.py',
        'db_config.py',
        'payloads.py',
        'scanner/__init__.py',
        'scanner/sqli_scanner.py',
        'scanner/xss_scanner.py',
        'requirements.txt'
    ]
    
    all_ok = True
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✓ {file} (OK)")
        else:
            print(f"  ✗ {file} (MISSING)")
            all_ok = False
    
    return all_ok


def main():
    """Run all verification checks"""
    print("="*60)
    print("SETUP VERIFICATION")
    print("="*60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Project Structure", check_project_structure),
        ("Database Connection", check_database_connection),
    ]
    
    results = []
    for name, check_func in checks:
        result = check_func()
        results.append((name, result))
    
    print("\n" + "="*60)
    print("VERIFICATION SUMMARY")
    print("="*60)
    
    all_passed = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    print("="*60)
    
    if all_passed:
        print("\n✓ All checks passed! You're ready to run the scanner.")
        print("  Run: python web_vuln_scanner.py")
    else:
        print("\n✗ Some checks failed. Please fix the issues above.")
    
    return all_passed


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nVerification interrupted.")
    except Exception as e:
        print(f"\nError during verification: {e}")

