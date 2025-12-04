#!/usr/bin/env python3
"""
Startup script for vulnerable_app.py with detailed diagnostics
Run on Kali: python3 start_vulnerable_app.py
"""
import subprocess
import sys
import time
import os
import signal

def check_dependencies():
    """Verify all required packages are installed"""
    print("Checking dependencies...")
    required = ['flask', 'flask_sqlalchemy', 'sqlite3']
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg.replace('_', '-'))
            print(f"  ✅ {pkg}")
        except ImportError:
            print(f"  ❌ {pkg}")
            missing.append(pkg)
    
    if missing:
        print(f"\nInstalling {len(missing)} missing package(s)...")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + missing, check=False)
    
    return True

def cleanup_old_db():
    """Remove old database to force fresh initialization"""
    if os.path.exists('vulnerable.db'):
        print("\nRemoving old vulnerable.db...")
        try:
            os.remove('vulnerable.db')
            print("  ✅ Old database removed")
        except Exception as e:
            print(f"  ⚠️  Could not remove old DB: {e}")

def start_app():
    """Start the vulnerable app and monitor its startup"""
    print("\nStarting vulnerable_app.py...")
    print("=" * 60)
    
    try:
        # Start in foreground so we can see errors
        proc = subprocess.Popen(
            [sys.executable, 'vulnerable_app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Monitor output for 10 seconds to catch startup errors
        start_time = time.time()
        db_created = False
        
        while time.time() - start_time < 10:
            line = proc.stdout.readline()
            if line:
                print(line.rstrip())
                if 'vulnerable.db' in line or 'Sample users' in line:
                    db_created = True
            
            # Check if DB exists
            if os.path.exists('vulnerable.db') and not db_created:
                db_created = True
                print("\n✅ vulnerable.db created successfully!")
            
            # Check if process crashed
            if proc.poll() is not None:
                print(f"\n❌ App process exited with code {proc.returncode}")
                remaining = proc.stdout.read()
                if remaining:
                    print("Remaining output:")
                    print(remaining)
                return False
            
            time.sleep(0.1)
        
        # Give it a moment to bind to port
        time.sleep(2)
        
        if os.path.exists('vulnerable.db'):
            print("\n" + "=" * 60)
            print("✅ STARTUP SUCCESSFUL")
            print("=" * 60)
            print("\nVulnerable app is running on http://localhost:8080/")
            print("Database: vulnerable.db")
            print("\nPress Ctrl+C to stop the app\n")
            
            # Keep process running
            try:
                proc.wait()
            except KeyboardInterrupt:
                print("\nShutting down...")
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            
            return True
        else:
            print("\n❌ Database not created - check error output above")
            proc.terminate()
            return False
            
    except Exception as e:
        print(f"\n❌ Error starting app: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("Vulnerable App Startup Manager")
    print("=" * 60)
    
    # Check we're in right directory
    if not os.path.exists('vulnerable_app.py'):
        print("❌ vulnerable_app.py not found in current directory!")
        print(f"Current directory: {os.getcwd()}")
        sys.exit(1)
    
    print(f"Working directory: {os.getcwd()}")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Clean old database
    cleanup_old_db()
    
    # Start app
    if start_app():
        print("\n✅ Vulnerable app ran successfully")
        sys.exit(0)
    else:
        print("\n❌ Vulnerable app startup failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
