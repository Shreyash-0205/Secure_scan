import json
import requests
from datetime import datetime


class BrokenAuthScanner:
    WEAK_PASSWORDS = [
        "admin", "password", "123456", "password123", "letmein", "welcome",
        "qwerty", "abc123", "54321", "111111", "123123"
    ]

    SEVERITY = {
        "High": "Critical vulnerability that poses a major risk.",
        "Low": "The vulnerability is either mitigated or less impactful.",
        "Safe": "No vulnerabilities detected. Authentication appears secure."
    }

    def __init__(self, mapped_data_file="scan_engine/scanner/mapped_data.json", results_file="scan_engine/reports/scan_results_json/broken_authentication.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.mapped_data = self.load_mapped_data()
        self.scan_results = {}

    def load_mapped_data(self):
        """Load and parse URLs from mapped_data.json."""
        try:
            with open(self.mapped_data_file, "r") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return {}

    def find_login_pages(self):
        """Extract login form URLs from mapped_data.json."""
        login_pages = []

        for page in self.mapped_data.get("pages", []):
            for form in page.get("forms", []):
                if any("password" in field.lower() for field in form.get("inputs", [])):
                    login_pages.append(form["action"])

        return login_pages

    def test_weak_passwords(self, target_url):
        """Check for weak credentials."""
        print(f"\n🔍 Testing {target_url} for weak login credentials...")

        for password in self.WEAK_PASSWORDS:
            data = {"username": "admin", "password": password}
            try:
                response = requests.post(target_url, data=data, timeout=5)

                if "Invalid" not in response.text and response.status_code == 200:
                    print(f"⚠️ Weak credentials found: admin / {password}")
                    return "High"
            except requests.RequestException as e:
                print(f"❌ Error testing weak passwords: {e}")
                return "Low"

        print("✅ No weak credentials detected.")
        return "Safe"

    def test_brute_force_protection(self, target_url):
        """Check if account lockout is enforced."""
        print(f"\n🔍 Testing {target_url} for brute-force protection...")

        for _ in range(5):  # Simulating multiple failed login attempts
            data = {"username": "admin", "password": "wrongpassword"}
            try:
                response = requests.post(target_url, data=data, timeout=5)

                if "Locked" in response.text or response.status_code == 429:
                    print("✅ Account lockout is enforced.")
                    return "Safe"
            except requests.RequestException as e:
                print(f"❌ Error testing brute-force protection: {e}")
                return "High"

        print("❌ No account lockout detected! Brute-force attack is possible.")
        return "High"

    def test_session_logout(self, target_url, dashboard_url, logout_url):
        """Check if session is properly invalidated after logout."""
        print(f"\n🔍 Checking session management for {target_url}...")

        session = requests.Session()

        # Log in with test credentials
        login_data = {"username": "admin", "password": "password123"}
        try:
            response = session.post(target_url, data=login_data, timeout=5)

            if "Invalid" in response.text:
                print("⚠️ Cannot log in with test credentials. Skipping session test.")
                return "Safe"
        except requests.RequestException as e:
            print(f"❌ Error logging in: {e}")
            return "Safe"

        # Check if dashboard is accessible
        try:
            dashboard_response = session.get(dashboard_url, timeout=5)
            if "Unauthorized" in dashboard_response.text:
                print("❌ Session not established correctly.")
                return "Low"
        except requests.RequestException as e:
            print(f"❌ Error accessing dashboard: {e}")
            return "Low"

        # Log out and check if session persists
        try:
            session.get(logout_url, timeout=5)
            dashboard_response_after_logout = session.get(dashboard_url, timeout=5)

            if "Unauthorized" not in dashboard_response_after_logout.text:
                print("❌ Session persists after logout! Logout is not secure.")
                return "High"
        except requests.RequestException as e:
            print(f"❌ Error testing session logout: {e}")
            return "Low"

        print("✅ Session is properly invalidated after logout.")
        return "Safe"

    def save_scan_results(self):
        """Save scan results to a JSON file without overwriting previous results."""
        try:
            with open(self.results_file, "r") as f:
                previous_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            previous_results = {}

        # Ensure all results are stored under a common structure
        if "scans" not in previous_results:
            previous_results["scans"] = {}

        # Add current scan results under the scanner's name
        previous_results["scans"][self.__class__.__name__] = self.scan_results  # Using self.results now

        with open(self.results_file, "w") as f:
            json.dump(previous_results, f, indent=4)

        print("\n✅ Authentication Tests Complete! Results saved in broken_authentication.json")

    def run(self):
        """Run authentication tests on detected login pages."""
        print("\n🚀 Scanning...\n")

        if not self.mapped_data:
            print("❌ No mapped data found!")
            return

        login_pages = self.find_login_pages()

        if not login_pages:
            print("❌ No login forms found in the scanned website.")
            return

        for login_url in login_pages:
            print(f"\n🚀 Testing login page: {login_url}")

            # Guess dashboard and logout URLs based on login path
            base_url = "/".join(login_url.split("/")[:-1])
            dashboard_url = f"{base_url}/dashboard"
            logout_url = f"{base_url}/logout"

            weak_password_severity = self.test_weak_passwords(login_url)
            brute_force_severity = self.test_brute_force_protection(login_url)
            session_severity = self.test_session_logout(login_url, dashboard_url, logout_url)

            # Determine overall safety level
            if weak_password_severity == "Safe" and brute_force_severity == "Safe" and session_severity == "Safe":
                overall_severity = "Safe"
            else:
                overall_severity = {
                    "High": "High" if any(s == "High" for s in [weak_password_severity, brute_force_severity, session_severity]) else "Low"
                }["High"]

            self.scan_results[login_url] = {
                "Weak Passwords Severity": weak_password_severity,
                "Brute Force Protection Severity": brute_force_severity,
                "Session Management Severity": session_severity,
                "Overall Severity": overall_severity
            }

        self.save_scan_results()
