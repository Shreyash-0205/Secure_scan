import json
import os
from datetime import datetime
from Database.db_connection import DatabaseConnection

class FullScanResultHandler:
    """Handles combining scan results from multiple JSON files and saving to the database."""

    def __init__(self, json_files, mapped_data_path="mapped_data.json"):
        """Initialize with the list of JSON files containing scan results and path to mapped data."""
        self.json_files = json_files  # List of JSON files
        self.mapped_data_path = "scan_engine/scanner/mapped_data.json"
        self.db = DatabaseConnection()

    def load_scan_results(self):
        """Load and combine scan results from multiple JSON files."""
        combined_results = {
            "scans": {},
            "execution_times": {},
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if not isinstance(self.json_files, list) or not all(isinstance(f, str) for f in self.json_files):
            print(f"❌ Error: self.json_files must be a list of valid file paths. Received: {self.json_files}")
            return combined_results

        for file in self.json_files:
            if not os.path.isfile(file):
                print(f"⚠️ Warning: {file} not found or is not a valid file. Skipping...")
                continue

            try:
                with open(file, "r") as f:
                    scan_data = json.load(f)

                filename = os.path.basename(file).replace(".json", "")
                combined_results["scans"][filename] = scan_data if isinstance(scan_data, dict) else {}

                # Merge execution times if available
                if "execution_times" in scan_data:
                    combined_results["execution_times"].update(scan_data["execution_times"])

            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"❌ Error: Unable to read {file}. {e}")

        return combined_results

    def load_website_url(self):
        """Load website URL from mapped_data.json."""
        if not os.path.isfile(self.mapped_data_path):
            print(f"❌ Error: Mapped data file '{self.mapped_data_path}' not found.")
            return "Unknown"

        try:
            with open(self.mapped_data_path, "r") as f:
                mapped_data = json.load(f)
                return mapped_data.get("target_url", "Unknown")
        except Exception as e:
            print(f"❌ Error reading mapped_data.json: {e}")
            return "Unknown"

    def load_scan_summary(self):
            """Load vulnerability counts and execution time from scan_summary.json."""
            summary_path = "scan_engine/reports/final_report/scan_summary.json"

            if not os.path.isfile(summary_path):
                print(f"⚠️ Warning: {summary_path} not found. Using default vulnerability values.")
                return {
                    "vulnerabilities_found": 0,
                    "high_risk_vulnerabilities": 0,
                    "medium_risk_vulnerabilities": 0,
                    "low_risk_vulnerabilities": 0,
                    "total_scan_time": None
                }

            try:
                with open(summary_path, "r") as f:
                    summary_data = json.load(f)

                return {
                    "vulnerabilities_found": summary_data.get("vulnerabilities_found", 0),
                    "high_risk_vulnerabilities": summary_data.get("high_risk_vulnerabilities", 0),
                    "medium_risk_vulnerabilities": summary_data.get("medium_risk_vulnerabilities", 0),
                    "low_risk_vulnerabilities": summary_data.get("low_risk_vulnerabilities", 0),
                    "total_scan_time": summary_data.get("execution_times", {}).get("Total Scan Time", None)
                }
            except Exception as e:
                print(f"❌ Error reading scan_summary.json: {e}")
                return {
                    "vulnerabilities_found": 0,
                    "high_risk_vulnerabilities": 0,
                    "medium_risk_vulnerabilities": 0,
                    "low_risk_vulnerabilities": 0,
                    "total_scan_time": None
                }

    def store_scan_results(self):
        """Save the combined scan results to the database."""
        scan_results = self.load_scan_results()
        if not scan_results or not scan_results["scans"]:
            print("❌ Error: No valid scan data found.")
            return

        vulnerability_count = self.load_scan_summary()

        website_url = self.load_website_url()

        total_scan_time = vulnerability_count["total_scan_time"]

        scan_json = json.dumps(scan_results, indent=4)

        query = """
            INSERT INTO scan_results (
                scanned_url, scan_data, execution_time, vulnerabilities_found,
                high_risk_vulnerabilities, medium_risk_vulnerabilities, low_risk_vulnerabilities
            ) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            website_url,
            scan_json,
            total_scan_time,
            vulnerability_count["vulnerabilities_found"],
            vulnerability_count["high_risk_vulnerabilities"],
            vulnerability_count["medium_risk_vulnerabilities"],
            vulnerability_count["low_risk_vulnerabilities"]
        )

        try:
            self.db.connect()
            self.db.execute_query(query, values)
            self.db.close()

            print(f"✅ Scan result stored successfully for {website_url}!")
            print(f"🕒 Total Scan Time Stored: {total_scan_time:.2f} seconds" if total_scan_time else "🕒 Total Scan Time: Not Available")
            print(f"⚠️ Total Vulnerabilities Found: {vulnerability_count['vulnerabilities_found']}")
            print(f"🔴 High Risk Vulnerabilities: {vulnerability_count['high_risk_vulnerabilities']}")
            print(f"🟠 Medium Risk Vulnerabilities: {vulnerability_count['medium_risk_vulnerabilities']}")
            print(f"🟢 Low Risk Vulnerabilities: {vulnerability_count['low_risk_vulnerabilities']}")

        except Exception as e:
            print(f"❌ Error while executing the query or saving results to the database: {e}")
            self.db.close()


    def run(self):
        """Convenience method to execute the full result storage pipeline."""
        print("🚀 Running Full Scan Result Handler...")
        self.store_scan_results()
        print("✅ Full Scan Result Handler execution complete.")
