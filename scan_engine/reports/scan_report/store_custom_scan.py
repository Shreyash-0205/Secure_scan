import json
import os
from datetime import datetime
from Database.db_connection import DatabaseConnection

class CustomScanResultHandler:
    """Handles saving custom scan results from multiple JSONs into the database."""

    def __init__(self, json_files, mapped_data_path="scan_engine/scanner/mapped_data.json"):
        self.json_files = json_files
        self.mapped_data_path = mapped_data_path
        self.db = DatabaseConnection()

    def load_scan_results(self):
        combined_results = {
            "scans": {},
            "execution_times": {},
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        for file in self.json_files:
            if not os.path.isfile(file):
                print(f"⚠️ Warning: {file} not found. Skipping.")
                continue

            try:
                with open(file, "r") as f:
                    scan_data = json.load(f)

                filename = os.path.basename(file).replace(".json", "")
                combined_results["scans"][filename] = scan_data

                if "execution_times" in scan_data:
                    combined_results["execution_times"].update(scan_data["execution_times"])

            except Exception as e:
                print(f"❌ Failed to read {file}: {e}")

        return combined_results

    def load_website_url(self):
        try:
            with open(self.mapped_data_path, "r") as f:
                mapped = json.load(f)
            return mapped.get("target_url", "Unknown")
        except:
            return "Unknown"

    def load_scan_summary(self):
        summary_path = "scan_engine/reports/final_report/security_scan_results.json"

        if not os.path.exists(summary_path):
            print(f"⚠️ {summary_path} not found. Using default summary.")
            return {
                "vulnerabilities_found": 0,
                "high_risk_vulnerabilities": 0,
                "medium_risk_vulnerabilities": 0,
                "low_risk_vulnerabilities": 0,
                "total_scan_time": None
            }

        try:
            with open(summary_path, "r") as f:
                summary = json.load(f)

            high = medium = low = 0

            scans = summary.get("scans", {})
            for scanner_data in scans.values():
                for url, findings in scanner_data.items():
                    if isinstance(findings, list):  # For scanners like SQL Injection
                        for item in findings:
                            severity = item.get("severity", "").lower()
                            if severity == "high":
                                high += 1
                            elif severity == "medium":
                                medium += 1
                            elif severity == "low":
                                low += 1
                    elif isinstance(findings, dict):  # For other types like Broken Auth
                        for key, value in findings.items():
                            if isinstance(value, str):
                                sev = value.lower()
                                if sev == "high":
                                    high += 1
                                elif sev == "medium":
                                    medium += 1
                                elif sev == "low":
                                    low += 1

            total_vulns = high + medium + low
            total_scan_time = summary.get("execution_times", {}).get("Total Scan Time", None)

            return {
                "vulnerabilities_found": total_vulns,
                "high_risk_vulnerabilities": high,
                "medium_risk_vulnerabilities": medium,
                "low_risk_vulnerabilities": low,
                "total_scan_time": total_scan_time
            }

        except Exception as e:
            print(f"❌ Error reading summary: {e}")
            return {
                "vulnerabilities_found": 0,
                "high_risk_vulnerabilities": 0,
                "medium_risk_vulnerabilities": 0,
                "low_risk_vulnerabilities": 0,
                "total_scan_time": None
            }


    def store_custom_scan_results(self):
        scan_results = self.load_scan_results()
        if not scan_results["scans"]:
            print("❌ No valid scan data found.")
            return

        summary = self.load_scan_summary()
        website_url = self.load_website_url()
        scan_json = json.dumps(scan_results, indent=4)

        query = """
            INSERT INTO custom_scans (
                scanned_url, scan_data, execution_time, vulnerabilities_found,
                high_risk_vulnerabilities, medium_risk_vulnerabilities, low_risk_vulnerabilities
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            website_url,
            scan_json,
            summary["total_scan_time"],
            summary["vulnerabilities_found"],
            summary["high_risk_vulnerabilities"],
            summary["medium_risk_vulnerabilities"],
            summary["low_risk_vulnerabilities"]
        )

        try:
            self.db.connect()
            self.db.execute_query(query, values)
            self.db.close()
            print(f"✅ Custom scan saved for {website_url}!")
        except Exception as e:
            print(f"❌ DB error: {e}")
            self.db.close()

    def run(self):
        print("🚀 Running Custom Scan Result Handler...")
        self.store_custom_scan_results()
        print("✅ Custom Scan Handler complete.")



if __name__ == "__main__":
    custom_scan_handler = CustomScanResultHandler(["scan_engine/reports/final_report/security_scan_results.json"])
    custom_scan_handler.store_custom_scan_results()
