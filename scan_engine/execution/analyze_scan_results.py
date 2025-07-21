import json
import os

class SecureScanAnalyzer:
    def __init__(self, scan_results_dir):
        self.scan_results_dir = scan_results_dir
        self.severity_summary = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}
        self.scanner_breakdown = {}

    def analyze_scan_results(self):
        for filename in os.listdir(self.scan_results_dir):
            file_path = os.path.join(self.scan_results_dir, filename)
            
            if not filename.endswith(".json"):
                continue  # Skip non-JSON files
            
            try:
                with open(file_path, "r") as file:
                    data = json.load(file)
                    self.process_scan_data(data, filename)
            except json.JSONDecodeError:
                print(f"⚠️ Skipping invalid JSON file: {filename}")
        
        self.generate_final_report()

    def process_scan_data(self, data, scanner_name):
        scanner_key = scanner_name.replace(".json", "")
        self.scanner_breakdown[scanner_key] = {"High": 0, "Medium": 0, "Low": 0, "Safe": 0}

        if "scans" in data:
            for scanner, urls in data["scans"].items():
                for url, findings in urls.items():
                    if isinstance(findings, list):  # If multiple findings per URL
                        for finding in findings:
                            self.count_severity(scanner_key, finding)
                    else:  # If it's a single object per URL
                        self.count_severity(scanner_key, findings)

    def count_severity(self, scanner_key, finding):
        severity = finding.get("severity", "Safe")  # Default to "Safe" if severity is missing
        if severity not in self.severity_summary:
            severity = "Safe"  # Catch any unexpected values
        
        self.severity_summary[severity] += 1
        self.scanner_breakdown[scanner_key][severity] += 1

    def generate_final_report(self):
        final_report = {
            "severity_summary": self.severity_summary,
            "scanner_breakdown": self.scanner_breakdown
        }

        with open("scan_results_json/final_report.json", "w") as report_file:
            json.dump(final_report, report_file, indent=4)
        
        print("✅ Final scan report saved as 'scan_results_json/final_report.json'")

# Run Analysis
analyzer = SecureScanAnalyzer("scan_results_json")
analyzer.analyze_scan_results()
