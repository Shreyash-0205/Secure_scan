import json
import os
import sys
import time
from scan_engine.scanner.crawler import WebCrawler
from scan_engine.execution.full_scan.run_all_scanners import SecurityScanner
from scan_engine.reports.scan_report.store_full_scan import FullScanResultHandler
from PyQt6.QtWidgets import QApplication

class SecurityScanManager:
    """Class to manage security scans, read results, and store findings."""

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.scanner_results_dir = "scan_engine/reports/scan_results_json"

    def update_scan_results(self, scanner_name, execution_time):
        """Update the execution time for a specific scanner in its existing result JSON file."""

        # Define actual file paths for each scanner's JSON file
        scanner_file_paths = {
            "http": "scan_engine/reports/scan_results_json/http.json",
            "sql_injection": "scan_engine/reports/scan_results_json/sql_injection.json",
            "broken_authentication": "scan_engine/reports/scan_results_json/broken_authentication.json",
            "csrf": "scan_engine/reports/scan_results_json/csrf.json",
            "store" : "scan_engine/reports/final_report/severity_report.json",
            "total_scan" : "scan_engine/reports/final_report/scan_summary.json"
        }

        # Get the file path for the given scanner_name
        results_file = scanner_file_paths.get(scanner_name)

        # If scanner name is not found in the mapping
        if not results_file:
            print(f"⚠️ Scanner '{scanner_name}' does not have a predefined results file.")
            return

        # Check if the results file exists
        if not os.path.exists(results_file):
            print(f"⚠️ Skipping update: {results_file} not found.")
            return  # Exit the function without creating a new file

        try:
            # Read existing file
            with open(results_file, "r") as file:
                results = json.load(file)

            # Ensure "execution_times" key exists
            if "execution_times" not in results:
                results["execution_times"] = {}

            # Update execution time
            results["execution_times"][scanner_name] = execution_time

            # Write the updated data back to the file
            with open(results_file, "w") as file:
                json.dump(results, file, indent=4)

            print(f"✅ Updated execution time for {scanner_name} in {results_file}")

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"❌ Error updating {results_file}: {e}")

    def run_crawler(self, target_url:str):
        """Runs the web crawler and logs execution time."""
        if not target_url:
            print("❌ URL is required for crawling.")
            return
        start_time = time.time()
        WebCrawler(target_url)  
        crawl_time = time.time() - start_time

        print(f"\n⏱️ Crawler completed in {crawl_time:.2f} seconds")

        self.update_scan_results("crawler", round(crawl_time, 2))
        return crawl_time

    def run_scanners(self):
        """Runs all security scanners and logs execution time for each."""
        start_time = time.time()

        results_file = "scan_engine/reports/scan_results.json"
        scanner = SecurityScanner(results_file)
        scanner.run()  # This saves scan_summary.json

        scan_time = time.time() - start_time
        print(f"\n⏱️ Security Scanners completed in {scan_time:.2f} seconds")

        # Load scan_summary to extract execution times
        summary_path = "scan_engine/reports/final_report/scan_summary.json"
        if os.path.exists(summary_path):
            try:
                with open(summary_path, "r") as f:
                    summary_data = json.load(f)
                    exec_times = summary_data.get("execution_times", {})

                    # Map the names used in scan_summary to internal scanner keys
                    name_mapping = {
                        "HTTP Scanner": "http",
                        "Broken Authentication Scanner": "broken_authentication",
                        "CSRF Scanner": "csrf",
                        "SQL Injection Scanner": "sql_injection",
                        "Total Scan Time": "total_scan"
                    }

                    for pretty_name, internal_key in name_mapping.items():
                        if pretty_name in exec_times:
                            self.update_scan_results(internal_key, round(exec_times[pretty_name], 2))

            except json.JSONDecodeError as e:
                print(f"❌ Failed to parse scan_summary.json: {e}")
        else:
            print("⚠️ scan_summary.json not found.")

        return scan_time

    def get_total_scan_count():
        from Database.db_connection import DatabaseConnection
        db = DatabaseConnection()
        try:
            db.connect()
            query = "SELECT COUNT(*) FROM scan_results"
            result = db.fetch_one(query)
            db.close()
            return result[0] if result else 0
        except Exception as e:
            print(f"❌ Error fetching scan count: {e}")
            return 0

    def store_results(self):
        """Stores scan results from all JSON files in the database and logs execution time."""
        print("\n🚀 Storing Results...")
        start_time = time.time()

        scan_files = [
            "scan_engine/reports/scan_results_json/http.json",
            "scan_engine/reports/scan_results_json/broken_authentication.json",
            "scan_engine/reports/scan_results_json/csrf.json",
            "scan_engine/reports/scan_results_json/sql_injection.json"
            ]

        scan_handler = FullScanResultHandler(scan_files)
        scan_handler.run()  

        store_time = time.time() - start_time

        print(f"\n⏱️ Results stored in {store_time:.2f} seconds")

        self.update_scan_results("total_scan", round(store_time, 2))
        return store_time

    def run_full_scan(self, url:str):
        """Runs the full scan process and tracks total execution time."""
        if not url:
            print("❌ URL is required for crawling.")
            return
        total_start_time = time.time()

        crawl_time = self.run_crawler(url)
        scan_time = self.run_scanners()
        print("\n✅ Security Scan Completed! Results saved in individual scanner files")
        store_time = self.store_results()

        total_time = time.time() - total_start_time 

        self.update_scan_results("total_scan", round(total_time, 2))

        print("\n✅ Security Scan Completed!")
        print(f"🔹 Crawler Time: {crawl_time:.2f} seconds")
        print(f"🔹 Scanners Time: {scan_time:.2f} seconds")
        print(f"🔹 Storing Results Time: {store_time:.2f} seconds")
        print(f"\n🚀 **Total Scan Time:** {total_time:.2f} seconds")


if __name__ == "__main__":
    if "--cli" in sys.argv:
        try:
            url_index = sys.argv.index("--url") + 1
            url = sys.argv[url_index]
        except (ValueError, IndexError):
            print("❌ Please provide a URL with --url <URL>")
            sys.exit(1)

        manager = SecurityScanManager()
        manager.run_full_scan(url)
    
    elif "--dev" in sys.argv:
        from GUI.main_window_ui.user_interface import Ui_MainWindow
        window = Ui_MainWindow()
        # optional: attach MainController here
        window.show()

    else:
        from GUI.log_in.login_gui import LoginWindow
        login = LoginWindow()
        login.show()
    app = QApplication(sys.argv)
    sys.exit(app.exec())

