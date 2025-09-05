import json
import time
import os
import sys
import hashlib
from scan_engine.scanner.network.http_scanner import URLSecurityScanner
from scan_engine.scanner.injections.sql_injection import SQLInjectionScanner
from scan_engine.scanner.injections.xss_injection import XSSScanner
from scan_engine.scanner.authentication.broken_authentication import BrokenAuthScanner
from scan_engine.scanner.authentication.csrf_scanner import CSRFScanner
from scan_engine.scanner.crawler import WebCrawler
from scan_engine.reports.scan_report.store_custom_scan import CustomScanResultHandler
from Database.db_connection import DatabaseConnection as db

class CustomSecurityScanner:
    """Class to manage and run custom-selected security scanners."""

    SECURITY_SCAN_RESULTS_FILE = "scan_engine/reports/final_report/security_scan_results.json"

    def __init__(self, url=None, selected_scanners=None):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self._update_sys_path()
        self.db = db()

        self.url = url
        self.selected_scanners = selected_scanners
        self.scan_results = None

    def _update_sys_path(self):
        """Ensure the project root is in sys.path."""
        if self.project_root not in sys.path:
            sys.path.append(self.project_root)

    def normalize_scanner_name(self, scanner_name):
        """Ensure consistent scanner names to avoid duplicates."""
        SCANNER_NAME_MAPPING = {
            "Http Scanner": "HTTP Scanner",
            "SQL-Injection": "SQL Injection",
            "SQLInjection": "SQL Injection",
            "XSS-Injection": "XSS Injection",
            "Broken Authentication": "Broken Authentication",
            "CSRFScanner": "CSRF Scanner",
            "CSRF Scanner": "CSRF Scanner"
        }
        return SCANNER_NAME_MAPPING.get(scanner_name, scanner_name)  

    def run_custom_scan(self):
        """Runs only the selected security scanners and stores results via CustomScanResultHandler."""
        scans_results = {
        "scans": {},
        "execution_times": {}
        }
        scanner_mapping = {
            "HTTP Scanner": URLSecurityScanner,
            "SQL Injection": SQLInjectionScanner,
            "XSS Injection": XSSScanner,
            "Broken Authentication": BrokenAuthScanner,
            "CSRF Scanner": CSRFScanner
        }

        for scanner_name in self.selected_scanners:
            normalized_name = self.normalize_scanner_name(scanner_name)
            if normalized_name in scanner_mapping and normalized_name not in scans_results["scans"]:
                scanner_instance = scanner_mapping[normalized_name]()

                start_time = time.time()
                scanner_instance.run()
                duration = time.time() - start_time

                scans_results["scans"][normalized_name] = scanner_instance.scan_results
                scans_results["execution_times"][normalized_name] = round(duration, 4)

        total_scan_time = sum(scans_results["execution_times"].values())
        scans_results["execution_times"]["Total Scan Time"] = round(total_scan_time, 4)

        try:
            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as f:
                json.dump(scans_results, f, indent=4)
            print(f"✅ Temporary scan results saved to {self.SECURITY_SCAN_RESULTS_FILE}")
        except Exception as e:
            print(f"❌ Failed to write scan results to file: {e}")
            return scans_results

        try:
            handler = CustomScanResultHandler([self.SECURITY_SCAN_RESULTS_FILE])
            handler.store_custom_scan_results()
        except Exception as e:
            print(f"❌ Failed to store scan results using CustomScanResultHandler: {e}")

        self.scan_results = scans_results
        return scans_results
    
    def get_results(self):
        return self.scan_results if self.scan_results else {}

class SecurityCustomScanManager:
    """Manages security scans, stores findings, and provides selection menus."""

    SECURITY_SCAN_RESULTS_FILE = "scan_engine/reports/final_report/security_scan_results.json"

    SCANNERS = {
        1: "SQL-Injection",
        2: "XSS-Injection",
        3: "Broken Authentication",
        4: "CSRF Scanner"
    }

    def __init__(self):
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def update_scan_results(self, key, value):
        """Update security_scan_results.json without overwriting existing data."""
        try:
            results = {}
            if os.path.exists(self.SECURITY_SCAN_RESULTS_FILE):
                with open(self.SECURITY_SCAN_RESULTS_FILE, "r") as file:
                    try:
                        results = json.load(file)
                    except json.JSONDecodeError:
                        results = {}

            if "execution_times" not in results:
                results["execution_times"] = {}

            results["execution_times"][key] = value

            with open(self.SECURITY_SCAN_RESULTS_FILE, "w") as file:
                json.dump(results, file, indent=4)

        except Exception as e:
            print(f"❌ Error updating scan results file: {e}")

    def run_crawler(self, target_url):
        """Runs the web crawler and logs execution time."""
        print("🚀 Running Crawler...")
        start_time = time.time()

        crawler = WebCrawler(target_url)
        crawler.crawl()

        crawl_time = time.time() - start_time
        print(f"\n⏱️ Crawler completed in {crawl_time:.2f} seconds")

        self.update_scan_results("crawler_time", round(crawl_time, 2))
        return crawl_time

    def run_scanners(self, target_url, selected_scanners):
        """Runs selected security scanners and logs execution time."""
        print("\n🚀 Running Selected Security Scanners...")
        start_time = time.time()

        scanner = CustomSecurityScanner(target_url, selected_scanners)
        scan_results = scanner.run_custom_scan()

        scan_time = time.time() - start_time
        print(f"\n⏱️ Security Scanners completed in {scan_time:.2f} seconds")

        self.update_scan_results("scanner_time", round(scan_time, 2))
        return scan_results, scan_time

    def store_results(self):
        """Stores scan results in the database and logs execution time."""
        print("\n🚀 Storing Results...")
        start_time = time.time()

        scan_handler = CustomScanResultHandler([self.SECURITY_SCAN_RESULTS_FILE])
        scan_handler.store_custom_scan_results()

        store_time = time.time() - start_time
        print(f"\n⏱️ Results stored in {store_time:.2f} seconds")

        self.update_scan_results("store_time", round(store_time, 2))
        return store_time

    def select_scanners_menu(self):
        """Displays a menu for scanner selection and returns the selected scanners."""
        print("\n🔹 **Select Security Scanners to Run** 🔹")
        
        # ✅ Use consistent scanner names
        SCANNERS = {
            1: "SQL Injection",
            2: "XSS Injection",
            3: "Broken Authentication",
            4: "CSRF Scanner"
        }

        for num, scanner in SCANNERS.items():
            print(f"[{num}] {scanner}")

        while True:
            try:
                user_input = input("\nEnter the numbers of the scanners you want to run (comma-separated): ")
                selected_numbers = [int(num.strip()) for num in user_input.split(",")]

                selected_scanners = [SCANNERS[num] for num in selected_numbers if num in SCANNERS]

                if not selected_scanners:
                    print("❌ Invalid selection. Please select at least one valid scanner.")
                else:
                    return selected_scanners

            except ValueError:
                print("❌ Invalid input. Please enter numbers only (e.g., 1,2,3).")


    def run_custom_scan(self):
        """Runs the full scan process and tracks execution time."""
        total_start_time = time.time()

        target_url = input("Enter the target URL (e.g., http://example.com): ").strip()
        selected_scanners = self.select_scanners_menu()

        crawl_time = self.run_crawler(target_url)
        scan_results, scan_time = self.run_scanners(target_url, selected_scanners) 

        print("\n✅ Security Scan Completed! Results saved in", self.SECURITY_SCAN_RESULTS_FILE)
        store_time = self.store_results()

        total_time = time.time() - total_start_time
        self.update_scan_results("total_scan_time", round(total_time, 2))

        print("\n✅ Security Scan Completed!")
        print(f"🔹 Crawler Time: {crawl_time:.2f} seconds")
        print(f"🔹 Scanners Time: {scan_time:.2f} seconds")
        print(f"🔹 Storing Results Time: {store_time:.2f} seconds")
        print(f"\n🚀 **Total Scan Time:** {total_time:.2f} seconds")

    def run(self):
        """Generator method to stream progress updates for PyQt."""
        yield f"🚀 Starting scan on {self.url} with: {', '.join(self.selected_scanners)}...\n"

        start_time = time.time()

        yield "🔎 Running web crawler...\n"
        crawler = WebCrawler(self.url)
        crawler.crawl()
        yield "✅ Crawler finished.\n"

        yield "🛡️ Running selected security scanners...\n"
        self.scan_results = self.run_custom_scan(self.selected_scanners, self.url)
        yield "✅ Security scanners finished.\n"

        total_time = time.time() - start_time
        if "execution_times" not in self.scan_results:
            self.scan_results["execution_times"] = {}
        self.scan_results["execution_times"]["total_scan_time"] = round(total_time, 2)

        yield f"🕒 Total scan time: {total_time:.2f} seconds\n"


if __name__ == "__main__":
    manager = SecurityCustomScanManager()
    manager.run_custom_scan()
