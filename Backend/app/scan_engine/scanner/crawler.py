import json
import sys
import os
import time
import subprocess
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright
from scan_engine.execution.full_scan.run_all_scanners import SecurityScanner

class WebCrawler:
    def __init__(self, target_url, mode="full_scan", selected_scanners=None, max_depth=2, max_pages=50):
        """ 
        Initialize the WebCrawler.
        - mode: "full_scan" (runs all scanners) or "custom_scan" (runs selected scanners).
        - selected_scanners: List of scanners (used only in custom scans).
        """
        self.target_url = target_url
        self.mode = mode
        self.selected_scanners = selected_scanners or []
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_links = set()
        self.mapped_data = {"target_url": target_url, "pages": []}
        self.results_file = "scan_engine/scanner/mapped_data.json"

    def extract_links(self, page, base_url):
        """Extracts all valid internal links from the page."""
        links = set()
        for link in page.query_selector_all("a"):
            href = link.get_attribute("href")
            if href:
                absolute_url = urljoin(base_url, href)
                parsed_absolute = urlparse(absolute_url)
                parsed_base = urlparse(base_url)

                if parsed_absolute.netloc == parsed_base.netloc and absolute_url not in self.visited_links:
                    links.add(absolute_url)

        return list(links)

    def extract_forms(self, page, base_url):
        """Extracts form details from the page."""
        forms = []
        for form in page.query_selector_all("form"):
            action = form.get_attribute("action") or base_url
            method = form.get_attribute("method") or "GET"

            inputs = []
            for input_element in form.query_selector_all("input, textarea, select"):
                input_name = input_element.get_attribute("name")
                if input_name:
                    inputs.append(input_name)

            forms.append({
                "action": urljoin(base_url, action),
                "method": method.upper(),
                "inputs": inputs
            })

        return forms

    def visit_page(self, page, url, base_url, depth):
        """Visits a page and extracts links and forms."""
        if depth >= self.max_depth or url in self.visited_links or len(self.mapped_data["pages"]) >= self.max_pages:
            return

        print(f"\n🔍 Crawling: {url} (Depth: {depth})")
        self.visited_links.add(url)

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except TimeoutError:
            print(f"⚠️ Timeout: Skipping {url} (Page took too long to load)")
            return

        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(1500)

        page_data = {
            "url": url,
            "links": self.extract_links(page, base_url),
            "forms": self.extract_forms(page, base_url)
        }

        self.mapped_data["pages"].append(page_data)

        for link in page_data["links"]:
            if len(self.mapped_data["pages"]) < self.max_pages:
                self.visit_page(page, link, base_url, depth + 1)

    def crawl(self):
        """Main function to start crawling a website."""
        print("\n🚀 Starting Web Crawler...") 
        print(f"🔎 Target URL: {self.target_url}") 

        start_time = time.time()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_extra_http_headers({"User-Agent": "Chromium (compatible; WebCrawler/1.0)"})

            try:
                self.visit_page(page, self.target_url, self.target_url, 0)
            finally:
                browser.close()

        crawl_time = time.time() - start_time
        print(f"\n Crawling Complete! Time: {crawl_time:.2f} seconds")

        self.store_crawl_results(crawl_time)
        self.run_scanners()

    def store_crawl_results(self, crawl_time):
        """Saves crawling results into the existing JSON file."""
        
        self.mapped_data["execution_time"] = round(crawl_time, 2)

        # Ensure there's actual data to save (skip if empty)
        if not self.mapped_data["pages"]:
            print(" No data to save. No pages crawled.")
            return

        try:
            # Check if the file exists
            if os.path.exists(self.results_file):
                with open(self.results_file, "r+", encoding="utf-8") as file:
                    try:
                        existing_data = json.load(file)
                        print(f"📂 Loaded existing data: {existing_data}")
                    except json.JSONDecodeError:
                        print(f"⚠️ {self.results_file} is empty or invalid. Creating a new one.")
                        existing_data = {}

                    # Merge existing data with new crawl results
                    existing_data.update(self.mapped_data)

                    # Write the updated JSON back to the file
                    file.seek(0)
                    json.dump(existing_data, file, indent=4)
                    file.truncate() 

            else:
                # If file doesn't exist, create and write new data
                with open(self.results_file, "w", encoding="utf-8") as file:
                    json.dump(self.mapped_data, file, indent=4)

                print(f"✅ Created new file and saved crawl data to {self.results_file}")

            print(f"\n✅ Crawling results saved to {self.results_file}")

        except Exception as e:
            print(f"❌ Error saving crawl results: {e}")

    def run_scanners(self):
        """Runs the appropriate scanner script after crawling."""
        
        try:
            if self.mode == "custom_scan":
                # Directly call the custom_scan function
                from scan_engine.execution.custom_scan.custom_scan_website import custom_scan
                custom_scan(self.results_file, self.selected_scanners)
            else:
                # Call the full scan function directly
                SecurityScanner(self.results_file)

            print(f"\n✅ Scanners executed successfully!")

        except Exception as e:
            print(f"❌ Error running scanner script: {e}")

if __name__ == "__main__":
    import sys

    print("✅ Script Started!")

    if "--cli" in sys.argv:
        try:
            url_index = sys.argv.index("--url") + 1
            target_url = sys.argv[url_index]
            print(f"✅ Received Input URL: {target_url}")
        except (ValueError, IndexError):
            print("❌ Please provide a URL using --url <URL>")
            sys.exit(1)

        if target_url.startswith("http"):
            print("✅ URL is valid, initializing WebCrawler...")
            WebCrawler(target_url).crawl()
        else:
            print("❌ Invalid URL! Make sure to include 'http://' or 'https://'.")
            sys.exit(1)



