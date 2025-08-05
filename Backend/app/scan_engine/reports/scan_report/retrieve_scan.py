import json
from Database.db_connection import DatabaseConnection

class ScanResultRetriever:
    """Handles retrieval of scan results from the database."""

    def __init__(self):
        """Initialize the database connection."""
        self.db = DatabaseConnection()

    def fetch_scan_count(self):
        """Retrieve the total number of scans performed."""
        query = "SELECT COUNT(*) FROM scan_results"
        
        self.db.connect()
        result = self.db.fetch_one(query)  # ✅ Fetch the count
        self.db.close()

        if result:
            scan_count = result[0]  # Extract count value from the tuple
            print(f"\n📊 **Total Scans Performed: {scan_count}**")
            return scan_count
        else:
            print("❌ No scan records found in the database.")
            return 0

    def fetch_latest_scan_result(self):
        """Retrieve the most recent scan result from the database."""
        query = "SELECT website_url, scan_data FROM scan_results ORDER BY id DESC LIMIT 1"
        
        self.db.connect()
        result = self.db.fetch_one(query)
        self.db.close()

        if result:
            website_url, scan_data_json = result
            scan_data = json.loads(scan_data_json)  # Convert JSON string back to dictionary
            
            print(f"\n🔍 **Latest Scan Result for {website_url}**")
            print(json.dumps(scan_data, indent=4))  # Pretty print the JSON data
            
            return scan_data
        else:
            print("❌ No scan results found in the database.")
            return None

    def fetch_all_scan_results(self):
        """Retrieve all scan results from the database."""
        query = "SELECT website_url, scan_data FROM scan_results ORDER BY id DESC"

        self.db.connect()
        results = self.db.fetch_all(query)
        self.db.close()

        if results:
            print("\n🔍 **All Scan Results:**")
            for website_url, scan_data_json in results:
                scan_data = json.loads(scan_data_json)  # Convert JSON string to dictionary
                print(f"\n🔹 **Scan for {website_url}:**")
                print(json.dumps(scan_data, indent=4))
        else:
            print("❌ No scan results found in the database.")

# Example Usage
if __name__ == "__main__":
    retriever = ScanResultRetriever()
    retriever.fetch_scan_count()
    retriever.fetch_latest_scan_result()
    # Uncomment below line if you want to fetch all scan results
    # retriever.fetch_all_scan_results()
