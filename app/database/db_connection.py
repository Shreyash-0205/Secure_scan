import pymysql
import os
from pymysql.err import MySQLError

class DatabaseConnection:
    def __init__(self):
        """Initialize database connection using environment variables."""
        self.host = os.getenv('DB_HOST')
        self.user = os.getenv('DB_USER')
        self.password = os.getenv('DB_PASSWORD')
        self.database = os.getenv('DB_NAME')

        if not all([self.host, self.user, self.password, self.database]):
            raise ValueError("❌ Missing database environment variables!")

        self.connection = None
        self.cursor = None 

    def connect(self):
        """Establish a connection to the database."""
        try:
            print("🔌 Connecting to the database...")
            print(f"🧠 Host: {self.host}, User: {self.user}, DB: {self.database}")

            self.connection = pymysql.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                connect_timeout=5
            )
            print("Connected object created.")
            self.cursor = self.connection.cursor()
            print("✅ Successfully connected to the database.")
            return True 
        except Exception as e:
            print(f"💥 Exception while connecting to MySQL: {e}")
            import traceback
            traceback.print_exc()
            self.connection = None
            return False

    def close(self):
        """Close the database connection."""
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection:
                self.connection.close()
                print("🔒 Connection closed.")
        except Exception as e:
            print(f"⚠️ Error while closing DB connection: {e}")


    def execute_query(self, query, params=None, return_cursor=False, return_last_insert_id=False):
        """Execute an SQL query (INSERT, UPDATE, DELETE)."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()

            if return_last_insert_id:
                return cursor.lastrowid
            elif return_cursor:
                return cursor
        except MySQLError as e:
            print(f"❌ Error executing query: {e}")
        finally:
            cursor.close() 

    def fetch_all(self, query, params=None):
        """Fetch all results from a SELECT query."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            return result
        except MySQLError as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            cursor.close()

    def fetch_one(self, query, params=None):
        """Fetch a single row from a SELECT query."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()
        except MySQLError as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            cursor.close()

    def fetch_user_email(self, username):
        """Fetch user email based on username."""
        query = "SELECT email FROM login WHERE username = %s"
        result = self.fetch_all(query, (username,))
        return result[0][0] if result else None

    def insert_scan(self, website_url, execution_time, vulnerabilities_found):
        """Insert a new custom scan and return its ID."""
        query = """
        INSERT INTO custom_scans (sacnned_url, execution_time, vulnerabilities_found) 
        VALUES (%s, %s, %s)
        """
        return self.execute_query(query, (website_url, execution_time, vulnerabilities_found), return_last_insert_id=True)

    def insert_scan_result(self, scan_id, scanner_name, scanner_result, risk_level):
        """Insert a scan result linked to a scan ID."""
        query = """
        INSERT INTO custom_scan_results (scan_id, scanner_name, scanner_result, risk_level) 
        VALUES (%s, %s, %s, %s)
        """
        self.execute_query(query, (scan_id, scanner_name, scanner_result, risk_level))

if __name__ == "__main__":
    db = DatabaseConnection()
    connected = db.connect()
    print("Manual DB connection success:", connected)
