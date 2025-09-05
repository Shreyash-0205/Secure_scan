import bcrypt
import logging
from Database.db_connection import DatabaseConnection

# Configure logging
logging.basicConfig(level=logging.INFO)  

class LoginLogic:

    def __init__(self):
        self.db = DatabaseConnection()

    def verify_user_credentials(self, username, password):
        """Checks if the username and password are valid."""
        print("🚀 Function verify_user_credentials started!")

        try:
            if not self.db.connect():
                print("❌ Database connection failed!")
                logging.error("❌ Database connection failed!")
                return False
        except Exception as e:
            print(f"💥 Exception while connecting to DB: {e}")
            logging.error(f"❌ DB Connect Exception: {e}")
            return False

        print(f"🔍 Checking login for: {username}")

        if not username or not password:
            print("⚠️ Username or password is empty!")
            logging.warning("❌ Username or password is empty!")
            return False  

        try:
            print("📡 Fetching password from database...")
            result = self.db.fetch_all("SELECT password FROM login WHERE username = %s", (username,))
            print(f"👥 All users in DB: {result}")
        except Exception as e:
            print(f"💥 Database error: {e}")
            logging.error(f"❌ Database error: {e}")
            return False  
        finally:
            self.db.close()

        if not result:
            print("❌ User not found!")
            logging.warning("❌ User not found!")
            return False  

        stored_password = result[0][0]
        print(f"🔑 Stored password retrieved: {stored_password}")

        if bcrypt.checkpw(password.encode(), stored_password.encode()):
            print("✅ Login successful!")
            logging.info("✅ Login successful!")
            return True  

        print("❌ Incorrect password!")
        logging.warning("❌ Incorrect password!")
        return False  
    

import sys
def excepthook(exc_type, exc_value, exc_traceback):
    print("Uncaught exception:", exc_value)

sys.excepthook = excepthook

if __name__ == "__main__":
    print("🔐 SecureScan Login Debug Mode\n")
    
    login_logic = LoginLogic()

    username = input("👤 Enter username: ")
    password = input("🔒 Enter password: ")

    is_valid = login_logic.verify_user_credentials(username, password)

    if is_valid:
        print("✅ Login successful! Welcome,", username)
    else:
        print("❌ Invalid credentials. Please try again.")

