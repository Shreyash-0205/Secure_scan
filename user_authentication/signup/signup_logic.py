import re
import bcrypt
import logging
from Database.db_connection import DatabaseConnection

# Configure logging
logging.basicConfig(level=logging.INFO)

class SignupLogic:

    def __init__(self):
        self.db = DatabaseConnection()

    def is_strong_password(self, password):
        """Checks whether the password meets the standard security rules."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, ""

    def register_user(self, username, email, password, confirm_password):
        """Registers a new user with email and hashed password after confirmation."""
        print("🚀 Function register_user started!")

        if not username or not password or not email:
            print("⚠️ Username, email, or password is empty!")
            logging.warning("⚠️ Username, email, or password is empty!")
            return False, "Username, email, or password cannot be empty."

        if password != confirm_password:
            print("⚠️ Password and Confirm Password do not match!")
            logging.warning("⚠️ Password and Confirm Password do not match!")
            return False, "Passwords do not match."

        # Check password strength
        is_valid, message = self.is_strong_password(password)
        if not is_valid:
            print(f"⚠️ {message}")
            logging.warning(f"⚠️ Weak password: {message}")
            return False, message

        try:
            if not self.db.connect():
                print("❌ Database connection failed!")
                logging.error("❌ Database connection failed!")
                return False, "Database connection failed."
        except Exception as e:
            print(f"💥 Exception while connecting to DB: {e}")
            logging.error(f"❌ DB Connect Exception: {e}")
            return False, f"Error connecting to database: {e}"

        try:
            print("🔍 Checking if user already exists...")
            result = self.db.fetch_all("SELECT * FROM login WHERE username = %s OR email = %s", (username, email))
            if result:
                print("⚠️ Username or email already exists!")
                logging.warning("⚠️ Username or email already exists!")
                return False, "Username or email already exists."
        except Exception as e:
            print(f"💥 Database error: {e}")
            logging.error(f"❌ Database error: {e}")
            return False, f"Database error: {e}"

        try:
            print("🔐 Hashing password...")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        except Exception as e:
            print(f"💥 Password hashing error: {e}")
            logging.error(f"❌ Password hashing error: {e}")
            return False, f"Error hashing password: {e}"

        try:
            print("📤 Inserting new user into database...")
            self.db.execute_query(
                "INSERT INTO login (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password.decode())
            )
            print("✅ User registered successfully!")
            logging.info("✅ User registered successfully!")
            return True, ""
        except Exception as e:
            print(f"💥 Error inserting user: {e}")
            logging.error(f"❌ Insert error: {e}")
            return False, f"Error inserting user: {e}"
        finally:
            self.db.close()


# Test script for debugging
import sys
def excepthook(exc_type, exc_value, exc_traceback):
    print("Uncaught exception:", exc_value)

sys.excepthook = excepthook

if __name__ == "__main__":
    print("📝 SecureScan Signup Debug Mode\n")

    signup_logic = SignupLogic()

    username = input("👤 Enter new username: ")
    email = input("📧 Enter email: ")
    password = input("🔒 Enter new password: ")
    confirm_password = input("🔒 Confirm password: ")

    is_registered = signup_logic.register_user(username, email, password, confirm_password)

    if is_registered:
        print("🎉 Signup successful! You can now login.")
    else:
        print("❌ Signup failed. Please try again.")


