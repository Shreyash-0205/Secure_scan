import bcrypt

def encrypt_password(password: str) -> str:
    """Encrypts a password using bcrypt."""
    salt = bcrypt.gensalt()  # Generate a salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)  # Hash the password
    return hashed_password.decode()  # Return as a string

def check_password(password: str, hashed_password: str) -> bool:
    """Checks if the entered password matches the stored hashed password."""
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Example usage
if __name__ == "__main__":
    user_password = input("Enter a password to encrypt: ")
    encrypted_password = encrypt_password(user_password)
    print(f"Encrypted Password: {encrypted_password}")

    # Verify password
    verify_password = input("Re-enter password to verify: ")
    if check_password(verify_password, encrypted_password):
        print("Password match!")
    else:
        print("Password does not match!")
