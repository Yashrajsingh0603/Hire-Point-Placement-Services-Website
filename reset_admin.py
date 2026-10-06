from database import get_db_connection
from werkzeug.security import generate_password_hash

new_password = "HireHub@123"

connection = get_db_connection()
cursor = connection.cursor()

password_hash = generate_password_hash(new_password)

cursor.execute("""
    UPDATE users
    SET password_hash = %s
    WHERE id = 1
""", (password_hash,))

connection.commit()

cursor.close()
connection.close()

print("Admin password reset successfully!")
print("Email: yashrajsingh@test.com")
print("Password: HireHub@123")