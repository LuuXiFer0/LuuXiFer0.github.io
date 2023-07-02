
import sqlite3, re
import pyotp
import json
import base64
from datetime import datetime, timedelta

def execute_sql_query(database, query, data):
    conn = sqlite3.connect(database)
    conn.set_trace_callback(print)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute(query, data)
    
    allow_commit = ["INSERT", "UPDATE", "DELETE"]
    for i in allow_commit:
        if i in query:
            conn.commit()
    
    return c


def login(username):
    database = "db_users.sqlite"
    query = "SELECT * FROM users WHERE username = %(username)s"
    data = {
        "username": username
    }
    
    user = execute_sql_query(database, query, data).fetchone()
    if not user:
        return False

    return user['password']

def create_response(response, username):
    session_data = {'username': username}
    session_json = json.dumps(session_data).encode()
    session_encoded = base64.b64encode(session_json)

    # Set cookie with Secure and HttpOnly flags, and an appropriate expiration time
    expires = datetime.now() + timedelta(days=1)  # Set the expiration time to  days from now
    response.set_cookie('vulpy_session', session_encoded, secure=True, httponly=True, expires=expires)

    return response

def password_change(username, password):
    database = "db_users.sqlite"
    query = "UPDATE users SET password = %(password)s WHERE username = %(username)s"
    data = {
        "username": username,
        "password": password
    }
    
    execute_sql_query(database, query, data)
    return True

def password_complexity(password):
    # Check length
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return False

    # Check uppercase letters
    if not re.search(r"[A-Z]", password):
        print("Password must contain at least one uppercase letter.")
        return False

    # Check lowercase letters
    if not re.search(r"[a-z]", password):
        print("Password must contain at least one lowercase letter.")
        return False

    # Check digits
    if not re.search(r"\d", password):
        print("Password must contain at least one digit.")
        return False

    # Check special characters
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character.")
        return False

    # Password meets all complexity requirements
    return True

def mfa_is_enabled(username):
    database = "db_users.sqlite"
    query = "SELECT * FROM users WHERE username = %(username)s and mfa_enabled = 1"
    data = {
        "username": username
    }
    
    user = execute_sql_query(database, query, data).fetchone()
    
    if user:
        return True
    else:
        return False


def mfa_disable(username):
    database = "db_users.sqlite"
    query = "UPDATE users SET mfa_enabled = 0 WHERE username = %(username)s"
    data = {
        "username": username
    }
    
    execute_sql_query(database, query, data)
    return True


def mfa_enable(username):
    database = "db_users.sqlite"
    query = "UPDATE users SET mfa_enabled = 1 WHERE username = %(username)s"
    data = {
        "username": username
    }
    
    execute_sql_query(database, query, data)
    return True


def mfa_get_secret(username):
    database = "db_users.sqlite"
    query = "SELECT * FROM users WHERE username = %(username)s"
    data = {
        "username": username
    }
    
    user = execute_sql_query(database, query, data).fetchone()
    
    if user:
        return user['mfa_secret'] #True
    else:
        return False


def mfa_reset_secret(username):
    secret=pyotp.random_base32()
    
    database = "db_users.sqlite"
    query = "UPDATE users SET mfa_secret = %(secret)s WHERE username = %(username)s"
    data = {
        "secret": secret,
        "username": username
    }
    
    execute_sql_query(database, query, data)
    
    return False


def mfa_validate(username, otp):
    secret = mfa_get_secret(username)
    totp = pyotp.TOTP(secret)
    if secret and totp.verify(otp):
        return True
    else:
        return False