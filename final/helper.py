from functools import wraps
from flask import redirect, session
from Crypto.Cipher import AES
import os
from dotenv import load_dotenv
from pathlib import Path
import re
from string import punctuation, whitespace


load_dotenv()

dotenv_path = Path("/workspaces/133610449/vault.env")
load_dotenv(dotenv_path=dotenv_path)

# 256-bit encryption key
secret_key = os.getenv("PASSWORD_API_KEY")


def validate(password):
    password = password.strip()
    digit = re.search("[0-9]", password)
    lower = re.search("[a-z]", password)
    upper = re.search("[A-Z]", password)
    valid_special_char = re.search(
        "['!', '$', '%', '#', '&', '(', ')', '-', '_', '?']", password
    )
    if len(password) <= 7:
        return False
    elif bool(digit) == False:
        return False
    elif bool(lower) == False:
        return False
    elif bool(upper) == False:
        return False
    elif bool(valid_special_char) == False:
        return False
    special_char = {"!", "$", "%", "#", "&", "(", ")", "-", "_", "?"}
    invalid_special_char = set(punctuation + whitespace) - special_char
    for i in invalid_special_char:
        if i in password:
            return False


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function
