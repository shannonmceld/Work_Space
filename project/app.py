import bcrypt, codecs, secrets
from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from helper import login_required, secret_key, validate
from flask_session import Session
from email_validator import validate_email
from AesEverywhere import aes256
from string import ascii_letters, digits


# Configure application
app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///accounts.db")


# app name
@app.errorhandler(404)
# inbuilt function which takes error as parameter
def not_found(e):
    # defining function
    return render_template("404.html")

@app.errorhandler(500)
# inbuilt function which takes error as parameter
def not_found(e):
    # defining function
    return render_template("500.html")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    id = session["user_id"]
    # query for user profiles
    profiles = db.execute(
        "SELECT * FROM profiles WHERE profile_id = ?",
        id,
    )

    return render_template("index.html", profiles=profiles)


@app.route("/detail", methods=["GET", "POST"])
@login_required
def detail():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        url = request.form.get("url")
        username = request.form.get("username")
        id = session["user_id"]
        # query for profile details
        details = db.execute(
            "SELECT * FROM details WHERE detail_id = :id AND url = :url And username = :username",
            id=id,
            url=url,
            username=username,
        )

        key = details[0]["key"]
        # decrypt password
        decrypt = aes256.decrypt(key, secret_key)
        # turn the bytes back to a string
        decrypt = codecs.decode(decrypt)
        return render_template("detail.html", details=details, decrypt=decrypt)
    else:
        return render_template("detail.html")


@app.route("/update", methods=["GET", "POST"])
@login_required
def update():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("email").lower()
        username = request.form.get("username").lower()
        url = request.form.get("website").lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        id = session["user_id"]

        # Ensure password was submitted
        if not password:
            flash(f"Must have Password!")
            return render_template("update.html")

        # Ensure confirm_password was submitted
        elif not confirm_password:
            flash(f"Must Confirm Password!")
            return render_template("update.html")

        # Ensure password match confirm_password
        elif password != confirm_password:
            flash(f"Passwords Do NOT Match!")
            return render_template("update.html")

        # encryptying password
        key = aes256.encrypt(password, secret_key)

        # query to update password
        update = db.execute(
            "Update details SET key = :key WHERE email = :email AND username = :username AND url = :url AND detail_id = :id",
            email=email,
            username=username,
            key=key,
            url=url,
            id=id,
        )

        # if query come back empty
        if bool(update) == False:
            flash(f"Information was Incorrect!")
            return render_template("update.html")

        # alert users of new password
        flash(f"Your Password has been Updated!")

        # redirect to index
        return redirect("/")

    else:
        return render_template("update.html")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        id = session["user_id"]
        url = request.form.get("url")
        username = request.form.get("username")

        # query to delete profile from the profile table
        db.execute(
            "DELETE FROM profiles WHERE profile_id = :id AND url = :url AND username = :username",
            id=id,
            url=url,
            username=username,
        )
        # query to delete details from the detail table
        db.execute(
            "DELETE FROM details WHERE detail_id = :id AND url = :url AND username = :username",
            id=id,
            url=url,
            username=username,
        )
        return render_template("index.html")

    else:
        return render_template("index.html")


@app.route("/generate", methods=["GET", "POST"])
def generate():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        letters = ascii_letters
        word = letters + digits
        password = ""
        # loop to join each random character
        for i in range(8, 20):
            password += "".join(secrets.choice(word))
        # user post form with no symbol generator
        if request.form["nosymbol"] == "nosymbol":
            flash(f"Your Password is {password}")
            return render_template("generate.html")
        else:
            return render_template("generate.html")
    else:
        return render_template("generate.html")


@app.route("/generatesymbol", methods=["GET", "POST"])
def generatesymbol():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        letters = ascii_letters
        symbol_word = (
            letters + digits + "!" + "$" + "%" + "#" + "&" + "(" + ")" + "-" + "_" + "?"
        )
        password_symbol = ""
        # loop to join each random character
        for i in range(8, 20):
            password_symbol += "".join(secrets.choice(symbol_word))
        # user post form with no symbol generator
        if request.form["symbol"] == "symbol":
            flash(f"Your Password is {password_symbol}")
            return render_template("generate.html")
        else:
            return render_template("generate.html")
    else:
        return render_template("generate.html")


@app.route("/forgot_username", methods=["GET", "POST"])
def forgot_username():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("email").lower()

        # Ensure email was submitted
        if not email:
            flash(f"Must Have Email")
            return render_template("forgot_username.html")

        # query for username in acoounts
        accounts = db.execute(
            "SELECT username FROM accounts WHERE email = ?",
            email,
        )

        # make sure the correct account was querried
        if len(accounts) != 1:
            flash(f"No such EMAIL!")
            return render_template("forgot_username.html")

        # Ensure correct username was querried
        elif bool(accounts[0]["username"]) == False:
            flash(f"No such EMAIL!")
            return render_template("forgot_username.html")
        else:
            flash(f"Your username is {accounts[0]['username']}!")
            return render_template("forgot_username.html", accounts=accounts)

    else:
        return render_template("forgot_username.html")


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        email = request.form.get("email").lower()
        username = request.form.get("username").lower()
        phone_number = request.form.get("phone_number").lower()
        password = request.form.get("password")
        verify_password = request.form.get("confirmation")

        # Ensure email was submitted
        if not username:
            flash(f"Must Have usename")
            return render_template("forgot_password.html")

        # Ensure email was submitted
        elif not email:
            flash(f"Must Have Email")
            return render_template("forgot_password.html")
        # Ensure email was submitted
        elif not phone_number:
            flash(f"Must Have phonenumber")
            return render_template("forgot_password.html")

        # Ensure password was submitted
        elif not password:
            flash(f"Must provide password!")
            return render_template("forgot_password.html")

        # Ensure password was submitted
        elif not verify_password:
            flash(f"Must verify password!")
            return render_template("forgot_password.html")

        # query all account information
        accounts = db.execute(
            "SELECT * FROM accounts WHERE email = :email AND username = :username AND phone = :phone_number",
            email=email,
            username=username,
            phone_number=phone_number
        )

        # Ensure Query returned
        if len(accounts) != 1:
            flash(f"Information does not match!")
            return render_template("forgot_password.html")

        # ensure password match
        elif password != verify_password:
            flash(f"Password must Match!")
            return render_template("forgot_password.html")

        # ensure password is correct pattern
        elif validate(password) == False:
            flash(
                f"Password Not VALID. Password should contain a Uppercase, a Lowercase, a Digit and a Special Character"
            )
            return render_template("forgot_password.html")

        # converting password to array of bytes
        bytes = password.encode("utf-8")

        # generating the salt
        salt = bcrypt.gensalt()

        # Hashing the password
        hash_password = bcrypt.hashpw(bytes, salt)

        # Edit password in table
        db.execute(
            "Update accounts SET hash = :hash_password WHERE email = :email",
            hash_password=hash_password,
            email=email,
        )

        # alert users of new password
        flash(f"Your Password has been changed!")

        # redirect to index
        return redirect("/")

    else:
        return render_template("forgot_password.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        password = request.form.get("password")
        verify_password = request.form.get("verify_password")
        id = session["user_id"]

        # Ensure password was submitted
        if not password:
            flash(f"Must provide password!")
            return render_template("change.html")

        # Ensure password was submitted
        elif not verify_password:
            flash(f"Must provide password!")
            return render_template("change.html")

        # ensure password match
        elif password != verify_password:
            flash(f"Password must Match!")
            return render_template("change.html")

        # Ensure passord match pattern
        elif validate(password) == False:
            flash(
                f"Password Not VALID. Password should contain a Uppercase, a Lowercase, a Digit and a Special Character"
            )
            return render_template("reigister.html")

        # converting password to array of bytes
        bytes = password.encode("utf-8")

        # generating the salt
        salt = bcrypt.gensalt()

        # Hashing the password
        hash_password = bcrypt.hashpw(bytes, salt)

        # Edit password in table
        db.execute(
            "Update accounts SET hash = :hash_password WHERE id = :id",
            hash_password=hash_password,
            id=id,
        )

        # alert users of new password
        flash(f"Your Password has been changed!")

        # redirect to index
        return redirect("/")

    else:
        # Redirect user to login form
        return render_template("change.html")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        date = datetime.now()
        username = request.form.get("username").lower()
        email = request.form.get("email").lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        url = request.form.get("website").lower()

        # Ensure username was submitted
        if not username:
            flash(f"Must have Username!")
            return render_template("add.html")

        # Ensure email was submitted
        if not email:
            flash(f"Must have Email!")
            return render_template("add.html")

        # Ensure password was submitted
        elif not password:
            flash(f"Must have Password!")
            return render_template("add.html")

        # Ensure confirm_password was submitted
        elif not confirm_password:
            flash(f"Must Confirm Password!")
            return render_template("add.html")

        # Ensure password match confirm_password
        elif password != confirm_password:
            flash(f"Passwords Do NOT Match!")
            return render_template("add.html")

        # encryptying password
        key = aes256.encrypt(password, secret_key)

        # insert new profile
        db.execute(
            "INSERT INTO profiles (profile_id, url, username) VALUES(?,?,?)",
            session["user_id"],
            url,
            username,
        )

        # insert profile new details
        db.execute(
            "INSERT INTO details (detail_id, email, date, username, key, url) VALUES(?,?,?,?,?,?)",
            session["user_id"],
            email,
            date,
            username,
            key,
            url,
        )
        return redirect("/")

    else:
        return render_template("add.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username").lower()
        email = request.form.get("email").lower()
        phone_number = request.form.get("phone_number")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        # Ensure username was submitted
        if not username:
            flash(f"Must have Username!")
            return render_template("register.html")

        # Ensure email was submitted
        if not email:
            flash(f"Must have Email!")
            return render_template("register.html")

        # Ensure phone number was submitted
        if not phone_number:
            flash(f"Must have Phone Number!")
            return render_template("register.html")

        # Ensure password was submitted
        elif not password:
            flash(f"Must Have Password!")
            return render_template("register.html")

        # Ensure confirm_password was submitted
        elif not confirm_password:
            flash(f"Must Confirm Password!")
            return render_template("register.html")

        # Ensure password match confirm_password
        elif password != confirm_password:
            flash(f"Passwords Do NOT Match!")
            return render_template("register.html")

        val_email = validate_email(email, check_deliverability=False)

        # #ensure email is valid
        if bool(val_email) == False:
            flash(f"Not a valid email!")
            return render_template("register.html")

        email = val_email.normalized
        # query username from accounts
        checkusername = db.execute(
            "SELECT username FROM accounts WHERE username = ?",
            username,
        )
        # query email from table
        checkemail = db.execute(
            "SELECT email FROM accounts WHERE email = ?",
            email,
        )
        # query number from table
        checkphonenum = db.execute(
            "SELECT phone FROM accounts WHERE phone = ?",
            phone_number,
        )

        # Ensure username isn't taken
        if len(checkusername) == 1:
            flash(f"Username is Already Registered!")
            return render_template("register.html")

        # Ensure username isn't taken
        elif len(checkemail) == 1:
            flash(f"Email is Already Registered!")
            return render_template("register.html")

        # Ensure username isn't taken
        elif len(checkphonenum) == 1:
            flash(f"Phone Number is Already Registered!")
            return render_template("register.html")

        # Ensure passord math pattern
        elif validate(password) == False:
            flash(
                f"Password Not VALID. Password should contain a Uppercase, a Lowercase, a Digit and a Special Character"
            )
            return render_template("reigister.html")

        # converting password to array of bytes
        bytes = password.encode("utf-8")

        # generating the salt
        salt = bcrypt.gensalt()

        # Hashing the password
        hash_password = bcrypt.hashpw(bytes, salt)

        # Put username and password in table
        db.execute(
            "INSERT INTO accounts (username, email, phone, hash) VALUES(?,?,?,?)",
            username,
            email,
            phone_number,
            hash_password,
        )

        # query assign user_id
        user_id = db.execute("SELECT id FROM accounts WHERE username = ?", (username,))

        # log in user after registration
        session["user_id"] = user_id[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username").lower():
            flash(f"Must provide username!")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash(f"Must provide password!")
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM accounts WHERE username = ?",
            request.form.get("username").lower(),
        )

        check_password = request.form.get("password")

        # ensure user typed correct password
        if len(rows) != 1:
            flash(f"Password Not Valid")
            return render_template("login.html")

        password = rows[0]["hash"]

        # converting password to array of bytes
        bytes = check_password.encode("utf-8")

        # generating the salt
        salt = bcrypt.gensalt()

        # Hashing the password
        hash = bcrypt.hashpw(bytes, salt)

        # checking password
        result = bcrypt.checkpw(password, hash)
        # Ensure username exists and password is correct
        if len(rows) != 1 or bool(bytes == False):
            flash(f"Wrong username or password!")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
