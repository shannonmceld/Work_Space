import os
from datetime import datetime
from collections import defaultdict

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # html table with all stocks owned
    # query for sum of price
    prices = db.execute(
        "SELECT SUM(price) FROM stocks WHERE user_id = ?", (session["user_id"],)
    )

    # query for user current cash balanc
    cash = db.execute("SELECT cash FROM users WHERE id =?", (session["user_id"],))

    # query for all infor joined between two tables
    rows = db.execute(
        "SELECT * FROM users JOIN stocks ON users.id = stocks.user_id WHERE users.id = ?",
        (session["user_id"],),
    )

    # query for user portfolio
    stocks = db.execute(
        "SELECT name,SUM(shares) AS shares,SUM(price) AS price FROM stocks GROUP BY name, user_id = ?",
        (session["user_id"],),
    )

    # list of price
    price = prices[0]["SUM(price)"]

    # list of cash
    cash = int(cash[0]["cash"])

    # return page GET method
    return render_template(
        "index.html",
        stocks=stocks,
        cash=cash,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # current timestamp
    date = datetime.now()
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # get form values through POST
        symbol = request.form.get("symbol")
        share = request.form.get("shares")
        id = session["user_id"]

        # Ensure symbol was submitted
        if not symbol:
            return apology("must complete form", 400)

        # Ensure share was submitted
        elif not share:
            return apology("must complete form", 400)

        # Ensure share is an integer
        elif not share.isdigit():
            return apology("must be whole number", 400)

        # cannot buy a negative amount of shares
        elif int(share) < 1:
            return apology("must be more than 0", 400)

        # ensure stock symbol actually valid
        symbol = lookup(symbol)
        if bool(symbol) == True:
            # get DICT attribute
            name = symbol.get("symbol")
            price = symbol.get("price")
            total_price = price * int(share)

            # query for all users info
            row = db.execute("SELECT * FROM users WHERE id = ?", (id,))

            # list of cash
            cash = float(row[0]["cash"])

            # Ensure user have enough cash to buy shares
            if total_price <= cash:
                # query upate cash after transaction
                db.execute(
                    "UPDATE users SET cash = cash-:total_price WHERE id = :id",
                    total_price=total_price,
                    id=id,
                )

                # query insert newly aquired shares information
                db.execute(
                    "INSERT INTO stocks (user_id, name, shares, date, price) VALUES(?, ?, ?,?,?)",
                    id,
                    name,
                    share,
                    date,
                    price,
                )

                # alert users of new purchased share
                flash(
                    f"Your {share} shares of {name} for {usd(price)}(ea.) has been purchased!"
                )

                # redirect to index
                return redirect("/")

            else:
                # return apology if not enough cash
                return apology("Sorry Not enough cash", 400)

        else:
            # return apology if symbol in not in look up function
            return apology("Invalid Stock Symbol", 400)

    else:
         # return form on buy page through GET method
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # query for user portfolio
    stocks = db.execute(
        "SELECT *, CASE WHEN shares < 0 THEN 'Sold' WHEN shares > 0 THEN 'Bought' END AS Type FROM stocks WHERE user_id = ? ORDER BY date",
        (session["user_id"],),
    )
    return render_template("history.html", stocks=stocks)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change Password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        password = request.form.get("password")
        verify_password = request.form.get("verify_password")
        id = session["user_id"]

        # Ensure password was submitted
        if not password:
            return render_template("password.html", flash(f"Must provide password!"))

        # Ensure password was submitted
        elif not verify_password:
            return render_template("password.html", flash(f"Must provide password!"))

        # ensure password match
        elif password != verify_password:
            return render_template("password.html", flash(f"Password must Match!"))

        # create a hash for the password
        hash_password = generate_password_hash(password)

        # Edit password in table
        db.execute(
            "Update users SET hash = :hash_password WHERE id = :id",
            hash_password=hash_password,
            id=id,
        )

        # alert users of new password
        flash(f"Your Password has been changed!")

        # redirect to index
        return redirect("/")

    else:
        # Redirect user to login form
        return render_template("password.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # return name price and symbol
        quotes = lookup(symbol)

        if not symbol:
            # return apology for invalid symbol
            return apology("Add symbol", 400)

        # if lookup return something
        elif bool(quotes) == True:
            # return values to the quoted template
            return render_template("quoted.html", quotes=quotes)

        else:
            # return apology for invalid symbol
            return apology("no such symbol", 400)

    else:
        # return form GET method
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")
        username = request.form.get("username")
        checkusername = db.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
        )

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure confirm_password was submitted
        elif not confirm_password:
            return apology("must confirm password", 400)

        # Ensure password match confirm_password
        elif password != confirm_password:
            return apology("passwords must match", 400)

        # Ensure username isn't taken
        elif bool(checkusername) == True:
            return apology("Username is taken", 400)

        # create a hash for the password
        hash_password = generate_password_hash(password)

        # Put username and password in table
        db.execute(
            "INSERT INTO users (username, hash) VALUES(?,?)", username, hash_password
        )
        user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,))

        # log in user after registration
        session["user_id"] = user_id[0]["id"]

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    date = datetime.now()
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # get submitted shares from form
        shares = request.form.get("shares")

        # get submitted symbol from form
        symbol = request.form.get("symbol").upper()

        stocks = lookup(symbol)
        id = session["user_id"]

        # Ensure symbol is submitted
        if not symbol:
            return apology("must complete form missing symbol", 400)

        # Ensure shares is submitted
        elif not shares:
            return apology("must complete form missing share", 400)

        # Ensure share is an integer
        elif not shares.isdigit():
            return apology("must be whole number", 400)

        # Ensure no negative amount of shares
        elif int(shares) < 1:
            return apology("must be more than 0", 400)

        # query to get shares
        get_share = db.execute(
            "SELECT shares FROM stocks WHERE name = :symbol AND user_id = :id",
            symbol=symbol,
            id=id,
        )

        # query to get price
        get_price = db.execute(
            "SELECT price FROM stocks WHERE name = :symbol AND user_id = :id",
            symbol=symbol,
            id=id,
        )

        # query to get all columns in table
        row = db.execute("SELECT * FROM users WHERE id = ?", (id,))

        # list for cash
        cash = float(row[0]["cash"])

        # list for price
        price = get_price[0]["price"]

        # list for shares
        cshare = get_share[0]["shares"]

        # total price for all shares
        total_price = (int(shares) * int(price))

        # has number of shares to sell
        if int(shares) > int(cshare):
            return apology("not enough shares", 400)
        else:
            # query to upate cash after transaction
            db.execute(
                "UPDATE users SET cash = cash + :price WHERE id = :id",
                price=price,
                id=id,
            )

            # query to insert sold shares
            db.execute(
                "INSERT INTO stocks (user_id, name, shares, date, price) VALUES(?, ?, ?,?,?)",
                id,
                symbol,
                -(int(shares)),
                date,
                price,
            )

            # Alert to inform user of symbol sold
            flash(
                f"Your {shares} shares of {symbol} for {usd(total_price)} has been sold!"
            )

            # redirect to index
            return redirect("/")
    else:
        # query to get informatin from table using GET method
        stocks = db.execute(
            "SELECT name,SUM(shares) AS shares,SUM(price) AS price FROM stocks GROUP BY name, user_id = ?",
            (session["user_id"],),
        )

        # return current page for form
        return render_template("sell.html", stocks=stocks)
