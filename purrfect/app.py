import os
import sqlite3
import click
from flask import Flask, flash, redirect, render_template, request, session, current_app, g
from flask.cli import with_appcontext
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'purrfect.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Ensure templates are auto-reloaded
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Ensure responses aren't cached
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

    # Configure session to use filesystem (instead of signed cookies)
    #app.config["SESSION_FILE_DIR"] = mkdtemp()
    #app.config["SESSION_PERMANENT"] = False
    #app.config["SESSION_TYPE"] = "filesystem"
    #session(app)

    # Database definition
    def get_db():
        if 'db' not in g:
            g.db = sqlite3.connect(
                current_app.config['DATABASE'],
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            g.db.row_factory = sqlite3.Row

        return g.db

    def close_db(e=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    def init_db():
        db = get_db()
        with current_app.open_resource('schema.sql') as f:
            db.executescript(f.read().decode('utf8'))

    @click.command('init-db')
    @with_appcontext
    def init_db_command():
        """Clear the existing data and create new tables."""
        init_db()
        click.echo('Initialized the database.')

    def init_app(app):
        app.teardown_appcontext(close_db)
        app.cli.add_command(init_db_command)


    # Define routes
    @app.route("/")
    def index():
        return render_template("purrfect.html")

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
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                              username=request.form.get("username"))

            # Ensure username exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
                return apology("invalid username and/or password", 403)

            # Remember which user has logged in
            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return render_template("home.html")

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

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """Register user"""
        if request.method == "POST":
            if not request.form.get("username"):
                return apology("must provide username", 400)
            elif not request.form.get("password"):
                return apology("must provide password", 400)
            elif request.form.get("password") != request.form.get("confirmation"):
                return apology("passwords don't match!", 400)
            # Put username into database. If unsuccessful, return apology (user already exists).
            result = db.execute("INSERT INTO users (username, password) VALUES(:username, :password)",
                            username=request.form.get("username"),
                            password=generate_password_hash(request.form.get("password")))
            if not result:
                return apology("username already taken", 400)
            # Set session id
            session["user_id"] = result
            return render_template("home.html")
        else:
            return render_template("register.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/home")
    @login_required
    def home():
        return render_template("home.html")

    def errorhandler(e):
        """Handle error"""
        return apology(e.name, e.code)

    # listen for errors
    for code in default_exceptions:
        app.errorhandler(code)(errorhandler)

    return app
