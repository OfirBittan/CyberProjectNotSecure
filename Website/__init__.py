# Imports.
from flask import Flask
from flask_mysqldb import MySQL
from flask_mail import Mail
from flask_session import Session

app = Flask(__name__)
mysql = MySQL(app)
DATA_BASE_NAME = 'projectDB'


def create_customers_table():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS Customers ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "email VARCHAR(150) UNIQUE, "
                    "first_name VARCHAR(150), "
                    "date DATETIME)"
                    )
        mysql.connection.commit()
        cur.close()


def create_password_history_table():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS password_history ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "user_id INT NOT NULL, "
                    "password VARCHAR(100) NOT NULL, "
                    "timestamp DATETIME NOT NULL, "
                    "FOREIGN KEY (user_id) REFERENCES users(id))"
                    )
        mysql.connection.commit()
        cur.close()


def create_users_table():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users ("
                    "id INT AUTO_INCREMENT PRIMARY KEY, "
                    "email VARCHAR(150) UNIQUE, "
                    "password VARCHAR(150), "
                    "first_name VARCHAR(150), "
                    "login_attempts INT DEFAULT 0, "
                    "last_failed_attempt DATETIME, "
                    "is_blocked BOOLEAN DEFAULT FALSE, "
                    "block_expiration DATETIME)"
                    )
        mysql.connection.commit()
        cur.close()


def create_database():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {DATA_BASE_NAME};")
        mysql.connection.commit()
        cur.close()


def create_app():
    # Init app with Flask library.
    app.secret_key = 'hjshjhdjah kjshkjdhjs'
    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'your user'  # changed it
    app.config['MYSQL_PASSWORD'] = 'your password'  # changed it
    create_database()  # create DB in MySQL
    app.config['MYSQL_DB'] = DATA_BASE_NAME

    # Init Flask-Mail to send random value for forgot password
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'verizzonmand2@gmail.com'
    app.config['MAIL_PASSWORD'] = 'hidb cigz wsco wlth'
    app.config['MAIL_DEFAULT_SENDER'] = 'verizzonmand2@gmail.com'

    # Init Flask-Mail with the Flask app.
    mail = Mail()
    mail.init_app(app)

    # Init flask session
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    # Create table user in db
    create_users_table()
    create_password_history_table()
    create_customers_table()

    return app
