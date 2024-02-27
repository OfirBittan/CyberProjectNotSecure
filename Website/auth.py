from flask import Blueprint, request, flash, render_template, redirect, url_for, session
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
from . import mysql, passwordCheck
from .models import User
import MySQLdb.cursors
import os

MAX_LOGIN_ATTEMPTS = 3  # Max num of login attempts before blocking user.
BLOCK_DURATION = 1  # Minutes of user being blocked.
auth = Blueprint('auth', __name__)


# Login function:
# verifies the user's details,
# blocks user if enter 3 incorrect passwords.
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = get_user_from_unique_key(email)
        if user:  # Checks if the user exists according to email.
            # Checks if the user blocked after 3 attempts and still on 1 ,minute block.
            if user['is_blocked']:
                if user['block_expiration'] > datetime.utcnow():
                    flash('Account is temporarily blocked. Please try again later.', category='error')
                    return redirect(url_for('auth.login'))
                else:
                    handle_failed_login_over(user)
            if verify_password(password, user['password']):  # Checks if the password is correct.
                flash('Logged in successfully!', category='success')
                session['email'] = email
                return redirect(url_for('views.home'))
            else:
                handle_failed_login(user)
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", logged_in=False)


# Sign up function:
# checking email, first name, password.
# if it passes the checks we add a new user to db.
@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = get_user_from_unique_key(email)
        if user:
            flash('Email already exists.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        else:
            if passwordCheck.main_check(None, password1):
                hashed_password = generate_password_hash(password1)
                new_user = User(email=email, password=hashed_password, first_name=first_name)
                new_user.add_new_user()
                session['email'] = email
                # Add to table Password history the first password created.
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
    return render_template("sign_up.html", logged_in=False)


# Password hash generating.
def generate_password_hash(password):
    salt = os.urandom(16)
    return pbkdf2_sha256.using(salt=salt, rounds=1000).hash(password)


# Password verifying with hash in log in.
def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)


# Get user full detail according to it's email.
def get_user_from_unique_key(email):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(f"SELECT * FROM users WHERE email = '{email}' LIMIT 1;")
    user = cur.fetchone()
    print(user)
    return user


# If the user enters correct mail but incorrect password:
# add up the number of times it happens.
# if the number of times it happened is 3 block the user for 1 minute.
def handle_failed_login(user):
    user['login_attempts'] += 1
    user['last_failed_attempt'] = datetime.utcnow()
    if user['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
        user['is_blocked'] = True
        user['block_expiration'] = datetime.utcnow() + timedelta(minutes=BLOCK_DURATION)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET login_attempts = %s, last_failed_attempt = %s, is_blocked = %s, "
                "block_expiration = %s WHERE email = %s",
                (user['login_attempts'], user['last_failed_attempt'], user['is_blocked'],
                 user['block_expiration'], user['email']))
    mysql.connection.commit()
    cur.close()


# After 1 minute of user being blocked we release it blockage.
def handle_failed_login_over(user):
    user['login_attempts'] = 0
    user['last_failed_attempt'] = None
    user['is_blocked'] = False
    user['block_expiration'] = None
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET login_attempts = %s, last_failed_attempt = %s, is_blocked = %s, "
                "block_expiration = %s WHERE email = %s",
                (user['login_attempts'], user['last_failed_attempt'], user['is_blocked'],
                 user['block_expiration'], user['email']))
    mysql.connection.commit()
    cur.close()
