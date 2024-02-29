from flask import Blueprint, request, flash, render_template, redirect, url_for, session
from .models import User, PasswordHistory
from datetime import datetime, timedelta
from flask_mail import Message, Mail
from . import mysql, passwordCheck
import MySQLdb.cursors
import hashlib
import random

MAX_LOGIN_ATTEMPTS = 3  # Max num of login attempts before blocking user.
BLOCK_DURATION = 1  # Minutes of user being blocked.
mail = Mail()
auth = Blueprint('auth', __name__)


# Get user full detail according to it's email.
def get_user_from_email_and_password(email, password):
    try:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}' LIMIT 1;")
        user = cur.fetchone()
        return user
    except Exception as e:
        flash(f"An error occurred: {e}", category='error')


# Login function:
# verifies the user's details,
# blocks user if enter 3 incorrect passwords.
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = get_user_from_unique_key(email)
        if user:
            if get_user_from_email_and_password(email, password):  # Checks if the user exists according to email.
                # Checks if the user blocked after 3 attempts and still on 1 ,minute block.
                if user['is_blocked']:
                    if user['block_expiration'] > datetime.utcnow():
                        flash('Account is temporarily blocked. Please try again later.', category='error')
                        return redirect(url_for('auth.login'))
                    else:
                        handle_failed_login_over(user)
                else:
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
                new_user = User(email=email, password=password1, first_name=first_name)
                new_user.add_new_user()
                PasswordHistory.save_password_history(get_user_from_unique_key(email)['id'], password1)
                session['email'] = email
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
    return render_template("sign_up.html", logged_in=False)


# Get user full detail according to it's email.
def get_user_from_unique_key(email):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(f"SELECT * FROM users WHERE email = '{email}' LIMIT 1;")
        user = cur.fetchone()
        return user
    except Exception as e:
        flash(f"An error occurred: {e}", category='error')


# If the user enters correct mail but incorrect password:
# add up the number of times it happens.
# if the number of times it happened is 3 block the user for 1 minute.
def handle_failed_login(user):
    if user:
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
    if user:
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


# Forgot password function:
# generate random,
# send it via email,
# store the code in the session or database for verification later.
@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        session['email'] = None
        email = request.form.get('email')
        user = get_user_from_unique_key(email)
        if user:
            code = generate_random_code()
            send_reset_code_email(email, code)
            session['reset_code_hash'] = hashlib.sha1(code.encode()).hexdigest()
            flash('A code has been sent to your email. Please check your inbox.', category='success')
            return redirect(url_for('auth.verify_code_from_mail', email=email))
        else:
            flash('Email does not exist.', category='error')
    return render_template("forgot_password.html", logged_in=False)


# Verify code from mail function.
@auth.route('/verify_code_from_mail', methods=['GET', 'POST'])
def verify_code_from_mail():
    email = request.args.get('email')
    if request.method == 'POST':
        code = request.form.get('code')
        if verify_code(code):
            return redirect(url_for('auth.reset_password', email=email))
        else:
            flash('Invalid code. Please try again.', category='error')
    return render_template("code_input.html", logged_in=False)


# Reset password function:
# after entering correct code from email go to the reset password screen.
# entering new password that will be saved in the db after hashing.
@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.args.get('email')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        user = get_user_from_unique_key(email)
        if user:
            if new_password != confirm_password:
                flash('Passwords do not match.', category='error')
            else:
                if passwordCheck.main_check(user, new_password):
                    change_password(email, user, new_password)
                    flash('Password changed successfully!', category='success')
                    return redirect(url_for('auth.login'))
        else:
            flash('Email does not exist.', category='error')
    return render_template("reset_password.html", logged_in=False)


# Generate a random code using SHA-1 for email.
def generate_random_code():
    random_code = str(random.randint(10000, 99999))
    hashed_code = hashlib.sha1(random_code.encode()).hexdigest()
    return hashed_code


# Send code to email.
def send_reset_code_email(email, code):
    msg = Message('Reset Your Password', recipients=[email])
    msg.body = f'Your reset password code is: {code}'
    mail.send(msg)


# Check that the code the user entered is the same as the one was sent to it's mail.
def verify_code(code):
    stored_code_hash = session.get('reset_code_hash')
    if stored_code_hash:
        # Filter the VerificationCode model by user_id and code
        entered_code_hash = hashlib.sha1(code.encode()).hexdigest()
        if entered_code_hash == stored_code_hash:
            return True
    return False


# Changing password in db and parameter.
def change_password(email, user, new_password):
    user['password'] = new_password
    PasswordHistory.save_password_history(get_user_from_unique_key(email)['id'], new_password)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET password = %s WHERE email = %s;", (user['password'], user['email']))
    mysql.connection.commit()
    cur.close()
