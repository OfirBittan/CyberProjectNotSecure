from flask import Blueprint, request, flash, render_template, redirect, url_for, session
from passlib.hash import pbkdf2_sha256
from . import mysql, passwordCheck
from .models import User
import MySQLdb.cursors
import os

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = get_user_from_unique_key(email)
        if user:
            if verify_password(password, user['password']):
                session['email'] = email
                flash('Logged in successfully!', category='success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", logged_in=False)


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
                print(session['email'])
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
    return render_template("sign_up.html", logged_in=False)


def generate_password_hash(password):
    salt = os.urandom(16)
    return pbkdf2_sha256.using(salt=salt, rounds=1000).hash(password)


def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)


def get_user_from_unique_key(email):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(f"SELECT * FROM users WHERE email = '{email}' LIMIT 1;")
    user = cur.fetchone()
    print(user)
    return user
