from flask import Blueprint, render_template, session, redirect, url_for, request, flash
from .models import Customers
from . import mysql
import datetime

views = Blueprint('views', __name__)


# Start page function:
@views.route('/')
def start():
    return render_template('start.html', logged_in=False)


# Logout.
@views.route('/logout')
def logout():
    session['email'] = None
    return redirect(url_for('auth.login'))


# Home page function:
@views.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html', logged_in=True)


# Add customer page function:
# gets email (unique) and customer name.
@views.route('/customer_add', methods=['GET', 'POST'])
def add_customer():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        customer = get_customer_from_unique_key(email)
        if customer:
            flash('Email already exists.', category='error')
        else:
            new_customer = Customers(email=email, first_name=first_name, date=datetime.datetime.now())
            new_customer.add_new_customer()
            flash(f'Added customer {new_customer.first_name}', category='success')
            return redirect(url_for('views.home'))
    return render_template('customer_add.html', logged_in=True)


# Get customer full detail according to it's email.
def get_customer_from_unique_key(email):
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM customers WHERE email = '{email}' LIMIT 1;")
    customer = cur.fetchone()
    return customer


# Get customer list page function:
@views.route('/customers_list', methods=['GET', 'POST'])
def customers_list():
    return render_template('customers_list.html', logged_in=True, all_customers=get_all_customers())


# Get all customers list.
def get_all_customers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT first_name FROM Customers;")
    first_names = cur.fetchall()
    cur.close()
    return [row[0] for row in first_names]


# Search customer page function:
# gets customer name.
@views.route('/customer_search', methods=['GET', 'POST'])
def search_customer():
    if request.method == 'POST':
        first_name = request.form.get('firstName')
        customer = get_customer_from_first_name(first_name)
        return render_template('customer_search.html', logged_in=True, customer=customer)
    return render_template('customer_search.html', logged_in=True, customer=None)


# Get customer name if exists.
def get_customer_from_first_name(first_name):
    try:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM Customers WHERE BINARY first_name = '{first_name}';")
        customers = cur.fetchall()
        cur.close()
        return customers
    except Exception as e:
        flash(f"An error occurred: {e}", category='error')
