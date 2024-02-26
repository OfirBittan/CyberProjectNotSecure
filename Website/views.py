from flask import Blueprint, render_template, session, redirect, url_for

views = Blueprint('views', __name__)


@views.route('/')
def start():
    return render_template('start.html', logged_in=False)


@views.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html', logged_in=True)


@views.route('/logout')
def logout():
    session['email'] = None
    return redirect(url_for('auth.login'))
