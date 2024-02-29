from flask import flash
from . import mysql


# Password length should be at least the min_len_val(10).
def min_len(password, min_len_val=10):
    if len(password) < min_len_val:
        flash(f'Your password length is less than {min_len_val} characters.', category='error')
        return False
    else:
        return True


# Check if the password contains any of the common password dictionary.
# https://cybernews.com/best-password-managers/most-common-passwords/
def common_pass_list(password):
    common_pass_dictionary = ["123456", "123456789", "qwerty", "password",
                              "12345", "qwerty123", "1q2w3e", "12345678",
                              "111111", "1234567890"]
    for common in common_pass_dictionary:
        if common in password:
            flash(f'Your password contains a common known keyword : {common}.', category='error')
            return False
    return True


# The password shouldn't be like any password that was used up till 3 changes ago.
# Check if the new password is the same as any of the last three passwords.
# If we are initializing a new user then we don't have password history. (user = None).
def password_history(user, new_password):
    if user is None:
        return True
    else:
        cur = mysql.connection.cursor()
        cur.execute("SELECT password FROM password_history WHERE user_id = %s;", (user['id'],))
        last_three_histories = cur.fetchall()
        for item in last_three_histories:
            for value in item:
                if new_password == value:
                    flash(f'Your new password is the same as one of the last 3 password you had.', category='error')
                    return False
        return True


# Check if there is at least one special character.
def special_char(password):
    special_characters = "_+{}\":;'[]~!@#$%^&*()"
    for special in special_characters:
        if special in password:
            return 1
    return 0


# Check if there is at least one lower case character.
def lower_case(password):
    for p in password:
        if p.islower():
            return 1
    return 0


# Check if there is at least one upper case character.
def upper_case(password):
    for p in password:
        if p.isupper():
            return 1
    return 0


# Check if there is at least one digit.
def dig(password):
    for p in password:
        if p.isdigit():
            return 1
    return 0


# 3 out of 4 check: [Upper case, Lower case, Digit, Special character]
def three_out_of_four(password):
    value = special_char(password) + lower_case(password) + upper_case(password) + dig(password)
    if value < 3:
        flash(f'Your password should contain at least 3 of the following options: '
              f'[Upper case, Lower case, Digit, Special character]', category='error')
        return False
    else:
        return True


# Main check password function.
def main_check(user, password):
    return min_len(password) and three_out_of_four(password) and common_pass_list(password) and password_history(user,
                                                                                                                 password)
