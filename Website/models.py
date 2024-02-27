from . import mysql
from datetime import datetime


class User:

    def __init__(self, email, password, first_name):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.login_attempts = 0
        self.last_failed_attempt = None
        self.is_blocked = False
        self.block_expiration = None
        self.stored_code_hash = None

    def add_new_user(self):
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO users (email, password, first_name, login_attempts, last_failed_attempt, "
            "is_blocked, block_expiration) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (self.email, self.password, self.first_name, self.login_attempts,
             self.last_failed_attempt, self.is_blocked, self.block_expiration))
        mysql.connection.commit()
        cur.close()


# PasswordHistory db table saves for every user the last 3 passwords history.
class PasswordHistory:
    def __init__(self, user_id, password, timestamp):
        self.user_id = user_id
        self.password = password
        self.timestamp = timestamp

    # Get the last 3 password history records for the user.
    # Delete the oldest password history record if there are already 3.
    # Add the new password history record.
    @staticmethod
    def save_password_history(user_id, password_hash):
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM password_history WHERE user_id = %s ORDER BY timestamp DESC LIMIT 3", (user_id,))
        last_three_histories = cur.fetchall()

        if len(last_three_histories) == 3:
            cur.execute("DELETE FROM password_history WHERE id = %s", (last_three_histories[-1]))
            mysql.connection.commit()

        cur.execute("INSERT INTO password_history (user_id, password, timestamp) VALUES (%s, %s, %s)",
                    (user_id, password_hash, datetime.utcnow()))
        mysql.connection.commit()
        cur.close()
