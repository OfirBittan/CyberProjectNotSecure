from . import mysql


class User:

    def __init__(self, email, password, first_name):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.login_attempts = 0
        self.last_failed_attempt = None
        self.is_blocked = False
        self.block_expiration = None

    def add_new_user(self):
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO users (email, password, first_name, login_attempts, last_failed_attempt, is_blocked, block_expiration) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (self.email, self.password, self.first_name, self.login_attempts,
             self.last_failed_attempt, self.is_blocked, self.block_expiration))
        mysql.connection.commit()
        cur.close()
