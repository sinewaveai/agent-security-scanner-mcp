# Demo: Vulnerable Python Code for Agent Security Scanner

import sqlite3

# 1. SQL Injection - f-string (should be fixed now!)
def get_user_by_id(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# 2. SQL Injection - .format()
def search_products(term):
    cursor.execute("SELECT * FROM products WHERE name = '{}'".format(term))
    return cursor.fetchall()

# 3. SQL Injection - % formatting
def get_order(order_id):
    cursor.execute("SELECT * FROM orders WHERE id = %s" % (order_id,))
    return cursor.fetchone()

# 4. SQL Injection - simple concatenation
def delete_user(user_id):
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
