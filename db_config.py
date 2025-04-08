import MySQLdb

def get_db_connection():
    return MySQLdb.connect(
        host="localhost",
        user="root",
        passwd="Saksham8453@",  # Replace this
        db="cap_db"
    )
