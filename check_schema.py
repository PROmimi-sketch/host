import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Check all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

# Check schema of 'campaign' table if it exists
if ('campaign',) in tables:
    cursor.execute("PRAGMA table_info(campaign);")
    campaign_schema = cursor.fetchall()
    for col in campaign_schema:
        print(col)
else:
    print("⚠️ 'campaign' table does not exist in the database.")

conn.close()
