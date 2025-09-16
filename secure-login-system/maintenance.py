import sqlite3
import bcrypt
import sys

DB = "database.db"

def connect():
    return sqlite3.connect(DB)

def list_users():
    with connect() as c:
        cur = c.cursor()
        cur.execute("SELECT id, username, role, failed_attempts, locked FROM users ORDER BY id")
        rows = cur.fetchall()
        if not rows:
            print("(no users)")
        else:
            for r in rows:
                print(r)

def rename_user(old_email, new_email):
    with connect() as c:
        cur = c.cursor()
        cur.execute("UPDATE users SET username=? WHERE username=?", (new_email.strip(), old_email.strip()))
        c.commit()
        if cur.rowcount:
            print(f"Renamed {old_email} -> {new_email}")
        else:
            print("No matching user.")

def delete_user(email):
    with connect() as c:
        cur = c.cursor()
        cur.execute("DELETE FROM users WHERE username=?", (email.strip(),))
        c.commit()
        if cur.rowcount:
            print(f"Deleted {email}")
        else:
            print("No matching user.")

def promote_admin(email):
    with connect() as c:
        cur = c.cursor()
        cur.execute("UPDATE users SET role='admin' WHERE username=?", (email.strip(),))
        c.commit()
        if cur.rowcount:
            print(f"{email} is now an admin.")
        else:
            print("No matching user.")

def reset_password(email, new_password):
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    with connect() as c:
        cur = c.cursor()
        cur.execute("UPDATE users SET password=? WHERE username=?", (hashed, email.strip()))
        c.commit()
        if cur.rowcount:
            print(f"Password reset for {email}")
        else:
            print("No matching user.")

def unlock_user(email):
    with connect() as c:
        cur = c.cursor()
        cur.execute("UPDATE users SET failed_attempts=0, locked=0 WHERE username=?", (email.strip(),))
        c.commit()
        if cur.rowcount:
            print(f"Unlocked {email}")
        else:
            print("No matching user.")

def reset_2fa(email):
    # keeps enrollment flow in your app; here just clears so app forces a new one
    with connect() as c:
        cur = c.cursor()
        cur.execute("UPDATE users SET totp_secret=NULL WHERE username=?", (email.strip(),))
        c.commit()
        if cur.rowcount:
            print(f"Cleared TOTP secret for {email}. User must re-enroll at next login.")
        else:
            print("No matching user.")

def purge_all_users_i_know_what_im_doing():
    confirm = input("Type 'DELETE ALL USERS' to confirm: ")
    if confirm != "DELETE ALL USERS":
        print("Aborted.")
        return
    with connect() as c:
        cur = c.cursor()
        cur.execute("DELETE FROM users")
        c.commit()
        print("All users deleted.")

def help_text():
    print("""
Usage:
  python maintenance.py list
  python maintenance.py rename <old_email> <new_email>
  python maintenance.py delete <email>
  python maintenance.py promote <email>
  python maintenance.py resetpass <email> <new_password>
  python maintenance.py unlock <email>
  python maintenance.py reset2fa <email>
  python maintenance.py purge_all_users   (DESTRUCTIVE)
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_text(); sys.exit(0)

    cmd = sys.argv[1].lower()
    try:
        if cmd == "list":
            list_users()
        elif cmd == "rename" and len(sys.argv) == 4:
            rename_user(sys.argv[2], sys.argv[3])
        elif cmd == "delete" and len(sys.argv) == 3:
            delete_user(sys.argv[2])
        elif cmd == "promote" and len(sys.argv) == 3:
            promote_admin(sys.argv[2])
        elif cmd == "resetpass" and len(sys.argv) == 4:
            reset_password(sys.argv[2], sys.argv[3])
        elif cmd == "unlock" and len(sys.argv) == 3:
            unlock_user(sys.argv[2])
        elif cmd == "reset2fa" and len(sys.argv) == 3:
            reset_2fa(sys.argv[2])
        elif cmd == "purge_all_users":
            purge_all_users_i_know_what_im_doing()
        else:
            help_text()
    except sqlite3.OperationalError as e:
        print("SQLite error:", e)