"""Northgate ATM Management System - a small Flask + SQLite web app.

Run:  pip install -r requirements.txt && python app.py
Open: http://127.0.0.1:5000   (or set PORT=5002 if 5000 is occupied)
Admin page: /admin, default password: admin123
"""
import hmac
import os
import re
import secrets
import sqlite3
import string
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "atm.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
PORT = int(os.environ.get("PORT", "5000"))
CURRENCY = "₹"
DAILY_WITHDRAW_LIMIT = 50000   # in cents ($500.00)
MAX_PIN_TRIES = 3

app = Flask(__name__, static_folder=BASE, template_folder=BASE)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

# ---------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  card TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 0,      -- stored in cents
  failed INTEGER NOT NULL DEFAULT 0,
  frozen INTEGER NOT NULL DEFAULT 0,
  created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id),
  kind TEXT NOT NULL,
  amount INTEGER NOT NULL,
  balance_after INTEGER NOT NULL,
  note TEXT,
  created TEXT NOT NULL);
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------- helpers
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@app.template_filter("money")
def money(cents):
    return f"{CURRENCY}{cents / 100:,.2f}"


@app.template_filter("card")
def card_fmt(number):
    return " ".join(number[i:i + 4] for i in range(0, len(number), 4))


def parse_amount(text):
    """'25' or '25.50' -> cents. Returns None if invalid."""
    try:
        d = Decimal((text or "").strip())
    except InvalidOperation:
        return None
    if not d.is_finite() or d <= 0 or d > 1_000_000:
        return None
    if d != d.quantize(Decimal("0.01")):
        return None
    return int(d * 100)


def valid_pin(pin):
    return bool(re.fullmatch(r"\d{4}", pin or ""))


def record(db, account_id, kind, amount, note=""):
    bal = db.execute("SELECT balance FROM accounts WHERE id=?",
                     (account_id,)).fetchone()["balance"]
    db.execute("INSERT INTO transactions(account_id,kind,amount,balance_after,note,created)"
               " VALUES (?,?,?,?,?,?)", (account_id, kind, amount, bal, note, now()))


def withdrawn_today(db, account_id):
    row = db.execute("SELECT COALESCE(SUM(amount),0) AS s FROM transactions"
                     " WHERE account_id=? AND kind='WITHDRAW' AND created LIKE ?",
                     (account_id, datetime.now().strftime("%Y-%m-%d") + "%")).fetchone()
    return row["s"]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        aid = session.get("aid")
        acct = None
        if aid:
            acct = get_db().execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
        if acct is None or acct["frozen"]:
            session.pop("aid", None)
            flash("Log in to continue.", "error")
            return redirect(url_for("login"))
        g.acct = acct
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------- CSRF
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf")
        if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
            abort(400, "Your form expired. Go back, reload the page and try again.")


@app.context_processor
def inject_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return {"csrf": session["csrf"]}


# ---------------------------------------------------------------- customer pages
@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("aid") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        pin, confirm = request.form.get("pin", ""), request.form.get("confirm", "")
        opening = parse_amount(request.form.get("opening"))
        error = None
        if not name or len(name) > 60:
            error = "Enter your full name (up to 60 characters)."
        elif not valid_pin(pin):
            error = "The PIN must be exactly 4 digits."
        elif pin != confirm:
            error = "The two PINs do not match."
        elif opening is None:
            error = "Enter an opening deposit greater than 0, like 100 or 100.50."
        if error:
            flash(error, "error")
        else:
            db = get_db()
            while True:
                card = "".join(secrets.choice(string.digits) for _ in range(12))
                if not db.execute("SELECT 1 FROM accounts WHERE card=?", (card,)).fetchone():
                    break
            cur = db.execute("INSERT INTO accounts(card,name,pin_hash,balance,created)"
                             " VALUES (?,?,?,?,?)",
                             (card, name, generate_password_hash(pin), opening, now()))
            record(db, cur.lastrowid, "DEPOSIT", opening, "Opening deposit")
            db.commit()
            flash(f"Account created. Your card number is {card_fmt(card)}. "
                  "Use it with your PIN to log in.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        card = request.form.get("card", "").replace(" ", "")
        pin = request.form.get("pin", "")
        db = get_db()
        acct = db.execute("SELECT * FROM accounts WHERE card=?", (card,)).fetchone()
        if acct is None:
            flash("Card number or PIN is incorrect.", "error")
        elif acct["frozen"]:
            flash("This card is blocked. Ask the bank to unblock it.", "error")
        elif check_password_hash(acct["pin_hash"], pin):
            db.execute("UPDATE accounts SET failed=0 WHERE id=?", (acct["id"],))
            db.commit()
            session.clear()
            session["aid"] = acct["id"]
            return redirect(url_for("dashboard"))
        else:
            failed = acct["failed"] + 1
            frozen = 1 if failed >= MAX_PIN_TRIES else 0
            db.execute("UPDATE accounts SET failed=?, frozen=? WHERE id=?",
                       (failed, frozen, acct["id"]))
            db.commit()
            if frozen:
                flash("Wrong PIN 3 times. This card is now blocked.", "error")
            else:
                flash(f"Card number or PIN is incorrect. {MAX_PIN_TRIES - failed} tries left.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    recent = db.execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 5",
                        (g.acct["id"],)).fetchall()
    left = max(0, DAILY_WITHDRAW_LIMIT - withdrawn_today(db, g.acct["id"]))
    return render_template("dashboard.html", acct=g.acct, recent=recent, left=left)


@app.post("/deposit")
@login_required
def deposit():
    amt = parse_amount(request.form.get("amount"))
    if amt is None:
        flash("Enter a valid amount, like 25 or 25.50.", "error")
    else:
        db = get_db()
        db.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (amt, g.acct["id"]))
        record(db, g.acct["id"], "DEPOSIT", amt, "Cash deposit")
        db.commit()
        flash(f"Deposited {money(amt)}.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/withdraw")
@login_required
def withdraw():
    amt = parse_amount(request.form.get("amount"))
    db = get_db()
    if amt is None:
        flash("Enter a valid amount, like 25 or 25.50.", "error")
    elif withdrawn_today(db, g.acct["id"]) + amt > DAILY_WITHDRAW_LIMIT:
        flash(f"This goes over the daily withdrawal limit of {money(DAILY_WITHDRAW_LIMIT)}.", "error")
    else:
        cur = db.execute("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?",
                         (amt, g.acct["id"], amt))
        if cur.rowcount == 0:
            flash("Not enough balance for this withdrawal.", "error")
        else:
            record(db, g.acct["id"], "WITHDRAW", amt, "Cash withdrawal")
            db.commit()
            flash(f"Withdrew {money(amt)}. Take your cash.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/transfer")
@login_required
def transfer():
    amt = parse_amount(request.form.get("amount"))
    to_card = request.form.get("to_card", "").replace(" ", "")
    db = get_db()
    target = db.execute("SELECT * FROM accounts WHERE card=?", (to_card,)).fetchone()
    if amt is None:
        flash("Enter a valid amount, like 25 or 25.50.", "error")
    elif target is None or target["frozen"]:
        flash("No active account found for that card number.", "error")
    elif target["id"] == g.acct["id"]:
        flash("Choose a different account to transfer to.", "error")
    else:
        cur = db.execute("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?",
                         (amt, g.acct["id"], amt))
        if cur.rowcount == 0:
            flash("Not enough balance for this transfer.", "error")
        else:
            db.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (amt, target["id"]))
            record(db, g.acct["id"], "TRANSFER_OUT", amt, f"To {card_fmt(target['card'])}")
            record(db, target["id"], "TRANSFER_IN", amt, f"From {card_fmt(g.acct['card'])}")
            db.commit()
            flash(f"Sent {money(amt)} to {target['name']}.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/change-pin")
@login_required
def change_pin():
    old, new = request.form.get("old", ""), request.form.get("new", "")
    if not check_password_hash(g.acct["pin_hash"], old):
        flash("Your current PIN is incorrect.", "error")
    elif not valid_pin(new):
        flash("The new PIN must be exactly 4 digits.", "error")
    else:
        db = get_db()
        db.execute("UPDATE accounts SET pin_hash=? WHERE id=?",
                   (generate_password_hash(new), g.acct["id"]))
        db.commit()
        flash("PIN changed.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/history")
@login_required
def history():
    rows = get_db().execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 100",
                            (g.acct["id"],)).fetchall()
    return render_template("history.html", rows=rows)


# ---------------------------------------------------------------- admin
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if hmac.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect(url_for("admin"))
        flash("Wrong admin password.", "error")
    if not session.get("admin"):
        return render_template("admin.html", is_admin=False)
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()
    stats = db.execute("SELECT COUNT(*) AS n, COALESCE(SUM(balance),0) AS total,"
                       " COALESCE(SUM(frozen),0) AS blocked FROM accounts").fetchone()
    recent = db.execute("SELECT t.*, a.name FROM transactions t JOIN accounts a ON a.id=t.account_id"
                        " ORDER BY t.id DESC LIMIT 15").fetchall()
    return render_template("admin.html", is_admin=True, accounts=accounts, stats=stats, recent=recent)


@app.post("/admin/toggle/<int:account_id>")
def admin_toggle(account_id):
    if not session.get("admin"):
        abort(403)
    db = get_db()
    db.execute("UPDATE accounts SET frozen=1-frozen, failed=0 WHERE id=?", (account_id,))
    db.commit()
    return redirect(url_for("admin"))


@app.post("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin"))


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)
