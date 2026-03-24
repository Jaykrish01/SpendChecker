from flask import Flask, request, jsonify, send_from_directory
import jwt
import datetime
import json
import os
import uuid

app = Flask(__name__)
SECRET_KEY = "mysecretkey"
USER_DB = "users.json"
EXPENSE_DB = "expenses.json"

# Ensure DB files exist
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump([], f)

if not os.path.exists(EXPENSE_DB):
    with open(EXPENSE_DB, "w") as f:
        json.dump([], f)

# ── DB helpers ──────────────────────────────────────────────

def load_users():
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=2)

def load_expenses():
    with open(EXPENSE_DB, "r") as f:
        return json.load(f)

def save_expenses(expenses):
    with open(EXPENSE_DB, "w") as f:
        json.dump(expenses, f, indent=2)

# ── JWT helper ───────────────────────────────────────────────

def decode_token(request):
    """Extract and verify JWT from Authorization header.
    Returns (payload, None) on success or (None, error_response) on failure."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, (jsonify({"message": "Missing or malformed token"}), 401)
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"message": "Token expired"}), 403)
    except jwt.InvalidTokenError:
        return None, (jsonify({"message": "Invalid token"}), 403)

# ── Static pages ─────────────────────────────────────────────

@app.route('/')
def home():
    return send_from_directory('.', 'login.html')

@app.route('/register_page')
def register_page():
    return send_from_directory('.', 'register.html')

@app.route('/dashboard')
def dashboard():
    return send_from_directory('.', 'dashboard.html')

# ── Auth endpoints ───────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    users = load_users()
    user = next((u for u in users if u["username"] == username and u["password"] == password), None)

    if user:
        token = jwt.encode(
            {
                "user_id": user["id"],
                "username": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    users = load_users()
    if any(u["username"] == username for u in users):
        return jsonify({"message": "Username already taken"}), 400

    new_user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "password": password
    }
    users.append(new_user)
    save_users(users)
    return jsonify({"message": "Registered successfully! Please log in."})

@app.route('/profile', methods=['GET'])
def profile():
    payload, err = decode_token(request)
    if err:
        return err
    return jsonify({"message": f"Welcome {payload['username']}!", "username": payload["username"]})

# ── Expense endpoints ─────────────────────────────────────────

@app.route('/expenses', methods=['GET'])
def get_expenses():
    payload, err = decode_token(request)
    if err:
        return err

    expenses = load_expenses()
    user_expenses = [e for e in expenses if e["user_id"] == payload["user_id"]]

    # Sort by date descending
    user_expenses.sort(key=lambda x: x["date"], reverse=True)
    return jsonify(user_expenses)


@app.route('/expenses', methods=['POST'])
def add_expense():
    payload, err = decode_token(request)
    if err:
        return err

    data = request.json
    title   = data.get("title", "").strip()
    amount  = data.get("amount")
    category = data.get("category", "Other").strip()
    date    = data.get("date", datetime.date.today().isoformat())
    note    = data.get("note", "").strip()

    if not title or amount is None:
        return jsonify({"message": "Title and amount are required"}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"message": "Amount must be a positive number"}), 400

    expense = {
        "id": str(uuid.uuid4()),
        "user_id": payload["user_id"],
        "title": title,
        "amount": round(amount, 2),
        "category": category,
        "date": date,
        "note": note,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

    expenses = load_expenses()
    expenses.append(expense)
    save_expenses(expenses)
    return jsonify(expense), 201


@app.route('/expenses/<expense_id>', methods=['DELETE'])
def delete_expense(expense_id):
    payload, err = decode_token(request)
    if err:
        return err

    expenses = load_expenses()
    expense = next((e for e in expenses if e["id"] == expense_id), None)

    if not expense:
        return jsonify({"message": "Expense not found"}), 404

    # Scope check — users can only delete their own expenses
    if expense["user_id"] != payload["user_id"]:
        return jsonify({"message": "Forbidden"}), 403

    expenses = [e for e in expenses if e["id"] != expense_id]
    save_expenses(expenses)
    return jsonify({"message": "Deleted successfully"})


@app.route('/expenses/summary', methods=['GET'])
def expense_summary():
    payload, err = decode_token(request)
    if err:
        return err

    expenses = load_expenses()
    user_expenses = [e for e in expenses if e["user_id"] == payload["user_id"]]

    total = round(sum(e["amount"] for e in user_expenses), 2)

    by_category = {}
    for e in user_expenses:
        cat = e.get("category", "Other")
        by_category[cat] = round(by_category.get(cat, 0) + e["amount"], 2)

    return jsonify({
        "total": total,
        "count": len(user_expenses),
        "by_category": by_category
    })


if __name__ == "__main__":
    app.run(debug=True)
