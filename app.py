from flask import Flask, request, jsonify, send_from_directory
from pymongo import MongoClient
from dotenv import load_dotenv
import jwt
import datetime
import bcrypt
import uuid
import os

load_dotenv()

app = Flask(__name__)
SECRET_KEY = "mysecretkey"

# ── MongoDB connection ───────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI")
client       = MongoClient(MONGO_URI)
db           = client["spendwise"]
users_col    = db["users"]
expenses_col = db["expenses"]

# Indexes for faster lookups
users_col.create_index("username", unique=True)
expenses_col.create_index("user_id")

# ── JWT helper ───────────────────────────────────────────────

def decode_token(req):
    auth_header = req.headers.get("Authorization")
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

@app.route('/register', methods=['POST'])
def register():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400
    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters"}), 400

    if users_col.find_one({"username": username}):
        return jsonify({"message": "Username already taken"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user = {
        "_id":      str(uuid.uuid4()),
        "username": username,
        "password": hashed.decode("utf-8"),
    }
    users_col.insert_one(user)
    return jsonify({"message": "Registered successfully! Please log in."})


@app.route('/login', methods=['POST'])
def login():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    user = users_col.find_one({"username": username})

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            "user_id":  user["_id"],
            "username": user["username"],
            "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        },
        SECRET_KEY,
        algorithm="HS256"
    )
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return jsonify({"token": token})


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

    expenses = list(expenses_col.find(
        {"user_id": payload["user_id"]},
        {"_id": 0}      # exclude mongo internal _id, we expose our own "id" field
    ).sort("date", -1))

    return jsonify(expenses)


@app.route('/expenses', methods=['POST'])
def add_expense():
    payload, err = decode_token(request)
    if err:
        return err

    data     = request.json
    title    = data.get("title", "").strip()
    amount   = data.get("amount")
    category = data.get("category", "Other").strip()
    date     = data.get("date", datetime.date.today().isoformat())
    note     = data.get("note", "").strip()

    if not title or amount is None:
        return jsonify({"message": "Title and amount are required"}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"message": "Amount must be a positive number"}), 400

    expense_id = str(uuid.uuid4())
    expense = {
        "_id":        expense_id,           # mongo document id
        "id":         expense_id,           # same value exposed to frontend
        "user_id":    payload["user_id"],
        "title":      title,
        "amount":     round(amount, 2),
        "category":   category,
        "date":       date,
        "note":       note,
        "created_at": datetime.datetime.utcnow().isoformat()
    }

    expenses_col.insert_one(expense)

    # strip mongo's _id before returning
    expense.pop("_id")
    return jsonify(expense), 201


@app.route('/expenses/<expense_id>', methods=['DELETE'])
def delete_expense(expense_id):
    payload, err = decode_token(request)
    if err:
        return err

    expense = expenses_col.find_one({"id": expense_id})

    if not expense:
        return jsonify({"message": "Expense not found"}), 404

    # scope check — only owner can delete
    if expense["user_id"] != payload["user_id"]:
        return jsonify({"message": "Forbidden"}), 403

    expenses_col.delete_one({"id": expense_id})
    return jsonify({"message": "Deleted successfully"})


@app.route('/expenses/summary', methods=['GET'])
def expense_summary():
    payload, err = decode_token(request)
    if err:
        return err

    # MongoDB aggregation pipeline — group by category on the server
    pipeline = [
        {"$match": {"user_id": payload["user_id"]}},
        {"$group": {
            "_id":   "$category",
            "total": {"$sum": "$amount"},
            "count": {"$sum": 1}
        }}
    ]
    results = list(expenses_col.aggregate(pipeline))

    total       = round(sum(r["total"] for r in results), 2)
    count       = sum(r["count"] for r in results)
    by_category = {r["_id"]: round(r["total"], 2) for r in results}

    return jsonify({"total": total, "count": count, "by_category": by_category})


if __name__ == "__main__":
    app.run(debug=True)
