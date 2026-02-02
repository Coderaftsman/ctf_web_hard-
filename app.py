from flask import Flask, render_template, request, redirect, make_response
import jwt
import time

app = Flask(__name__)

FLAG = "cyber{jwt_trust_broken}"

# ⚠️ Weak secret + bad verification logic (intentional for CTF)
SECRET = "dev-secret"

def issue_token(role="user"):
    payload = {
        "role": role,
        "iat": int(time.time())
    }
    # HS256 token issued, but verification below is flawed
    return jwt.encode(payload, SECRET, algorithm="HS256")

def decode_token(token):
    try:
        # ❌ Vulnerability: accepts alg=none tokens (no signature verification)
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None

@app.route("/")
def index():
    token = issue_token("user")
    resp = make_response(render_template("index.html"))
    resp.set_cookie("session", token)
    return resp

@app.route("/admin")
def admin():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")

    data = decode_token(token)
    if not data:
        return "Invalid session", 401

    if data.get("role") == "admin":
        return render_template("admin.html", flag=FLAG)

    return "Access denied", 403
