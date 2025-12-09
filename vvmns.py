"""
Anonymous Messaging Web App (single-file Flask app)

Features:
- Send anonymous messages (no registration)
- Optional "room" parameter so messages can be grouped
- Messages stored in SQLite (messages.db) with id, room, body, created_at, ip_hash
- Simple rate limiting per-IP (in-memory) to avoid spam
- Minimal Bootstrap UI rendered via render_template_string so it's single-file

How to run:
1. Install dependencies: pip install flask
2. Run: python anonymous_messaging_app.py
3. Open http://127.0.0.1:5000/

Security notes:
- This is a simple demo. Do NOT use as-is in production.
- Consider adding stronger spam protection (CAPTCHA), authentication, content moderation,
  HTTPS, and better rate-limiting (Redis) for production.
"""

from flask import Flask, request, g, redirect, url_for, render_template_string, abort
import sqlite3
from datetime import datetime, timedelta
import uuid
import hashlib
import os
import threading

DATABASE = 'messages.db'
RATE_LIMIT_WINDOW = timedelta(seconds=30)  # short window for demo
MAX_MESSAGES_PER_WINDOW = 5

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret')

# -------------------- Database helpers --------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    cur = db.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        room TEXT,
        body TEXT,
        created_at TEXT,
        ip_hash TEXT
    )
    ''')
    db.commit()
    db.close()

# Initialize DB at startup (safe to call multiple times)
init_db()

# -------------------- Simple in-memory rate limiter --------------------
# Note: This uses memory and will be lost on restart. For production use Redis or similar.
rate_lock = threading.Lock()
rate_map = {}  # ip_hash -> list of datetime

def ip_to_hash(ip):
    # Hash the IP so we don't store raw IP addresses.
    if not ip:
        ip = 'unknown'
    return hashlib.sha256(ip.encode('utf-8')).hexdigest()

def is_rate_limited(ip_hash):
    now = datetime.utcnow()
    with rate_lock:
        history = rate_map.get(ip_hash, [])
        # Drop old entries
        history = [t for t in history if now - t <= RATE_LIMIT_WINDOW]
        if len(history) >= MAX_MESSAGES_PER_WINDOW:
            rate_map[ip_hash] = history
            return True
        # allow
        history.append(now)
        rate_map[ip_hash] = history
        return False

# -------------------- Routes --------------------

INDEX_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Anonymous Messenger</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container py-4">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h3">Anonymous Messenger</h1>
        <small class="text-muted">Room: <strong>{{ room or 'public' }}</strong></small>
      </div>

      <div class="card mb-3">
        <div class="card-body">
          <form method="post" action="{{ url_for('send') }}">
            <input type="hidden" name="room" value="{{ room or '' }}">
            <div class="mb-3">
              <label for="body" class="form-label">Message</label>
              <textarea id="body" name="body" class="form-control" rows="3" maxlength="2000" required></textarea>
            </div>
            <div class="mb-3">
              <label for="alias" class="form-label">Optional alias (displayed, still anonymous)</label>
              <input id="alias" name="alias" class="form-control" maxlength="50" placeholder="e.g. Friendly Stranger">
            </div>
            <div class="d-flex gap-2">
              <button type="submit" class="btn btn-primary">Send anonymously</button>
              <a class="btn btn-outline-secondary" href="{{ url_for('index') }}">Switch room</a>
            </div>
          </form>
        </div>
      </div>

      {% if error %}
      <div class="alert alert-danger">{{ error }}</div>
      {% endif %}

      <div class="card">
        <div class="card-body">
          <h5 class="card-title">Recent messages</h5>
          {% if messages %}
            <ul class="list-unstyled">
            {% for m in messages %}
              <li class="mb-3">
                <div class="small text-muted">{{ m['created_at'] }}</div>
                <div class="p-2 border rounded">{{ m['body']|e }}</div>
              </li>
            {% endfor %}
            </ul>
          {% else %}
            <p class="text-muted">No messages yet.</p>
          {% endif %}
        </div>
      </div>

      <footer class="mt-4 text-muted small">Tip: Append <code>?room=yourroom</code> to the URL to create a separate room.</footer>
    </div>
  </body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    room = request.args.get('room', '').strip() or None
    db = get_db()
    cur = db.cursor()
    if room:
        cur.execute('SELECT id, room, body, created_at FROM messages WHERE room = ? ORDER BY created_at DESC LIMIT 50', (room,))
    else:
        cur.execute('SELECT id, room, body, created_at FROM messages WHERE room IS NULL OR room = ? ORDER BY created_at DESC LIMIT 50', (room,))
    rows = cur.fetchall()
    messages = [dict(r) for r in rows]
    # Format created_at nicely
    for m in messages:
        try:
            dt = datetime.fromisoformat(m['created_at'])
            m['created_at'] = dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return render_template_string(INDEX_HTML, messages=messages, room=room, error=None)

@app.route('/send', methods=['POST'])
def send():
    body = (request.form.get('body') or '').strip()
    room = (request.form.get('room') or '').strip() or None
    alias = (request.form.get('alias') or '').strip() or None

    if not body:
        return render_template_string(INDEX_HTML, messages=[], room=room, error='Message cannot be empty')

    # Basic length check
    if len(body) > 2000:
        return render_template_string(INDEX_HTML, messages=[], room=room, error='Message too long')

    # Rate limit based on IP (hashed)
    ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', '')
    ip_hash = ip_to_hash(ip)
    if is_rate_limited(ip_hash):
        return render_template_string(INDEX_HTML, messages=[], room=room, error='You are sending messages too fast. Try again later.')

    # Compose stored body: include alias if provided (still anonymous)
    if alias:
        stored_body = f"[{alias}] {body}"
    else:
        stored_body = body

    message_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    db = get_db()
    cur = db.cursor()
    cur.execute('INSERT INTO messages (id, room, body, created_at, ip_hash) VALUES (?, ?, ?, ?, ?)',
                (message_id, room, stored_body, created_at, ip_hash))
    db.commit()

    # Redirect back to index (to GET) so refresh won't resubmit form
    if room:
        return redirect(url_for('index', room=room))
    return redirect(url_for('index'))

@app.route('/api/messages', methods=['GET'])
def api_messages():
    """Simple API to fetch recent messages in JSON. Use ?room=roomname to filter."""
    room = request.args.get('room', '').strip() or None
    limit = int(request.args.get('limit') or 50)
    limit = min(200, max(1, limit))
    db = get_db()
    cur = db.cursor()
    if room:
        cur.execute('SELECT id, room, body, created_at FROM messages WHERE room = ? ORDER BY created_at DESC LIMIT ?', (room, limit))
    else:
        cur.execute('SELECT id, room, body, created_at FROM messages ORDER BY created_at DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    result = []
    for r in rows:
        result.append({'id': r['id'], 'room': r['room'], 'body': r['body'], 'created_at': r['created_at']})
    return {'messages': result}

# Admin-ish utility: purge messages older than X days (GET with ?days=...); in real app protect with auth
@app.route('/admin/purge', methods=['GET'])
def admin_purge():
    days = int(request.args.get('days') or 30)
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM messages WHERE created_at < ?', (cutoff,))
    deleted = cur.rowcount
    db.commit()
    return {'deleted': deleted}

if __name__ == '__main__':
    # For development only. Use a WSGI server in production.
    app.run(host='127.0.0.1', port=5000, debug=True)
