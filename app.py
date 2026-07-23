import os
import re
import sqlite3
import uuid
import secrets
from datetime import datetime, timedelta
from html import escape
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'market.db')

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
app.config['DATABASE'] = DATABASE
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set True in production with HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

socketio = SocketIO(app, cors_allowed_origins=['http://127.0.0.1:5000', 'http://localhost:5000'], async_mode='threading')

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
MAX_MESSAGE_COUNT = 5
MESSAGE_WINDOW_SECONDS = 10
MAX_REPORTS_PER_USER = 5

message_timestamps = {}

# Database helpers

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db_path = app.config.get('DATABASE', DATABASE)
        db = g._database = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def add_missing_column(cursor, table, column_definition):
    column_name = column_definition.split()[0]
    cursor.execute(f"PRAGMA table_info({table})")
    existing = [row['name'] for row in cursor.fetchall()]
    if column_name not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_definition}")


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT,
                password_hash TEXT,
                bio TEXT,
                role TEXT NOT NULL DEFAULT 'user',
                is_blocked INTEGER NOT NULL DEFAULT 0,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMP,
                balance_cents INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL DEFAULT '0',
                price_cents INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                buyer_id TEXT,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                is_sold INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP,
                sold_at TIMESTAMP,
                updated_at TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS transaction_log (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                product_id TEXT,
                amount_cents INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TIMESTAMP
            )
            """
        )
        db.commit()

        add_missing_column(cursor, 'user', 'password_hash TEXT')
        add_missing_column(cursor, 'user', "role TEXT NOT NULL DEFAULT 'user'")
        add_missing_column(cursor, 'user', 'is_blocked INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'user', 'failed_login_count INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'user', 'locked_until TIMESTAMP')
        add_missing_column(cursor, 'user', 'balance_cents INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'user', 'created_at TIMESTAMP')
        add_missing_column(cursor, 'user', 'updated_at TIMESTAMP')
        add_missing_column(cursor, 'product', 'price TEXT NOT NULL DEFAULT \'0\'')
        add_missing_column(cursor, 'product', 'price_cents INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'product', 'buyer_id TEXT')
        add_missing_column(cursor, 'product', 'is_blocked INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'product', 'is_sold INTEGER NOT NULL DEFAULT 0')
        add_missing_column(cursor, 'product', 'created_at TIMESTAMP')
        add_missing_column(cursor, 'product', 'sold_at TIMESTAMP')
        add_missing_column(cursor, 'product', 'updated_at TIMESTAMP')
        add_missing_column(cursor, 'report', 'target_type TEXT NOT NULL DEFAULT "product"')
        add_missing_column(cursor, 'report', 'status TEXT NOT NULL DEFAULT "pending"')
        add_missing_column(cursor, 'report', 'created_at TIMESTAMP')
        add_missing_column(cursor, 'transaction_log', 'product_id TEXT')
        db.commit()

        cursor.execute("SELECT COUNT(*) AS cnt FROM user")
        if cursor.fetchone()['cnt'] == 0:
            admin_id = str(uuid.uuid4())
            password = 'Admin@12345'
            admin_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT OR IGNORE INTO user (id, username, password, password_hash, bio, role, is_blocked, balance_cents, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'admin', 0, 0, ?, ?)",
                (admin_id, 'admin', admin_hash, admin_hash, '', datetime.utcnow(), datetime.utcnow())
            )
            app.logger.warning('Initial admin created with username admin. Change the password immediately.')
            db.commit()


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.context_processor
def inject_current_user():
    return {'current_user': get_current_user()}

@app.before_request
def enforce_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    if request.method == 'POST':
        token = session.get('csrf_token')
        form_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or not form_token or not secrets.compare_digest(token, form_token):
            abort(400, 'Invalid CSRF token')

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self';"
    return response

@app.errorhandler(400)
def bad_request(error):
    return render_template('error.html', message='잘못된 요청입니다.'), 400

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', message='접근이 거부되었습니다.'), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', message='페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message='서버 오류가 발생했습니다.'), 500

# Validation helpers

def validate_username(username):
    return bool(re.fullmatch(r'[A-Za-z0-9_.-]{4,30}', username))


def validate_password(password):
    return (
        isinstance(password, str)
        and 8 <= len(password) <= 128
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
        and re.search(r'[!@#$%^&*()_+\-=[\]{};:\\"\'",.<>/?]', password)
    )


def validate_text_field(value, max_length=500):
    if not isinstance(value, str):
        return False
    text = value.strip()
    return 1 <= len(text) <= max_length and '<' not in text and '>' not in text


def parse_price(price_text):
    try:
        cleaned = price_text.strip().replace(',', '')
        if not re.fullmatch(r'\d+(\.\d{1,2})?', cleaned):
            return None
        parts = cleaned.split('.')
        cents = int(parts[0]) * 100
        if len(parts) == 2:
            cents += int(parts[1].ljust(2, '0'))
        return cents
    except Exception:
        return None


def format_price(cents):
    return f"{cents // 100:,}.{str(cents % 100).zfill(2)}"


def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?', (user_id,))
    return cursor.fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_current_user()
        if user and user['is_blocked']:
            session.clear()
            flash('차단된 계정입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapped_view


def can_modify_product(user, product):
    return user and (user['role'] == 'admin' or user['id'] == product['seller_id'])


def log_audit(user_id, event_type, details):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        'INSERT INTO audit_log (id, user_id, event_type, details, created_at) VALUES (?, ?, ?, ?, ?)',
        (str(uuid.uuid4()), user_id, event_type, details, datetime.utcnow())
    )
    db.commit()


def check_rate_limit(user_id):
    now = datetime.utcnow().timestamp()
    timestamps = message_timestamps.setdefault(user_id, [])
    timestamps[:] = [t for t in timestamps if now - t < MESSAGE_WINDOW_SECONDS]
    if len(timestamps) >= MAX_MESSAGE_COUNT:
        return False
    timestamps.append(now)
    return True

# Routes

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/products')
def products():
    query = request.args.get('q', '').strip()
    db = get_db()
    cursor = db.cursor()
    if query:
        search = f'%{query}%'
        cursor.execute('SELECT product.*, user.username AS seller_name FROM product JOIN user ON product.seller_id = user.id WHERE (product.title LIKE ? OR product.description LIKE ?) AND product.is_blocked = 0 AND product.is_sold = 0', (search, search))
    else:
        cursor.execute('SELECT product.*, user.username AS seller_name FROM product JOIN user ON product.seller_id = user.id WHERE product.is_blocked = 0 AND product.is_sold = 0')
    products = cursor.fetchall()
    return render_template('products.html', products=products, query=query, format_price=format_price)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not validate_username(username):
            flash('사용자명은 4~30자의 영숫자, 밑줄, 점, 대시만 허용됩니다.')
            return redirect(url_for('register'))
        if not validate_password(password):
            flash('비밀번호는 최소 8자이며 소문자, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id FROM user WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        hashed = generate_password_hash(password)
        now = datetime.utcnow()
        cursor.execute(
            'INSERT INTO user (id, username, password, password_hash, role, balance_cents, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (user_id, username, hashed, hashed, 'user', 100000, now, now)
        )
        db.commit()
        log_audit(user_id, 'register', f'User {username} registered.')
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
        if user['is_blocked']:
            flash('계정이 차단되었습니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        locked_until = user['locked_until']
        if locked_until:
            if isinstance(locked_until, str):
                locked_until = datetime.fromisoformat(locked_until)
            if datetime.utcnow() < locked_until:
                flash('계정이 일시적으로 잠겼습니다. 잠시 후 다시 시도하세요.')
                return redirect(url_for('login'))
        password_valid = False
        if user['password_hash']:
            password_valid = check_password_hash(user['password_hash'], password)
        elif user['password'] and user['password'] == password:
            password_valid = True
            new_hash = generate_password_hash(password)
            cursor.execute('UPDATE user SET password_hash = ? WHERE id = ?', (new_hash, user['id']))
        if password_valid:
            cursor.execute('UPDATE user SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?', (datetime.utcnow(), user['id']))
            db.commit()
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            flash('로그인 성공!')
            log_audit(user['id'], 'login', 'User logged in successfully.')
            return redirect(url_for('dashboard'))
        failures = user['failed_login_count'] + 1
        lock_until = None
        if failures >= MAX_LOGIN_ATTEMPTS:
            lock_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            cursor.execute('UPDATE user SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?', (failures, lock_until, datetime.utcnow(), user['id']))
            db.commit()
            flash('로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도하세요.')
            return redirect(url_for('login'))
        cursor.execute('UPDATE user SET failed_login_count = ?, updated_at = ? WHERE id = ?', (failures, datetime.utcnow(), user['id']))
        db.commit()
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_current_user()
    session.clear()
    if user:
        log_audit(user['id'], 'logout', 'User logged out.')
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = get_current_user()
    db = get_db()
    cursor = db.cursor()
    query = request.args.get('q', '').strip()
    if query:
        search = f'%{query}%'
        cursor.execute('SELECT * FROM product WHERE (title LIKE ? OR description LIKE ?) AND is_blocked = 0 AND is_sold = 0', (search, search))
    else:
        cursor.execute('SELECT * FROM product WHERE is_blocked = 0 AND is_sold = 0')
    products = cursor.fetchall()
    return render_template('dashboard.html', products=products, user=current_user, query=query, format_price=format_price)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        if not validate_text_field(bio, max_length=300):
            flash('소개글은 300자 이내로 입력해 주세요. HTML 태그는 사용할 수 없습니다.')
            return redirect(url_for('profile'))
        cursor.execute('UPDATE user SET bio = ?, updated_at = ? WHERE id = ?', (bio.strip(), datetime.utcnow(), user['id']))
        db.commit()
        log_audit(user['id'], 'profile_update', 'Updated bio information.')
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    user = get_current_user()
    if request.method == 'POST':
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        price_text = request.form.get('price', '')
        if not validate_text_field(title, max_length=100):
            flash('제목은 1~100자이며 HTML 태그 없이 입력해야 합니다.')
            return redirect(url_for('new_product'))
        if not validate_text_field(description, max_length=1000):
            flash('설명은 1~1000자이며 HTML 태그 없이 입력해야 합니다.')
            return redirect(url_for('new_product'))
        price_cents = parse_price(price_text)
        if price_cents is None or price_cents <= 0:
            flash('가격은 0보다 큰 숫자로 입력해야 합니다.')
            return redirect(url_for('new_product'))
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            'INSERT INTO product (id, title, description, price, price_cents, seller_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (product_id, title.strip(), description.strip(), format_price(price_cents), price_cents, user['id'], datetime.utcnow(), datetime.utcnow())
        )
        db.commit()
        log_audit(user['id'], 'product_create', f'Created product {product_id}.')
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute('SELECT * FROM user WHERE id = ?', (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, user=get_current_user(), format_price=format_price)

@app.route('/product/<product_id>/buy', methods=['POST'])
@login_required
def buy_product(product_id):
    buyer = get_current_user()
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] == buyer['id']:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    if product['is_blocked']:
        flash('해당 상품은 현재 거래할 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['is_sold']:
        flash('이미 판매된 상품입니다.')
        return redirect(url_for('dashboard'))
    if buyer['balance_cents'] < product['price_cents']:
        flash('잔액이 부족합니다. 충전 후 다시 시도해주세요.')
        return redirect(url_for('transaction'))
    cursor.execute('SELECT * FROM user WHERE id = ?', (product['seller_id'],))
    seller = cursor.fetchone()
    if not seller:
        abort(404)
    now = datetime.utcnow()
    transaction_id = str(uuid.uuid4())
    cursor.execute(
        'INSERT INTO transaction_log (id, sender_id, receiver_id, product_id, amount_cents, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (transaction_id, buyer['id'], seller['id'], product_id, product['price_cents'], 'completed', now)
    )
    cursor.execute('UPDATE user SET balance_cents = balance_cents - ?, updated_at = ? WHERE id = ?', (product['price_cents'], now, buyer['id']))
    cursor.execute('UPDATE user SET balance_cents = balance_cents + ?, updated_at = ? WHERE id = ?', (product['price_cents'], now, seller['id']))
    cursor.execute('UPDATE product SET is_sold = 1, buyer_id = ?, sold_at = ?, updated_at = ? WHERE id = ?', (buyer['id'], now, now, product_id))
    db.commit()
    log_audit(buyer['id'], 'product_purchase', f'Purchased product {product_id} from {seller["id"]}.')
    flash('상품 구매가 완료되었습니다. 거래 내역에서 확인하세요.')
    return redirect(url_for('transactions'))

@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    user = get_current_user()
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if not can_modify_product(user, product):
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        price_text = request.form.get('price', '')
        if not validate_text_field(title, max_length=100):
            flash('제목은 1~100자이며 HTML 태그 없이 입력해야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        if not validate_text_field(description, max_length=1000):
            flash('설명은 1~1000자이며 HTML 태그 없이 입력해야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        price_cents = parse_price(price_text)
        if price_cents is None or price_cents <= 0:
            flash('가격은 0보다 큰 숫자로 입력해야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        cursor.execute(
            'UPDATE product SET title = ?, description = ?, price = ?, price_cents = ?, updated_at = ? WHERE id = ?',
            (title.strip(), description.strip(), format_price(price_cents), price_cents, datetime.utcnow(), product_id)
        )
        db.commit()
        log_audit(user['id'], 'product_update', f'Updated product {product_id}.')
        flash('상품이 업데이트되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product, format_price=format_price)

@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    user = get_current_user()
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if not can_modify_product(user, product):
        abort(403)
    cursor.execute('DELETE FROM product WHERE id = ?', (product_id,))
    db.commit()
    log_audit(user['id'], 'product_delete', f'Deleted product {product_id}.')
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    user = get_current_user()
    if request.method == 'POST':
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '')
        if not validate_text_field(target_id, max_length=100) or not validate_text_field(reason, max_length=500):
            flash('신고 대상과 사유는 유효한 텍스트여야 합니다.')
            return redirect(url_for('report'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT COUNT(*) AS cnt FROM report WHERE reporter_id = ? AND target_id = ? AND status = ?', (user['id'], target_id, 'pending'))
        if cursor.fetchone()['cnt'] > 0:
            flash('동일한 대상에 대한 신고를 중복 접수할 수 없습니다.')
            return redirect(url_for('report'))
        cursor.execute('SELECT COUNT(*) AS cnt FROM report WHERE reporter_id = ? AND status = ?', (user['id'], 'pending'))
        if cursor.fetchone()['cnt'] >= MAX_REPORTS_PER_USER:
            flash('신고 대기 중인 항목이 많습니다. 관리자의 검토를 기다려주세요.')
            return redirect(url_for('report'))
        target_type = 'product'
        cursor.execute('SELECT id FROM user WHERE id = ?', (target_id,))
        if cursor.fetchone():
            target_type = 'user'
        cursor.execute('SELECT id FROM product WHERE id = ?', (target_id,))
        if not cursor.fetchone() and target_type == 'product':
            flash('존재하지 않는 신고 대상입니다.')
            return redirect(url_for('report'))
        report_id = str(uuid.uuid4())
        cursor.execute(
            'INSERT INTO report (id, reporter_id, target_type, target_id, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (report_id, user['id'], target_type, target_id, reason.strip(), 'pending', datetime.utcnow())
        )
        db.commit()
        log_audit(user['id'], 'report_create', f'Reported {target_type} {target_id}.')
        flash('신고가 접수되었습니다. 감사합니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

@app.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    user = get_current_user()
    if request.method == 'POST':
        receiver_name = request.form.get('receiver', '').strip()
        amount_text = request.form.get('amount', '')
        if not validate_username(receiver_name):
            flash('받는 사람은 올바른 사용자명이어야 합니다.')
            return redirect(url_for('transaction'))
        amount_cents = parse_price(amount_text)
        if amount_cents is None or amount_cents <= 0:
            flash('이체 금액은 0보다 큰 숫자여야 합니다.')
            return redirect(url_for('transaction'))
        if amount_cents > user['balance_cents']:
            flash('잔액이 부족합니다.')
            return redirect(url_for('transaction'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (receiver_name,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('수신자를 찾을 수 없습니다.')
            return redirect(url_for('transaction'))
        if receiver['id'] == user['id']:
            flash('자기 자신에게는 이체할 수 없습니다.')
            return redirect(url_for('transaction'))
        now = datetime.utcnow()
        transaction_id = str(uuid.uuid4())
        cursor.execute('INSERT INTO transaction_log (id, sender_id, receiver_id, amount_cents, status, created_at) VALUES (?, ?, ?, ?, ?, ?)', (transaction_id, user['id'], receiver['id'], amount_cents, 'completed', now))
        cursor.execute('UPDATE user SET balance_cents = balance_cents - ?, updated_at = ? WHERE id = ?', (amount_cents, now, user['id']))
        cursor.execute('UPDATE user SET balance_cents = balance_cents + ?, updated_at = ? WHERE id = ?', (amount_cents, now, receiver['id']))
        db.commit()
        log_audit(user['id'], 'transaction', f'Sent {amount_cents} cents to {receiver_name}.')
        flash('이체가 완료되었습니다.')
        return redirect(url_for('transactions'))
    return render_template('transaction.html', user=user)

@app.route('/transactions')
@login_required
def transactions():
    user = get_current_user()
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        SELECT tl.*, p.title AS product_title
        FROM transaction_log tl
        LEFT JOIN product p ON tl.product_id = p.id
        WHERE tl.sender_id = ? OR tl.receiver_id = ?
        ORDER BY tl.created_at DESC
        '''
    , (user['id'], user['id']))
    history = cursor.fetchall()
    return render_template('transactions.html', history=history, user=user, format_price=format_price)

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, username, role, balance_cents, is_blocked, created_at FROM user ORDER BY username')
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users, format_price=format_price)

@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        SELECT p.*, u.username AS seller_username
        FROM product p
        LEFT JOIN user u ON p.seller_id = u.id
        ORDER BY p.created_at DESC
        '''
    )
    products = cursor.fetchall()
    return render_template('admin_products.html', products=products, format_price=format_price)

@app.route('/admin/products/<product_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    new_state = 0 if product['is_blocked'] else 1
    cursor.execute('UPDATE product SET is_blocked = ?, updated_at = ? WHERE id = ?', (new_state, datetime.utcnow(), product_id))
    db.commit()
    log_audit(session['user_id'], 'product_toggle_block', f'Changed block status for product {product_id} to {new_state}.')
    flash('상품 차단 상태가 변경되었습니다.')
    return redirect(url_for('admin_products'))

@app.route('/admin/users/<user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?', (user_id,))
    target_user = cursor.fetchone()
    if not target_user:
        abort(404)
    if target_user['role'] == 'admin':
        flash('관리자 계정은 차단할 수 없습니다.')
        return redirect(url_for('admin_users'))
    new_state = 0 if target_user['is_blocked'] == 1 else 1
    cursor.execute('UPDATE user SET is_blocked = ?, updated_at = ? WHERE id = ?', (new_state, datetime.utcnow(), user_id))
    db.commit()
    log_audit(session['user_id'], 'user_toggle_block', f'Changed block status for user {user_id} to {new_state}.')
    flash('사용자 차단 상태가 변경되었습니다.')
    return redirect(url_for('admin_users'))

@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        SELECT report.*, u.username AS reporter_name,
               p.title AS target_product_title,
               t.username AS target_user_name
        FROM report
        LEFT JOIN user u ON report.reporter_id = u.id
        LEFT JOIN product p ON report.target_type = 'product' AND report.target_id = p.id
        LEFT JOIN user t ON report.target_type = 'user' AND report.target_id = t.id
        ORDER BY report.created_at DESC
        '''
    )
    reports = cursor.fetchall()
    return render_template('admin_reports.html', reports=reports)

@app.route('/admin/reports/<report_id>/resolve', methods=['POST'])
@admin_required
def resolve_report(report_id):
    action = request.form.get('action')
    if action not in ('approve', 'dismiss'):
        abort(400)
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM report WHERE id = ?', (report_id,))
    report = cursor.fetchone()
    if not report:
        abort(404)
    status = 'reviewed' if action == 'approve' else 'dismissed'
    if action == 'approve':
        if report['target_type'] == 'product':
            cursor.execute('SELECT * FROM product WHERE id = ?', (report['target_id'],))
            target = cursor.fetchone()
            if target:
                cursor.execute('UPDATE product SET is_blocked = ?, updated_at = ? WHERE id = ?', (1, datetime.utcnow(), report['target_id']))
                flash('신고가 승인되어 상품이 차단되었습니다.')
            else:
                flash('신고 대상 상품을 찾을 수 없어 상태만 변경되었습니다.')
        elif report['target_type'] == 'user':
            cursor.execute('SELECT * FROM user WHERE id = ?', (report['target_id'],))
            target = cursor.fetchone()
            if target and target['role'] != 'admin':
                cursor.execute('UPDATE user SET is_blocked = ?, updated_at = ? WHERE id = ?', (1, datetime.utcnow(), report['target_id']))
                flash('신고가 승인되어 사용자가 차단되었습니다.')
            elif target and target['role'] == 'admin':
                flash('관리자 계정은 자동으로 차단할 수 없습니다. 신고는 상태만 변경되었습니다.')
            else:
                flash('신고 대상 사용자를 찾을 수 없어 상태만 변경되었습니다.')
    else:
        flash('신고가 기각되었습니다.')
    cursor.execute('UPDATE report SET status = ? WHERE id = ?', (status, report_id))
    db.commit()
    log_audit(session['user_id'], 'report_resolve', f'{action} report {report_id}.')
    return redirect(url_for('admin_reports'))

# SocketIO

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    user = get_current_user()
    if not user:
        return False
    send({'username': '시스템', 'message': f'{user["username"]}님이 채팅에 입장했습니다.'}, broadcast=True)

@socketio.on('send_message')
def handle_send_message_event(data):
    user = get_current_user()
    if not user:
        return
    message = data.get('message', '').strip()
    if not validate_text_field(message, max_length=300):
        return
    if not check_rate_limit(user['id']):
        send({'username': '시스템', 'message': '메시지 전송 속도가 너무 빠릅니다. 잠시 후 다시 시도해주세요.'}, room=request.sid)
        return
    payload = {
        'username': escape(user['username']),
        'message': escape(message),
        'timestamp': datetime.utcnow().isoformat()
    }
    send(payload, broadcast=True)

if __name__ == '__main__':
    init_db()
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, use_reloader=False)
