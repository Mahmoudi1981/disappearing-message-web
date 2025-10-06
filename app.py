from flask import Flask, render_template, request, jsonify
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import time

app = Flask(__name__)

# ذخیره‌سازی موقت پیام‌ها (فقط در حافظه)
messages = {}

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    message = data.get('message', '').strip()
    password = data.get('password', '').strip()

    if not message or not password:
        return jsonify({'error': 'پیام و رمز عبور نمی‌تواند خالی باشد.'}), 400

    try:
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(message.encode('utf-8'))
        token = secrets.token_urlsafe(16)

        # ذخیره پیام + salt
        messages[token] = {
            'salt': base64.urlsafe_b64encode(salt).decode(),
            'encrypted': base64.urlsafe_b64encode(encrypted).decode()
        }

        # پاک کردن خودکار پس از 7 روز (در صورت خوانده نشدن)
        def auto_delete():
            time.sleep(7 * 24 * 3600)  # 7 روز
            if token in messages:
                del messages[token]
        threading.Thread(target=auto_delete, daemon=True).start()

        return jsonify({'token': token})
    except Exception as e:
        return jsonify({'error': 'خطا در رمزنگاری'}), 500

@app.route('/receive', methods=['POST'])
def receive_message():
    data = request.json
    token = data.get('token', '').strip()
    password = data.get('password', '').strip()

    if not token or not password:
        return jsonify({'error': 'کد و رمز عبور نمی‌تواند خالی باشد.'}), 400

    if token not in messages:
        return jsonify({'error': 'کد نامعتبر است یا پیام قبلاً خوانده شده.'}), 404

    try:
        msg_data = messages[token]
        salt = base64.urlsafe_b64decode(msg_data['salt'])
        encrypted = base64.urlsafe_b64decode(msg_data['encrypted'])

        key = derive_key(password, salt)
        f = Fernet(key)
        decrypted = f.decrypt(encrypted).decode('utf-8')

        # خودنابود! پاک کردن پیام بعد از خواندن
        del messages[token]

        return jsonify({'message': decrypted})
    except Exception as e:
        return jsonify({'error': 'رمز عبور اشتباه است یا پیام آسیب دیده.'}), 403

if __name__ == '__main__':
    app.run(debug=True)