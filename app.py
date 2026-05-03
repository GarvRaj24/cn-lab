from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure_speak_secret_key_2026' 

# SocketIO initialization with increased buffer for encrypted media transfers[cite: 3]
socketio = SocketIO(app, 
    cors_allowed_origins="*", 
    max_http_buffer_size=50 * 1024 * 1024, 
    ping_timeout=60, 
    ping_interval=25
)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    """Handles users joining a specific room channel[cite: 3]."""
    room = data.get('room')
    username = data.get('username', 'Anonymous')
    join_room(room)
    # Notify existing peers in the room[cite: 3]
    emit('user_joined', {'username': username, 'sid': request.sid}, to=room, include_self=False)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    """Relays RSA public keys for E2EE handshake[cite: 3]."""
    room = data.get('room')
    emit('receive_public_key', data, to=room, include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    """
    Relays encrypted payloads. 
    Includes sentAt and msgId to support CN Panel telemetry[cite: 1, 3].
    """
    room = data.get('room')
    emit('receive_message', {
        'type': data.get('type'),
        'msgId': data.get('msgId'),
        'sentAt': data.get('sentAt'),
        'iv': data.get('iv'),
        'encryptedKey': data.get('encryptedKey'),
        'encryptedData': data.get('encryptedData'),
        'isViewOnce': data.get('isViewOnce', False),
        'username': data.get('username', 'Anonymous')
    }, to=room, include_self=False)

if __name__ == '__main__':
    # Enabled adhoc SSL for Web Crypto API and Microphone requirements (HTTPS)[cite: 3]
    socketio.run(app, debug=True, port=5000, host='0.0.0.0', ssl_context='adhoc')