from flask import Flask, render_template, request
from flask_socketio import SocketIO, join_room, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure_speak_secret_key_2026'

socketio = SocketIO(app,
    cors_allowed_origins="*",
    max_http_buffer_size=50 * 1024 * 1024,
    ping_timeout=60,
    ping_interval=25,
    async_mode='threading'
)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    username = data.get('username', 'Anonymous')
    join_room(room)
    emit('user_joined', {'username': username, 'sid': request.sid}, to=room, include_self=False)

@socketio.on('signal_public_key')
def on_signal_public_key(data):
    room = data.get('room')
    emit('receive_public_key', data, to=room, include_self=False)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    """
    Relay to peers, then ack msgId back to sender for local RTT measurement.
    No sentAt needed — eliminates cross-device clock skew entirely.
    """
    room = data.get('room')
    msg_id = data.get('msgId')

    emit('receive_message', {
        'type': data.get('type'),
        'msgId': msg_id,
        'iv': data.get('iv'),
        'encryptedKey': data.get('encryptedKey'),
        'encryptedData': data.get('encryptedData'),
        'isViewOnce': data.get('isViewOnce', False),
        'username': data.get('username', 'Anonymous')
    }, to=room, include_self=False)

    # Ack sender so they compute RTT with their own clock
    emit('message_ack', {'msgId': msg_id}, to=request.sid)

@socketio.on('cn_ping')
def on_cn_ping(data):
    """Immediate pong for client-side RTT measurement."""
    emit('cn_pong', {'pingId': data.get('pingId')}, to=request.sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, host='0.0.0.0', ssl_context='adhoc')