const socket = io();
let room = null;
let myKeyPair = null;     
let peerPublicKey = null; 
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;
let myUsername = "Anonymous";
let peerUsername = "Unknown";

// --- CN PANEL STATE[cite: 1] ---
let pendingRttMap = {};   // msgId -> { sentAt, type }
let msgIdCounter  = 0;
let handshakeStart = null;
let hsTimings = {};       // step -> ms offset
let packetLog = [];

// ============================================================
// --- SECURITY ENFORCERS (DRM LAYER)[cite: 1, 2] ---
// ============================================================
document.addEventListener('contextmenu', event => event.preventDefault());

document.addEventListener('keydown', (e) => {
    // Block F12, Ctrl+Shift+I, Ctrl+Shift+J (DevTools)
    if (e.keyCode === 123 || (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74))) {
        e.preventDefault();
        return false;
    }
    // Block Ctrl+U (View Source)
    if (e.ctrlKey && e.keyCode === 85) {
        e.preventDefault();
        return false;
    }
    // Block Ctrl+S (Save), Ctrl+P (Print)
    if (e.ctrlKey && (e.keyCode === 83 || e.keyCode === 80)) {
        e.preventDefault();
        return false;
    }
    // Block Ctrl+C (Copy)
    if (e.ctrlKey && e.keyCode === 67) {
        if(document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            alert("SECURE TERMINAL: COPY DISABLED");
        }
    }
});

document.addEventListener('dragstart', (e) => e.preventDefault());

// ============================================================
// --- INITIALIZATION ---
// ============================================================
window.onload = function() {
    console.log("SecureSpeak System Online");
    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    if (urlRoom) document.getElementById('room-id').value = urlRoom;

    document.getElementById('btn-create').addEventListener('click', generateRoom);
    document.getElementById('btn-join').addEventListener('click', joinChat);
    document.getElementById('btn-copy').addEventListener('click', copyId);
    
    // CN Panel Toggle[cite: 1, 2]
    document.getElementById('toggle-cn-panel').addEventListener('click', () => {
        document.getElementById('cn-panel').classList.toggle('hidden');
    });

    document.getElementById('room-id').addEventListener('keyup', (e) => { if(e.key === 'Enter') joinChat(); });
    document.getElementById('username-input').addEventListener('keyup', (e) => { if(e.key === 'Enter') document.getElementById('room-id').focus(); });
    document.getElementById('message-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); sendTextMessage(); }
    });
};

function generateRoom() {
    const randomId = Array.from(window.crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('room-id').value = randomId;
    document.getElementById('share-link-text').innerText = randomId;
    document.getElementById('share-area').classList.remove('hidden');
}

async function joinChat() {
    room = document.getElementById('room-id').value.trim();
    const nameInput = document.getElementById('username-input').value.trim();
    myUsername = nameInput.length > 0 ? nameInput : "Anonymous";

    if (!room) return alert("ACCESS DENIED: Room ID Required");

    // Start Handshake Telemetry[cite: 1]
    handshakeStart = performance.now();
    hsTimings = { start: 0 };
    updateHandshakeTimeline();

    document.getElementById('display-username').innerText = myUsername.toUpperCase();

    try {
        // Step: RSA Keygen[cite: 1, 2]
        myKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );
        
        hsTimings.rsa_keygen = Math.round(performance.now() - handshakeStart);
        updateHandshakeTimeline();

        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('display-room').innerText = room;
        
        socket.emit('join', { room: room, username: myUsername });
    } catch (e) {
        console.error(e);
        alert("CRYPTO ERROR: Browser incompatible");
    }
}

// ============================================================
// --- SIGNALING & KEY EXCHANGE ---
// ============================================================
socket.on('user_joined', async (data) => {
    peerUsername = data.username || "Unknown";
    document.getElementById('status-text').innerHTML = `<span style='color:#bc13fe'>DETECTED: ${peerUsername}</span>`;
    
    const exportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
    socket.emit('signal_public_key', { room: room, key: exportedKey, request_reply: true, username: myUsername });
});

socket.on('receive_public_key', async (data) => {
    if(data.username) peerUsername = data.username;
    peerPublicKey = await window.crypto.subtle.importKey("jwk", data.key, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
    
    document.getElementById('status-text').innerHTML = `<span style='color:#00f3ff'>SECURE UPLINK: ${peerUsername}</span>`;
    document.getElementById('connection-dot').classList.add('active');

    // Step: Session Established[cite: 1]
    hsTimings.aes_session = Math.round(performance.now() - handshakeStart);
    updateHandshakeTimeline();

    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room: room, key: myExportedKey, request_reply: false, username: myUsername });
    }
});

// ============================================================
// --- ENCRYPTION & TELEMETRY LOGIC ---
// ============================================================
async function encryptAndSend(dataBuffer, type, isViewOnce = false) {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Wait for peer.");
    try {
        const msgId = ++msgIdCounter;
        const sentAt = performance.now();

        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataBuffer);
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawAesKey);

        const payload = {
            room: room, 
            type: type, 
            msgId: msgId, 
            sentAt: sentAt,
            iv: arrayBufferToBase64(iv),
            encryptedKey: arrayBufferToBase64(encryptedKey), 
            encryptedData: arrayBufferToBase64(encryptedData),
            isViewOnce: isViewOnce, 
            username: myUsername
        };

        // Log to CN Panel[cite: 1]
        logPacket('OUT', payload.iv, payload.encryptedData);
        socket.emit('encrypted_message', payload);

        pendingRttMap[msgId] = { sentAt, type };

        const msg = isViewOnce && (type === 'image' || type === 'audio') ? `SENT SELF-DESTRUCTING ${type.toUpperCase()}` : null;
        renderMessage(dataBuffer, type, 'sent', msg, isViewOnce, myUsername);
    } catch (err) { console.error("Encryption Error:", err); }
}

socket.on('receive_message', async (data) => {
    try {
        const recvAt = performance.now();
        
        // Log Packet and RTT[cite: 1, 3]
        logPacket('IN', data.iv, data.encryptedData);
        if (data.sentAt) {
            logRtt(data.type, Math.round(recvAt - data.sentAt));
        }

        const iv = base64ToArrayBuffer(data.iv);
        const encKey = base64ToArrayBuffer(data.encryptedKey);
        const encData = base64ToArrayBuffer(data.encryptedData);
        
        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encData);
        
        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce, data.username);
    } catch (e) { console.error("Decryption Error:", e); }
});

// ============================================================
// --- CN PANEL HELPERS[cite: 1] ---
// ============================================================
function logPacket(dir, iv, data) {
    const list = document.getElementById('pkt-list');
    const row = document.createElement('div');
    row.className = 'pkt-row';
    row.innerHTML = `
        <span class="pkt-dir ${dir === 'OUT' ? 'pkt-out' : 'pkt-in'}">${dir}</span>
        <div class="pkt-hex">
            <span class="hex-key">iv:</span> ${iv.substring(0,10)}...
            <span class="hex-key">dat:</span> ${data.substring(0,16)}...
        </div>
    `;
    list.prepend(row);
    if (list.children.length > 15) list.lastChild.remove();
}

function logRtt(type, ms) {
    const list = document.getElementById('rtt-list');
    const color = ms < 100 ? 'var(--neon-green)' : 'var(--neon-amber)';
    const entry = document.createElement('div');
    entry.style.cssText = `font-size:0.6rem; color:${color}; font-family:var(--font-code); margin-bottom:4px;`;
    entry.innerText = `> ${type.toUpperCase()} EXCHANGE: ${ms}ms`;
    list.prepend(entry);
    if (list.children.length > 10) list.lastChild.remove();
}

function updateHandshakeTimeline() {
    const steps = [
        { key: 'start', label: 'TCP/WS Uplink' },
        { key: 'rsa_keygen', label: 'RSA-2048 Generation' },
        { key: 'aes_session', label: 'Handshake Verified' }
    ];
    const container = document.getElementById('hs-steps');
    container.innerHTML = steps.map((s, i) => `
        <div class="hs-step">
            <div class="hs-num" style="background:${hsTimings[s.key] ? 'var(--neon-blue)' : 'transparent'}; color:${hsTimings[s.key] ? 'black' : 'inherit'}">
                ${hsTimings[s.key] ? '✓' : i+1}
            </div>
            <div class="hs-label" style="color:${hsTimings[s.key] ? 'var(--hs-label-done)' : 'var(--hs-label-pending)'}">
                ${s.label}
            </div>
            <div class="hs-ms">${hsTimings[s.key] !== undefined ? hsTimings[s.key] + 'ms' : '--'}</div>
        </div>
    `).join('');
}

// ============================================================
// --- UI & MEDIA HANDLERS[cite: 2] ---
// ============================================================
function sendTextMessage() {
    const input = document.getElementById('message-input');
    if (input.value) { encryptAndSend(new TextEncoder().encode(input.value), 'text'); input.value = ''; input.focus(); }
}

function triggerImageUpload(isViewOnce) {
    const fileInput = document.getElementById('image-input');
    fileInput.value = ''; fileInput.onchange = null; 
    fileInput.onchange = function(e) {
        const file = fileInput.files[0];
        if (file) { 
            const reader = new FileReader(); 
            reader.onload = (evt) => encryptAndSend(evt.target.result, 'image', isViewOnce); 
            reader.readAsArrayBuffer(file); 
        }
    };
    fileInput.click();
}

async function startRecording(isViewOnce) {
    currentRecordingModeViewOnce = isViewOnce;
    const btn = document.getElementById('record-btn');
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];
        mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: 'audio/webm' });
            encryptAndSend(await blob.arrayBuffer(), 'audio', currentRecordingModeViewOnce);
            btn.classList.remove('recording');
            stream.getTracks().forEach(track => track.stop());
        };
        mediaRecorder.start();
        btn.classList.add('recording');
    } catch (e) { console.error(e); alert("AUDIO HARDWARE BLOCKED"); }
}

function stopRecording() { if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop(); }

function renderMessage(buffer, type, source, customText = null, isViewOnce = false, senderName = "Anonymous") {
    const div = document.createElement('div');
    div.className = `message ${source}`;
    const nameLabel = document.createElement('div');
    nameLabel.className = 'sender-name';
    nameLabel.innerText = senderName;
    div.appendChild(nameLabel);

    if (customText) {
        div.innerHTML += `<i class="fas fa-info-circle"></i> ${customText}`;
        div.style.fontFamily = "var(--font-code)"; div.style.fontSize = "0.8rem";
    } else if (type === 'text') {
        div.innerHTML += new TextDecoder().decode(buffer);
    } else if (type === 'image') {
        const blob = new Blob([buffer]); const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            div.innerHTML += `<div class="vo-container"><div style="font-size:1rem; color:var(--neon-red); margin-bottom:5px">HIDDEN DATA</div><button class="vo-btn">REVEAL (10s)</button></div>`;
            div.querySelector('button').onclick = function() {
                openModal(url);
                div.innerHTML = `<span class="sender-name">${senderName}</span><span style="color:var(--neon-blue); font-family:var(--font-code)">[ VIEWING DATA... ]</span>`;
                startDestructTimer(div, url, "[ IMAGE SCRUBBED ]", true); 
            };
        } else {
            div.innerHTML += `<div class="media-content"><img src="${url}" onclick="openModal('${url}')" style="width:100%; height:100%; object-fit:cover; cursor:pointer;"></div>`;
        }
    } else if (type === 'audio') {
        const blob = new Blob([buffer]); const url = URL.createObjectURL(blob);
        if (isViewOnce && source === 'received') {
            div.innerHTML += `<div class="vo-container"><div style="font-size:1rem; color:var(--neon-red); margin-bottom:5px">AUDIO LOG</div><button class="vo-btn">PLAY</button></div>`;
            div.querySelector('button').onclick = function() {
                div.innerHTML = `<span class="sender-name">${senderName}</span><audio controls autoplay controlsList="nodownload" src="${url}"></audio>`;
                div.querySelector('audio').onended = function() { startDestructTimer(div, url, "[ AUDIO SCRUBBED ]"); };
            };
        } else { div.innerHTML += `<audio controls controlsList="nodownload" src="${url}"></audio>`; }
    }
    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function startDestructTimer(div, url, msg, closeActiveModal = false) {
    setTimeout(() => {
        div.innerHTML = `<span style="color:#555; font-family:var(--font-code)">${msg}</span>`;
        if(url) URL.revokeObjectURL(url);
        if(closeActiveModal) closeModal();
    }, 10000); 
}

function openModal(src) {
    document.getElementById('image-modal').classList.add('modal-active');
    document.getElementById('full-image').src = src;
}
function closeModal() {
    document.getElementById('image-modal').classList.remove('modal-active');
    setTimeout(() => { document.getElementById('full-image').src = ''; }, 300);
}
function copyId() {
    const text = document.getElementById('share-link-text').innerText;
    if(text) { navigator.clipboard.writeText(text); alert("ACCESS CODE COPIED"); }
}

// --- UTILS[cite: 2] ---
function arrayBufferToBase64(buffer) {
    let binary = ''; const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i += 8192) binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 8192, bytes.byteLength)));
    return window.btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64); const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Global Exports
window.generateRoom = generateRoom; window.joinChat = joinChat; window.copyId = copyId;
window.triggerImageUpload = triggerImageUpload; window.startRecording = startRecording; window.stopRecording = stopRecording;
window.sendTextMessage = sendTextMessage; window.closeModal = closeModal; window.openModal = openModal;