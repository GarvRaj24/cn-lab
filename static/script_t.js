const socket = io();
let room = null;
let myKeyPair = null;     
let peerPublicKey = null; 
let mediaRecorder = null;
let audioChunks = [];
let currentRecordingModeViewOnce = false;
let myUsername = "Anonymous";
let peerUsername = "Unknown";

// --- SECURITY ENFORCERS (DRM LAYER) ---
document.addEventListener('contextmenu', event => event.preventDefault()); // Block Right Click

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
    // Block Ctrl+C (Copy) - Allow in input fields logic handled by CSS, but this is double tap
    if (e.ctrlKey && e.keyCode === 67) {
        // Check if not in input
        if(document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            alert("SECURE TERMINAL: COPY DISABLED");
        }
    }
});

// Block Dragging
document.addEventListener('dragstart', (e) => e.preventDefault());

window.onload = function() {
    console.log("SecureSpeak System Online");
    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    if (urlRoom) document.getElementById('room-id').value = urlRoom;

    document.getElementById('btn-create').addEventListener('click', generateRoom);
    document.getElementById('btn-join').addEventListener('click', joinChat);
    document.getElementById('btn-copy').addEventListener('click', copyId);
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
    if (nameInput.length > 0) myUsername = nameInput;
    else myUsername = "Anonymous";

    if (!room) return alert("ACCESS DENIED: Room ID Required");

    document.getElementById('display-username').innerText = myUsername.toUpperCase();

    try {
        myKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );
        
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('chat-screen').classList.remove('hidden');
        document.getElementById('display-room').innerText = room;
        
        socket.emit('join', { room: room, username: myUsername });
    } catch (e) {
        console.error(e);
        alert("CRYPTO ERROR: Browser incompatible");
    }
}

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
    if (data.request_reply) {
        const myExportedKey = await window.crypto.subtle.exportKey("jwk", myKeyPair.publicKey);
        socket.emit('signal_public_key', { room: room, key: myExportedKey, request_reply: false, username: myUsername });
    }
});

async function encryptAndSend(dataBuffer, type, isViewOnce = false) {
    if (!peerPublicKey) return alert("UPLINK OFFLINE: Wait for peer.");
    try {
        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, dataBuffer);
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, rawAesKey);

        socket.emit('encrypted_message', {
            room: room, type: type, iv: arrayBufferToBase64(iv),
            encryptedKey: arrayBufferToBase64(encryptedKey), encryptedData: arrayBufferToBase64(encryptedData),
            isViewOnce: isViewOnce, username: myUsername
        });
        const msg = isViewOnce && (type === 'image' || type === 'audio') ? `SENT SELF-DESTRUCTING ${type.toUpperCase()}` : null;
        renderMessage(dataBuffer, type, 'sent', msg, isViewOnce, myUsername);
    } catch (err) { console.error("Encryption Error:", err); }
}

socket.on('receive_message', async (data) => {
    try {
        const iv = base64ToArrayBuffer(data.iv);
        const encKey = base64ToArrayBuffer(data.encryptedKey);
        const encData = base64ToArrayBuffer(data.encryptedData);
        const rawAesKey = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, myKeyPair.privateKey, encKey);
        const aesKey = await window.crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encData);
        renderMessage(decryptedData, data.type, 'received', null, data.isViewOnce, data.username);
    } catch (e) { console.error("Decryption Error:", e); }
});

function sendTextMessage() {
    const input = document.getElementById('message-input');
    if (input.value) { encryptAndSend(new TextEncoder().encode(input.value), 'text'); input.value = ''; input.focus(); }
}

function triggerImageUpload(isViewOnce) {
    const fileInput = document.getElementById('image-input');
    fileInput.value = ''; fileInput.onchange = null; 
    fileInput.onchange = function(e) {
        const file = fileInput.files[0];
        if (file) { const reader = new FileReader(); reader.onload = (evt) => encryptAndSend(evt.target.result, 'image', isViewOnce); reader.readAsArrayBuffer(file); }
    };
    fileInput.click();
}

async function startRecording(isViewOnce) {
    currentRecordingModeViewOnce = isViewOnce;
    const btn = isViewOnce ? document.getElementById('record-btn-vo') : document.getElementById('record-btn');
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        audioChunks = [];
        mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: 'audio/webm' });
            encryptAndSend(await blob.arrayBuffer(), 'audio', currentRecordingModeViewOnce);
            btn.classList.remove('recording');
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
            div.innerHTML += `<div class="media-content"><img src="${url}" onclick="openModal('${url}')" style="cursor: pointer;"></div>`;
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

window.generateRoom = generateRoom; window.joinChat = joinChat; window.copyId = copyId;
window.triggerImageUpload = triggerImageUpload; window.startRecording = startRecording; window.stopRecording = stopRecording;
window.sendTextMessage = sendTextMessage; window.closeModal = closeModal; window.openModal = openModal;