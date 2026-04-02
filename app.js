/**
 * ========================================================
 * ENCRYPTED CHAT - WITH REAL-TIME SYNC & USERNAMES
 * ========================================================
 * Features: Real-time settings sync, usernames, group chat
 * ========================================================
 */

// ========================================================
// SECTION 1: CRYPTO UTILITIES (Same as before)
// ========================================================

const Crypto = {
    utf8ToArrayBuffer(str) {
        return new TextEncoder().encode(str);
    },

    arrayBufferToUtf8(buffer) {
        return new TextDecoder().decode(buffer);
    },

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    generateRandomBytes(length) {
        const buffer = new Uint8Array(length);
        crypto.getRandomValues(buffer);
        return buffer.buffer;
    },

    async deriveKeyPBKDF2(password, salt, iterations = 250000) {
        try {
            const passwordBuffer = this.utf8ToArrayBuffer(password);
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                passwordBuffer,
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            return key;
        } catch (error) {
            console.error('PBKDF2 key derivation failed:', error);
            throw new Error('Failed to derive encryption key');
        }
    },

    async deriveKeyArgon2(password, salt) {
        try {
            if (typeof argon2 === 'undefined') {
                console.warn('Argon2 not available, using PBKDF2');
                return this.deriveKeyPBKDF2(password, salt);
            }

            const result = await argon2.hash({
                pass: password,
                salt: new Uint8Array(salt),
                type: argon2.ArgonType.Argon2id,
                time: 3,
                mem: 65536,
                hashLen: 32,
                parallelism: 4
            });

            const key = await crypto.subtle.importKey(
                'raw',
                result.hash,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
            );

            return key;
        } catch (error) {
            console.error('Argon2 failed, falling back to PBKDF2:', error);
            return this.deriveKeyPBKDF2(password, salt);
        }
    },

    async aesGcmEncrypt(key, data) {
        try {
            const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
            const plaintextBuffer = this.utf8ToArrayBuffer(plaintext);
            const iv = this.generateRandomBytes(12);

            const ciphertextBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                key,
                plaintextBuffer
            );

            return {
                ciphertext: this.arrayBufferToBase64(ciphertextBuffer),
                iv: this.arrayBufferToBase64(iv)
            };
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error('Failed to encrypt data');
        }
    },

    async aesGcmDecrypt(key, ciphertext, iv, parseJSON = false) {
        try {
            const ciphertextBuffer = this.base64ToArrayBuffer(ciphertext);
            const ivBuffer = this.base64ToArrayBuffer(iv);

            const plaintextBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivBuffer,
                    tagLength: 128
                },
                key,
                ciphertextBuffer
            );

            const plaintext = this.arrayBufferToUtf8(plaintextBuffer);

            if (parseJSON) {
                try {
                    return JSON.parse(plaintext);
                } catch (e) {
                    return plaintext;
                }
            }

            return plaintext;
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Decryption failed - invalid password or corrupted data');
        }
    },

    async createRoomCheck(key) {
        return await this.aesGcmEncrypt(key, 'ROOM_OK');
    },

    async verifyRoomPassword(key, roomCheck) {
        try {
            const decrypted = await this.aesGcmDecrypt(key, roomCheck.ciphertext, roomCheck.iv);
            return decrypted === 'ROOM_OK';
        } catch (error) {
            return false;
        }
    }
};

// ========================================================
// SECTION 2: FIREBASE CONFIGURATION
// ========================================================

const Firebase = {
    app: null,
    database: null,

    async init() {
        // TODO: Replace with your Firebase config
           const firebaseConfig = {
            apiKey: "AIzaSyAS_HheqFK98UIvjtiBxtHSOkOfuaOkkug",
            authDomain: "kwit-5dde3.firebaseapp.com",
            databaseURL: "https://kwit-5dde3-default-rtdb.firebaseio.com",
            projectId: "kwit-5dde3",
            storageBucket: "kwit-5dde3.firebasestorage.app",
            messagingSenderId: "692601571855",
            appId: "1:692601571855:web:03e8538f22f47202a5f17a"
        };


        try {
            const { initializeApp } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js');
            const { getDatabase, ref, set, get, push, onChildAdded, onValue, update, off } = 
                await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js');

            this.app = initializeApp(firebaseConfig);
            this.database = getDatabase(this.app);
            
            this.ref = ref;
            this.set = set;
            this.get = get;
            this.push = push;
            this.onChildAdded = onChildAdded;
            this.onValue = onValue;
            this.update = update;
            this.off = off;

            console.log('✅ Firebase initialized');
            return true;
        } catch (error) {
            console.error('❌ Firebase initialization failed:', error);
            alert('Firebase configuration error. Please update Firebase config in app.js');
            return false;
        }
    },

    async writeData(path, data) {
        const dbRef = this.ref(this.database, path);
        await this.set(dbRef, data);
    },

    async readData(path) {
        const dbRef = this.ref(this.database, path);
        const snapshot = await this.get(dbRef);
        return snapshot.exists() ? snapshot.val() : null;
    },

    listenToNewChildren(path, callback) {
        const dbRef = this.ref(this.database, path);
        this.onChildAdded(dbRef, (snapshot) => {
            callback({
                id: snapshot.key,
                data: snapshot.val()
            });
        });
        return () => this.off(dbRef);
    },

    listenToValue(path, callback) {
        const dbRef = this.ref(this.database, path);
        this.onValue(dbRef, (snapshot) => {
            callback(snapshot.val());
        });
        return () => this.off(dbRef);
    },

    async pushData(path, data) {
        const dbRef = this.ref(this.database, path);
        const newRef = this.push(dbRef);
        await this.set(newRef, data);
        return newRef.key;
    },

    async updateData(path, updates) {
        const dbRef = this.ref(this.database, path);
        await this.update(dbRef, updates);
    },

    getServerTimestamp() {
        return { '.sv': 'timestamp' };
    }
};

// ========================================================
// SECTION 3: ROOM MANAGEMENT
// ========================================================

const Room = {
    current: {
        id: null,
        name: null,
        masterKey: null,
        userId: null,
        username: null
    },

    generateRoomId() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let roomId = '';
        const randomBytes = new Uint8Array(12);
        crypto.getRandomValues(randomBytes);
        
        for (let i = 0; i < 12; i++) {
            roomId += chars[randomBytes[i] % chars.length];
        }
        return roomId;
    },

    generateUserId() {
        return 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    },

    async create(roomName, password, username) {
        try {
            if (!password || password.length < 6) {
                throw new Error('Password must be at least 6 characters');
            }

            if (!username || username.trim() === '') {
                throw new Error('Username is required');
            }

            UI.showLoading('Creating secure room...');

            const roomId = this.generateRoomId();
            const salt = Crypto.generateRandomBytes(16);
            const saltBase64 = Crypto.arrayBufferToBase64(salt);

            console.log('🔑 Deriving Room Master Key...');
            const masterKey = await Crypto.deriveKeyArgon2(password, salt);
            const roomCheck = await Crypto.createRoomCheck(masterKey);

            // Encrypt default settings
            const defaultSettings = Settings.getDefaultSettings();
            const encryptedSettings = await Crypto.aesGcmEncrypt(masterKey, defaultSettings);

            const roomData = {
                salt: saltBase64,
                roomCheck: roomCheck,
                roomName: roomName || 'Untitled Room',
                createdAt: Firebase.getServerTimestamp(),
                settings: encryptedSettings
            };

            await Firebase.writeData(`rooms/${roomId}`, roomData);

            this.current.id = roomId;
            this.current.name = roomName || 'Untitled Room';
            this.current.masterKey = masterKey;
            this.current.userId = this.generateUserId();
            this.current.username = username.trim();

            // Register user in room
            await this.registerUser();

            const roomLink = `${window.location.origin}${window.location.pathname}?room=${roomId}`;

            console.log('✅ Room created:', roomId);
            UI.hideLoading();

            return { roomId, roomLink };
        } catch (error) {
            UI.hideLoading();
            console.error('❌ Room creation failed:', error);
            throw error;
        }
    },

    async join(roomId, password, username) {
        try {
            if (!roomId || !password) {
                throw new Error('Room ID and password required');
            }

            if (!username || username.trim() === '') {
                throw new Error('Username is required');
            }

            UI.showLoading('Joining room...');

            const roomData = await Firebase.readData(`rooms/${roomId}`);
            
            if (!roomData) {
                throw new Error('Room not found');
            }

            if (!roomData.salt || !roomData.roomCheck) {
                throw new Error('Invalid room data');
            }

            const salt = Crypto.base64ToArrayBuffer(roomData.salt);

            console.log('🔑 Deriving key from password...');
            const derivedKey = await Crypto.deriveKeyArgon2(password, salt);

            const isPasswordCorrect = await Crypto.verifyRoomPassword(derivedKey, roomData.roomCheck);

            if (!isPasswordCorrect) {
                throw new Error('Invalid password');
            }

            this.current.id = roomId;
            this.current.name = roomData.roomName || 'Chat Room';
            this.current.masterKey = derivedKey;
            this.current.userId = this.generateUserId();
            this.current.username = username.trim();

            // Register user in room
            await this.registerUser();

            console.log('✅ Joined room:', roomId);
            UI.hideLoading();

            return {
                success: true,
                roomName: this.current.name
            };
        } catch (error) {
            UI.hideLoading();
            console.error('❌ Join room failed:', error);
            throw error;
        }
    },

    async registerUser() {
        // Encrypt and store username
        const encryptedUsername = await Crypto.aesGcmEncrypt(
            this.current.masterKey,
            this.current.username
        );

        await Firebase.updateData(`rooms/${this.current.id}/users/${this.current.userId}`, {
            username: encryptedUsername,
            joinedAt: Firebase.getServerTimestamp(),
            online: true
        });
    },

    async getUsernames() {
        const usersData = await Firebase.readData(`rooms/${this.current.id}/users`);
        const usernames = {};

        if (usersData) {
            for (const [userId, data] of Object.entries(usersData)) {
                try {
                    const decrypted = await Crypto.aesGcmDecrypt(
                        this.current.masterKey,
                        data.username.ciphertext,
                        data.username.iv
                    );
                    usernames[userId] = decrypted;
                } catch (error) {
                    console.error('Failed to decrypt username:', error);
                    usernames[userId] = 'Unknown';
                }
            }
        }

        return usernames;
    },

    leave() {
        // Mark user as offline
        if (this.isInRoom()) {
            Firebase.updateData(`rooms/${this.current.id}/users/${this.current.userId}`, {
                online: false
            });
        }

        Messaging.clearListeners();
        Settings.clearMusic();
        Settings.stopListeningToSettings();
        
        this.current = {
            id: null,
            name: null,
            masterKey: null,
            userId: null,
            username: null
        };
    },

    isInRoom() {
        return this.current.id !== null && this.current.masterKey !== null;
    },

    getRoomIdFromUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get('room');
    }
};

// ========================================================
// SECTION 4: MESSAGING
// ========================================================

const Messaging = {
    listeners: [],
    typingTimeout: null,
    typingListenerUnsubscribe: null,
    usernames: {},

    async send(text) {
        try {
            if (!Room.isInRoom()) {
                throw new Error('Not in a room');
            }

            if (!text || text.trim() === '') {
                throw new Error('Message cannot be empty');
            }

            const messageObj = {
                text: text.trim(),
                author: Room.current.userId,
                username: Room.current.username,
                timestamp: Date.now()
            };

            console.log('🔒 Encrypting message...');
            const encrypted = await Crypto.aesGcmEncrypt(Room.current.masterKey, messageObj);

            const firebaseMessage = {
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv,
                serverTimestamp: Firebase.getServerTimestamp()
            };

            const messageId = await Firebase.pushData(`rooms/${Room.current.id}/messages`, firebaseMessage);

            console.log('✅ Message sent:', messageId);
            await this.setTypingStatus(false);

            return messageId;
        } catch (error) {
            console.error('❌ Send message failed:', error);
            throw error;
        }
    },

    async listen(callback) {
        if (!Room.isInRoom()) return;

        // Load usernames first
        this.usernames = await Room.getUsernames();

        let processedMessages = new Set();

        console.log('👂 Listening for messages...');

        const unsubscribe = Firebase.listenToNewChildren(`rooms/${Room.current.id}/messages`, async (snapshot) => {
            try {
                const messageId = snapshot.id;
                const encryptedMessage = snapshot.data;

                if (processedMessages.has(messageId)) return;
                processedMessages.add(messageId);

                const decrypted = await Crypto.aesGcmDecrypt(
                    Room.current.masterKey,
                    encryptedMessage.ciphertext,
                    encryptedMessage.iv,
                    true
                );

                const message = {
                    id: messageId,
                    text: decrypted.text,
                    author: decrypted.author,
                    username: decrypted.username || this.usernames[decrypted.author] || 'Unknown',
                    timestamp: decrypted.timestamp,
                    isMe: decrypted.author === Room.current.userId
                };

                callback(message);

            } catch (error) {
                console.error('❌ Failed to decrypt message:', error);
                callback({
                    id: snapshot.id,
                    text: '[Unable to decrypt - wrong password?]',
                    author: 'system',
                    username: 'System',
                    timestamp: Date.now(),
                    isMe: false,
                    error: true
                });
            }
        });

        this.listeners.push(unsubscribe);
    },

    async setTypingStatus(isTyping) {
        if (!Room.isInRoom()) return;

        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }

        if (isTyping) {
            // Encrypt username for typing indicator
            const encryptedUsername = await Crypto.aesGcmEncrypt(
                Room.current.masterKey,
                Room.current.username
            );

            await Firebase.updateData(`rooms/${Room.current.id}/typing/${Room.current.userId}`, {
                isTyping: true,
                username: encryptedUsername,
                timestamp: Firebase.getServerTimestamp()
            });

            this.typingTimeout = setTimeout(() => {
                this.setTypingStatus(false);
            }, 3000);
        } else {
            await Firebase.updateData(`rooms/${Room.current.id}/typing/${Room.current.userId}`, {
                isTyping: false
            });
        }
    },

    listenForTyping(callback) {
        if (!Room.isInRoom()) return;

        this.typingListenerUnsubscribe = Firebase.listenToValue(
            `rooms/${Room.current.id}/typing`,
            async (typingData) => {
                if (!typingData) {
                    callback(null);
                    return;
                }

                // Find who is typing (excluding self)
                for (const [userId, data] of Object.entries(typingData)) {
                    if (userId !== Room.current.userId && data.isTyping === true) {
                        let username = 'Someone';
                        
                        if (data.username) {
                            try {
                                username = await Crypto.aesGcmDecrypt(
                                    Room.current.masterKey,
                                    data.username.ciphertext,
                                    data.username.iv
                                );
                            } catch (error) {
                                console.error('Failed to decrypt typing username');
                            }
                        }
                        
                        callback(username);
                        return;
                    }
                }

                callback(null);
            }
        );
    },

    clearListeners() {
        this.listeners.forEach(unsubscribe => unsubscribe());
        this.listeners = [];
        
        if (this.typingListenerUnsubscribe) {
            this.typingListenerUnsubscribe();
            this.typingListenerUnsubscribe = null;
        }
        
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
    }
};

// ========================================================
// SECTION 5: SETTINGS & CUSTOMIZATION
// ========================================================

const Settings = {
    currentSettings: null,
    settingsListener: null,

    getDefaultSettings() {
        return {
            // Background
            bgColor: '#0f0f23',
            bgImage: null,
            bgOpacity: 100,
            
            // Chat colors
            myBubbleColor: '#6c5ce7',
            otherBubbleColor: '#a29bfe',
            myTextColor: '#ffffff',
            otherTextColor: '#ffffff',
            chatBgColor: '#0f0f23',
            
            // Shapes
            bubbleShape: 'rounded',
            inputShape: 'rounded',
            buttonShape: 'rounded',
            
            // Header
            headerVisible: true,
            headerBgColor: '#16213e',
            headerTextColor: '#eaeaea',
            
            // Text
            fontSize: '16',
            fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
            
            // Music
            musicEnabled: false,
            musicFile: null,
            musicVolume: 50,
            
            // Background text
            bgTextEnabled: false,
            bgText: '',
            bgTextSize: 40,
            bgTextColor: '#ffffff',
            bgTextPosition: 'center',
            
            // Timestamp
            lastUpdated: Date.now(),

            // Robot AI
            robotProvider: 'cerebras'
        };
    },

    async load() {
        if (!Room.isInRoom()) return;

        try {
            const roomData = await Firebase.readData(`rooms/${Room.current.id}`);
            
            if (roomData && roomData.settings) {
                const decrypted = await Crypto.aesGcmDecrypt(
                    Room.current.masterKey,
                    roomData.settings.ciphertext,
                    roomData.settings.iv,
                    true
                );
                
                this.currentSettings = { ...this.getDefaultSettings(), ...decrypted };
            } else {
                this.currentSettings = this.getDefaultSettings();
            }

            this.apply();
            this.updateUI();
            
            // Start listening for settings changes
            this.listenToSettings();
            
            console.log('✅ Settings loaded');
        } catch (error) {
            console.error('Failed to load settings:', error);
            this.currentSettings = this.getDefaultSettings();
            this.apply();
        }
    },

    listenToSettings() {
        if (!Room.isInRoom() || this.settingsListener) return;

        console.log('👂 Listening for settings changes...');

        this.settingsListener = Firebase.listenToValue(
            `rooms/${Room.current.id}/settings`,
            async (settingsData) => {
                if (!settingsData) return;

                try {
                    const decrypted = await Crypto.aesGcmDecrypt(
                        Room.current.masterKey,
                        settingsData.ciphertext,
                        settingsData.iv,
                        true
                    );

                    // Only update if settings are newer
                    if (decrypted.lastUpdated > this.currentSettings.lastUpdated) {
                        console.log('📥 Settings updated from another user');
                        this.currentSettings = { ...this.getDefaultSettings(), ...decrypted };
                        this.apply();
                        this.updateUI();
                    }
                } catch (error) {
                    console.error('Failed to decrypt settings update:', error);
                }
            }
        );
    },

    stopListeningToSettings() {
        if (this.settingsListener) {
            this.settingsListener();
            this.settingsListener = null;
        }
    },

    async save() {
        if (!Room.isInRoom()) return;

        try {
            // Update timestamp
            this.currentSettings.lastUpdated = Date.now();

            const encrypted = await Crypto.aesGcmEncrypt(
                Room.current.masterKey,
                this.currentSettings
            );

            await Firebase.updateData(`rooms/${Room.current.id}`, {
                settings: encrypted
            });

            console.log('✅ Settings saved and synced to all users');
        } catch (error) {
            console.error('Failed to save settings:', error);
            throw error;
        }
    },

    apply() {
        const s = this.currentSettings;
        const root = document.documentElement;

        // Apply CSS variables
        root.style.setProperty('--chat-bg', s.chatBgColor);
        root.style.setProperty('--bubble-me', s.myBubbleColor);
        root.style.setProperty('--bubble-other', s.otherBubbleColor);
        root.style.setProperty('--text-me', s.myTextColor);
        root.style.setProperty('--text-other', s.otherTextColor);
        root.style.setProperty('--header-bg', s.headerBgColor);
        root.style.setProperty('--header-text', s.headerTextColor);
        root.style.setProperty('--font-size', s.fontSize + 'px');
        root.style.setProperty('--font-family', s.fontFamily);

        // Apply shapes
        const shapeValues = {
            rounded: { bubble: '18px', input: '24px', button: '8px' },
            medium: { bubble: '10px', input: '12px', button: '4px' },
            sharp: { bubble: '0px', input: '0px', button: '0px' },
            circle: { bubble: '30px', input: '24px', button: '8px' },
            pill: { bubble: '18px', input: '24px', button: '50px' }
        };

        root.style.setProperty('--bubble-radius', shapeValues[s.bubbleShape]?.bubble || '18px');
        root.style.setProperty('--input-radius', shapeValues[s.inputShape]?.input || '24px');
        root.style.setProperty('--button-radius', shapeValues[s.buttonShape]?.button || '8px');

        // Apply background
        const bgLayer = document.getElementById('backgroundImageLayer');
        if (bgLayer) {
            if (s.bgImage) {
                bgLayer.style.backgroundImage = `url(${s.bgImage})`;
                bgLayer.style.opacity = s.bgOpacity / 100;
            } else {
                bgLayer.style.backgroundImage = '';
                bgLayer.style.opacity = 1;
            }
        }

        // Apply header visibility
        const header = document.getElementById('chatHeader');
        if (header) {
            if (s.headerVisible) {
                header.classList.remove('hidden');
            } else {
                header.classList.add('hidden');
            }
        }

        // Apply background text
        this.applyBackgroundText();

        // Apply music
        if (s.musicEnabled && s.musicFile) {
            this.playMusic(s.musicFile, s.musicVolume);
        } else {
            this.clearMusic();
        }

        // Apply robot AI provider
        if (s.robotProvider && window.ROBOT_PROVIDER !== undefined) {
            window.ROBOT_PROVIDER = s.robotProvider;
            // Sync UI buttons
            document.querySelectorAll('.provider-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.provider === s.robotProvider);
            });
        }
    },

    applyBackgroundText() {
        const s = this.currentSettings;
        
        // Remove existing overlay
        const existing = document.querySelector('.background-text-overlay');
        if (existing) existing.remove();

        if (s.bgTextEnabled && s.bgText) {
            const overlay = document.createElement('div');
            overlay.className = `background-text-overlay ${s.bgTextPosition}`;
            overlay.textContent = s.bgText;
            overlay.style.fontSize = s.bgTextSize + 'px';
            overlay.style.color = s.bgTextColor;
            
            const chatScreen = document.getElementById('chatScreen');
            if (chatScreen) {
                chatScreen.appendChild(overlay);
            }
        }
    },

    updateUI() {
        const s = this.currentSettings;
        const sv = (id, val) => { const el = document.getElementById(id); if(el) el.value = val; };
        const sc = (id, val) => { const el = document.getElementById(id); if(el) el.checked = val; };
        const st = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };

        // Update color pickers
        sv('bgColorPicker', s.bgColor);
        sv('myBubbleColorPicker', s.myBubbleColor);
        sv('otherBubbleColorPicker', s.otherBubbleColor);
        sv('myTextColorPicker', s.myTextColor);
        sv('otherTextColorPicker', s.otherTextColor);
        sv('chatBgColorPicker', s.chatBgColor);
        sv('headerBgColorPicker', s.headerBgColor);
        sv('headerTextColorPicker', s.headerTextColor);
        sv('bgTextColorPicker', s.bgTextColor);

        // Update selects
        sv('bubbleShapeSelect', s.bubbleShape);
        sv('inputShapeSelect', s.inputShape);
        sv('buttonShapeSelect', s.buttonShape);
        sv('fontSizeSelect', s.fontSize);
        sv('fontFamilySelect', s.fontFamily);
        sv('bgTextPositionSelect', s.bgTextPosition);

        // Update toggles
        sc('headerVisibleToggle', s.headerVisible);
        sc('musicToggle', s.musicEnabled);
        sc('bgTextToggle', s.bgTextEnabled);

        // Update sliders
        sv('bgOpacitySlider', s.bgOpacity);
        st('bgOpacityValue', s.bgOpacity + '%');
        sv('bgTextSizeSlider', s.bgTextSize);
        st('bgTextSizeValue', s.bgTextSize + 'px');
        sv('musicVolumeSlider', s.musicVolume);
        st('musicVolumeValue', s.musicVolume + '%');

        // Update text input
        sv('bgTextInput', s.bgText);

        // Update music controls
        if (s.musicFile) {
            const mc = document.getElementById('musicControls');
            if(mc) mc.classList.remove('hidden');
            st('musicFileName', 'Music loaded');
        }

        // Update robot provider UI
        if (s.robotProvider) {
            document.querySelectorAll('.provider-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.provider === s.robotProvider);
            });
            const labels = {cerebras:'🟢 Cerebras — Fastest • Best for real-time',groq:'🔵 Groq — Fast • Multiple models',openrouter:'🟣 OpenRouter — Wide model selection',nvidia:'🟡 NVIDIA — High quality • Slower'};
            st('providerStatus', labels[s.robotProvider] || s.robotProvider);
        }
    },

    playMusic(dataUrl, volume) {
        const audio = document.getElementById('backgroundAudio');
        if (audio.src !== dataUrl) {
            audio.src = dataUrl;
        }
        audio.volume = volume / 100;
        audio.play().catch(e => console.log('Music autoplay blocked:', e));
    },

    clearMusic() {
        const audio = document.getElementById('backgroundAudio');
        audio.pause();
        audio.currentTime = 0;
    },

    reset() {
        this.currentSettings = this.getDefaultSettings();
        this.apply();
        this.updateUI();
    }
};

// ========================================================
// SECTION 6: UI CONTROLLER
// ========================================================

const UI = {
    currentScreen: 'welcome',

    async init() {
        console.log('🎨 Initializing UI...');

        const firebaseReady = await Firebase.init();
        if (!firebaseReady) {
            alert('Firebase is not configured. Please update the config in app.js');
            return;
        }

        this.setupEventListeners();

        const roomId = Room.getRoomIdFromUrl();
        if (roomId) {
            this.showScreen('joinRoom');
            document.getElementById('roomLinkInput').value = roomId;
        }

        console.log('✅ UI initialized');
    },

    setupEventListeners() {
        // Welcome screen
        document.getElementById('createRoomBtn').addEventListener('click', () => {
            this.showScreen('createRoom');
        });

        document.getElementById('joinRoomBtn').addEventListener('click', () => {
            this.showScreen('joinRoom');
        });

        // Create room
        document.getElementById('confirmCreateBtn').addEventListener('click', async () => {
            await this.handleCreateRoom();
        });

        document.getElementById('cancelCreateBtn').addEventListener('click', () => {
            this.showScreen('welcome');
        });

        // Join room
        document.getElementById('confirmJoinBtn').addEventListener('click', async () => {
            await this.handleJoinRoom();
        });

        document.getElementById('cancelJoinBtn').addEventListener('click', () => {
            this.showScreen('welcome');
        });

        // Chat screen
        document.getElementById('sendMessageBtn').addEventListener('click', async () => {
            await this.handleSendMessage();
        });

        document.getElementById('messageInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.handleSendMessage();
            }
        });

        document.getElementById('messageInput').addEventListener('input', () => {
            Messaging.setTypingStatus(true);
        });

        document.getElementById('leaveRoomBtn').addEventListener('click', () => {
            this.handleLeaveRoom();
        });

        document.getElementById('shareRoomBtn').addEventListener('click', () => {
            this.showShareModal();
        });

        document.getElementById('settingsBtn').addEventListener('click', () => {
            this.toggleSettings();
        });

        // Settings panel
        this.setupSettingsListeners();

        // Share modal
        document.getElementById('closeShareModal').addEventListener('click', () => {
            document.getElementById('shareModal').classList.add('hidden');
        });

        document.getElementById('copyLinkBtn').addEventListener('click', () => {
            const input = document.getElementById('shareLinkInput');
            input.select();
            document.execCommand('copy');
            alert('Link copied to clipboard!');
        });
    },

    setupSettingsListeners() {
        // Close settings
        document.getElementById('closeSettingsBtn').addEventListener('click', () => {
            this.toggleSettings();
        });

        // Background color
        document.getElementById('bgColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.bgColor = e.target.value;
            document.documentElement.style.setProperty('--chat-bg', e.target.value);
        });

        document.getElementById('chatBgColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.chatBgColor = e.target.value;
            document.documentElement.style.setProperty('--chat-bg', e.target.value);
        });

        // Background image
        document.getElementById('uploadBgImageBtn').addEventListener('click', () => {
            document.getElementById('bgImageInput').click();
        });

        document.getElementById('bgImageInput').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    Settings.currentSettings.bgImage = event.target.result;
                    Settings.apply();
                };
                reader.readAsDataURL(file);
            }
        });

        document.getElementById('removeBgImageBtn').addEventListener('click', () => {
            Settings.currentSettings.bgImage = null;
            Settings.apply();
        });

        document.getElementById('bgOpacitySlider').addEventListener('input', (e) => {
            Settings.currentSettings.bgOpacity = parseInt(e.target.value);
            document.getElementById('bgOpacityValue').textContent = e.target.value + '%';
            Settings.apply();
        });

        // Bubble colors
        document.getElementById('myBubbleColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.myBubbleColor = e.target.value;
            Settings.apply();
        });

        document.getElementById('otherBubbleColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.otherBubbleColor = e.target.value;
            Settings.apply();
        });

        document.getElementById('myTextColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.myTextColor = e.target.value;
            Settings.apply();
        });

        document.getElementById('otherTextColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.otherTextColor = e.target.value;
            Settings.apply();
        });

        // Shapes
        document.getElementById('bubbleShapeSelect').addEventListener('change', (e) => {
            Settings.currentSettings.bubbleShape = e.target.value;
            Settings.apply();
        });

        document.getElementById('inputShapeSelect').addEventListener('change', (e) => {
            Settings.currentSettings.inputShape = e.target.value;
            Settings.apply();
        });

        document.getElementById('buttonShapeSelect').addEventListener('change', (e) => {
            Settings.currentSettings.buttonShape = e.target.value;
            Settings.apply();
        });

        // Header
        document.getElementById('headerVisibleToggle').addEventListener('change', (e) => {
            Settings.currentSettings.headerVisible = e.target.checked;
            Settings.apply();
        });

        document.getElementById('headerBgColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.headerBgColor = e.target.value;
            Settings.apply();
        });

        document.getElementById('headerTextColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.headerTextColor = e.target.value;
            Settings.apply();
        });

        // Font
        document.getElementById('fontSizeSelect').addEventListener('change', (e) => {
            Settings.currentSettings.fontSize = e.target.value;
            Settings.apply();
        });

        document.getElementById('fontFamilySelect').addEventListener('change', (e) => {
            Settings.currentSettings.fontFamily = e.target.value;
            Settings.apply();
        });

        // Background music
        document.getElementById('musicToggle').addEventListener('change', (e) => {
            Settings.currentSettings.musicEnabled = e.target.checked;
            if (e.target.checked && Settings.currentSettings.musicFile) {
                Settings.playMusic(Settings.currentSettings.musicFile, Settings.currentSettings.musicVolume);
            } else {
                Settings.clearMusic();
            }
        });

        document.getElementById('uploadMusicBtn').addEventListener('click', () => {
            document.getElementById('musicFileInput').click();
        });

        document.getElementById('musicFileInput').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    Settings.currentSettings.musicFile = event.target.result;
                    document.getElementById('musicControls').classList.remove('hidden');
                    document.getElementById('musicFileName').textContent = file.name;
                };
                reader.readAsDataURL(file);
            }
        });

        document.getElementById('playMusicBtn').addEventListener('click', () => {
            const audio = document.getElementById('backgroundAudio');
            audio.play();
        });

        document.getElementById('pauseMusicBtn').addEventListener('click', () => {
            const audio = document.getElementById('backgroundAudio');
            audio.pause();
        });

        document.getElementById('stopMusicBtn').addEventListener('click', () => {
            const audio = document.getElementById('backgroundAudio');
            audio.pause();
            audio.currentTime = 0;
        });

        document.getElementById('musicVolumeSlider').addEventListener('input', (e) => {
            Settings.currentSettings.musicVolume = parseInt(e.target.value);
            document.getElementById('musicVolumeValue').textContent = e.target.value + '%';
            const audio = document.getElementById('backgroundAudio');
            audio.volume = e.target.value / 100;
        });

        // Background text
        document.getElementById('bgTextToggle').addEventListener('change', (e) => {
            Settings.currentSettings.bgTextEnabled = e.target.checked;
            Settings.apply();
        });

        document.getElementById('bgTextInput').addEventListener('input', (e) => {
            Settings.currentSettings.bgText = e.target.value;
            Settings.applyBackgroundText();
        });

        document.getElementById('bgTextSizeSlider').addEventListener('input', (e) => {
            Settings.currentSettings.bgTextSize = parseInt(e.target.value);
            document.getElementById('bgTextSizeValue').textContent = e.target.value + 'px';
            Settings.applyBackgroundText();
        });

        document.getElementById('bgTextColorPicker').addEventListener('change', (e) => {
            Settings.currentSettings.bgTextColor = e.target.value;
            Settings.applyBackgroundText();
        });

        document.getElementById('bgTextPositionSelect').addEventListener('change', (e) => {
            Settings.currentSettings.bgTextPosition = e.target.value;
            Settings.applyBackgroundText();
        });

        // Save/Reset
        document.getElementById('saveSettingsBtn').addEventListener('click', async () => {
            try {
                // Capture robot provider before saving
                if (window.ROBOT_PROVIDER) {
                    Settings.currentSettings.robotProvider = window.ROBOT_PROVIDER;
                }
                await Settings.save();
                alert('✅ Settings saved and synced to all users!');
            } catch (error) {
                alert('❌ Failed to save settings: ' + error.message);
            }
        });

        document.getElementById('resetSettingsBtn').addEventListener('click', () => {
            if (confirm('Reset all settings to default?')) {
                Settings.reset();
                alert('✅ Settings reset to default');
            }
        });

        // Provider buttons — also update Settings.currentSettings
        document.querySelectorAll('.provider-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                Settings.currentSettings.robotProvider = btn.dataset.provider;
            });
        });
    },

    showScreen(screenName) {
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });

        const screen = document.getElementById(screenName + 'Screen');
        if (screen) {
            screen.classList.add('active');
            this.currentScreen = screenName;
        }
    },

    showLoading(text = 'Loading...') {
        const overlay = document.getElementById('loadingOverlay');
        const loadingText = document.getElementById('loadingText');
        if (overlay) {
            loadingText.textContent = text;
            overlay.classList.remove('hidden');
        }
    },

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.add('hidden');
        }
    },

    async handleCreateRoom() {
        const roomName = document.getElementById('roomNameInput').value.trim();
        const password = document.getElementById('createPasswordInput').value;
        const confirmPassword = document.getElementById('confirmPasswordInput').value;
        const status = document.getElementById('createRoomStatus');

        // Prompt for username
        const username = prompt('Enter your username:');
        if (!username || username.trim() === '') {
            status.textContent = 'Username is required';
            status.className = 'status-message error';
            return;
        }

        if (!password || password.length < 6) {
            status.textContent = 'Password must be at least 6 characters';
            status.className = 'status-message error';
            return;
        }

        if (password !== confirmPassword) {
            status.textContent = 'Passwords do not match';
            status.className = 'status-message error';
            return;
        }

        try {
            await Room.create(roomName, password, username);
            
            status.textContent = 'Room created successfully!';
            status.className = 'status-message success';

            setTimeout(() => {
                this.showScreen('chat');
                this.initChat();
            }, 1000);
        } catch (error) {
            status.textContent = error.message;
            status.className = 'status-message error';
        }
    },

    async handleJoinRoom() {
        let roomInput = document.getElementById('roomLinkInput').value.trim();
        const password = document.getElementById('joinPasswordInput').value;
        const status = document.getElementById('joinRoomStatus');

        // Prompt for username
        const username = prompt('Enter your username:');
        if (!username || username.trim() === '') {
            status.textContent = 'Username is required';
            status.className = 'status-message error';
            return;
        }

        if (roomInput.includes('?room=')) {
            const url = new URL(roomInput);
            roomInput = url.searchParams.get('room');
        }

        if (!roomInput || !password) {
            status.textContent = 'Room ID and password required';
            status.className = 'status-message error';
            return;
        }

        try {
            await Room.join(roomInput, password, username);
            
            status.textContent = 'Joined successfully!';
            status.className = 'status-message success';

            setTimeout(() => {
                this.showScreen('chat');
                this.initChat();
            }, 1000);
        } catch (error) {
            status.textContent = 'Invalid room ID or password';
            status.className = 'status-message error';
        }
    },

    async initChat() {
        document.getElementById('roomNameDisplay').textContent = Room.current.name;
        document.getElementById('roomIdDisplay').textContent = `ID: ${Room.current.id}`;

        // Load settings first (with real-time listener)
        await Settings.load();

        // Init robot realtime sync (Firebase path for robot states)
        if (window.RobotSystem) {
            window.RobotSystem.initSync(Firebase, Room.current.id, Room.current.userId);
            window.RobotSystem.setLabels(Room.current.username, '...');
        }

        // Listen for messages
        await Messaging.listen((message) => {
            this.addMessageToUI(message);

            // Trigger robot animation
            if (message.isMe && window.RobotSystem && window.RobotSystem.isReady()) {
                // My message → left robot
                window.RobotSystem.runForMe(message.text);
            }
            // Other user's robot is handled via Firebase sync in RobotSystem.initSync
        });

        // Listen for typing with username
        Messaging.listenForTyping((username) => {
            this.showTypingIndicator(username);
            // Update right robot label when we know the other person's name
            if (username && window.RobotSystem) {
                window.RobotSystem.setLabels(Room.current.username, username);
            }
        });
    },

    addMessageToUI(message) {
        const container = document.getElementById('messagesContainer');
        const bubble = document.createElement('div');
        
        bubble.className = `message-bubble ${message.isMe ? 'me' : 'other'}`;
        if (message.error) {
            bubble.classList.add('error');
        }

        // Add username label (only for other users)
        if (!message.isMe && message.username) {
            const usernameLabel = document.createElement('div');
            usernameLabel.className = 'message-username';
            usernameLabel.textContent = message.username;
            usernameLabel.style.fontSize = '0.75rem';
            usernameLabel.style.opacity = '0.7';
            usernameLabel.style.marginBottom = '4px';
            bubble.appendChild(usernameLabel);
        }

        const text = document.createElement('p');
        text.className = 'message-text';
        text.textContent = message.text;

        const meta = document.createElement('div');
        meta.className = 'message-meta';
        const time = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        meta.textContent = time;

        bubble.appendChild(text);
        bubble.appendChild(meta);
        container.appendChild(bubble);

        container.scrollTop = container.scrollHeight;
    },

    async handleSendMessage() {
        const input = document.getElementById('messageInput');
        const text = input.value.trim();

        if (!text) return;

        try {
            await Messaging.send(text);
            input.value = '';
            input.style.height = 'auto';
        } catch (error) {
            alert('Failed to send message: ' + error.message);
        }
    },

    showTypingIndicator(username) {
        const indicator = document.getElementById('typingIndicator');
        if (indicator) {
            if (username) {
                indicator.classList.remove('hidden');
                indicator.querySelector('span:last-child').textContent = `${username} is typing...`;
            } else {
                indicator.classList.add('hidden');
            }
        }
    },

    handleLeaveRoom() {
        if (confirm('Are you sure you want to leave this room?')) {
            Room.leave();
            this.showScreen('welcome');
            document.getElementById('messagesContainer').innerHTML = '';
        }
    },

    showShareModal() {
        const modal = document.getElementById('shareModal');
        const input = document.getElementById('shareLinkInput');
        const roomLink = `${window.location.origin}${window.location.pathname}?room=${Room.current.id}`;
        
        input.value = roomLink;
        modal.classList.remove('hidden');
    },

    toggleSettings() {
        const panel = document.getElementById('settingsPanel');
        panel.classList.toggle('active');
    }
};

// ========================================================
// INITIALIZE APP
// ========================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Encrypted Chat Starting...');
    UI.init();
});

console.log('✅ App loaded successfully');
