// ✅ Fully compatible WebSocket + Kyber768 (liboqs-js) server
import WebSocket from 'ws';
import crypto from 'crypto';
import oqs from 'liboqs-js';

await oqs.loadOqs(); // Required init for liboqs

const { subtle } = crypto.webcrypto;
const PORT = process.env.PORT || 8080;

const clients = new Map();
const vaults = new Map();
const vaultHashes = new Map();
const offlineMessages = new Map();

function generateVaultHash() {
    return crypto.randomBytes(32).toString('hex');
}

function parseExpirationTime(duration) {
    const unit = duration.slice(-2);
    const value = parseInt(duration.slice(0, -2), 10);
    switch (unit) {
        case 'h': return value * 60 * 60 * 1000;
        case 'mo': return value * 30 * 24 * 60 * 60 * 1000;
        case 'yr': return value * 365 * 24 * 60 * 60 * 1000;
        default: return 0;
    }
}

function cleanupExpiredVaults() {
    const now = Date.now();
    for (const [vaultId, vault] of vaults.entries()) {
        if (vault.expiration > 0 && now > vault.expiration) {
            const message = JSON.stringify({
                type: 'vault_expired_notification',
                expiredVaultId: vaultId,
                expiredVaultName: vault.vaultName
            });

            vault.members.forEach(memberId => {
                const client = clients.get(memberId);
                if (client && client.readyState === WebSocket.OPEN) {
                    client.send(message);
                }
            });

            vaults.delete(vaultId);
            vaultHashes.delete(vault.vaultHash);
            offlineMessages.delete(vaultId);
        }
    }
}
setInterval(cleanupExpiredVaults, 60 * 60 * 1000);

const wss = new WebSocket.Server({ port: PORT });

wss.on('connection', ws => {
    let currentUserId = null;

    ws.on('message', async message => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            return;
        }

        switch (data.type) {
            case 'register':
                currentUserId = data.userId;
                clients.set(currentUserId, ws);
                checkAndSendOfflineMessages(currentUserId);
                break;

            case 'create_vault': {
                const { userId, vaultName, vaultType, expiration } = data;
                const vaultId = crypto.randomUUID();
                const vaultHash = generateVaultHash();
                const now = Date.now();
                const expirationTime = expiration === 'never' ? 0 : now + parseExpirationTime(expiration);

                const vault = {
                    vaultId,
                    vaultName,
                    vaultHash,
                    members: [userId],
                    expiration: expirationTime,
                    type: vaultType,
                    messages: []
                };

                if (vaultType === 'private') {
                    const kem = new oqs.KEM('Kyber768');
                    const { publicKey, secretKey } = kem.generateKeypair();
                    vault.kyberPublicKey = Buffer.from(publicKey).toString('base64');
                    vault.kyberPrivateKey = Buffer.from(secretKey).toString('base64');
                }

                vaults.set(vaultId, vault);
                vaultHashes.set(vaultHash, vaultId);

                const response = {
                    type: 'vault_created',
                    vaultId,
                    vaultName,
                    vaultHash,
                    vaultType,
                    expiration: expirationTime
                };

                if (vaultType === 'private') {
                    response.kyberPublicKey = vault.kyberPublicKey;
                }

                ws.send(JSON.stringify(response));
                break;
            }

            case 'join_vault': {
                const { userId, vaultHash, vaultName, ciphertext } = data;
                const vaultId = vaultHashes.get(vaultHash);
                if (!vaultId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Vault not found.' }));
                    return;
                }

                const vault = vaults.get(vaultId);
                if (vault.members.includes(userId)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Already a member of this vault.' }));
                    return;
                }

                if (vault.type === 'private') {
                    try {
                        const kem = new oqs.KEM('Kyber768');
                        const sharedSecret = kem.decapsulate(
                            Buffer.from(ciphertext, 'base64'),
                            Buffer.from(vault.kyberPrivateKey, 'base64')
                        );

                        const aesKey = await subtle.importKey(
                            "raw",
                            sharedSecret,
                            { name: "AES-GCM" },
                            false,
                            ["encrypt", "decrypt"]
                        );

                        vault.aesKey = aesKey;
                    } catch (e) {
                        console.error('Kyber decapsulation error:', e);
                        ws.send(JSON.stringify({ type: 'error', message: 'Failed to decapsulate Kyber ciphertext.' }));
                        return;
                    }
                }

                vault.members.push(userId);

                const response = {
                    type: 'vault_joined',
                    joinedVaultId: vaultId,
                    joinedVaultName: vault.vaultName,
                    joinedVaultType: vault.type,
                    joinedExpiration: vault.expiration,
                    vaultHash
                };

                ws.send(JSON.stringify(response));
                break;
            }

            case 'send_message': {
                const { vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType } = data;
                const vault = vaults.get(vaultId);
                if (!vault) return;

                const messageObj = {
                    vaultId,
                    senderId,
                    encryptedMessage,
                    iv,
                    timestamp,
                    isFile,
                    fileName,
                    fileMimeType
                };

                broadcastToVault(vaultId, messageObj, senderId);
                vault.messages.push(messageObj);
                break;
            }
        }
    });

    ws.on('close', () => {
        if (currentUserId) {
            clients.delete(currentUserId);
        }
    });
});

function broadcastToVault(vaultId, message, senderId) {
    const vault = vaults.get(vaultId);
    if (!vault) return;

    const jsonMessage = JSON.stringify({ type: 'new_message', ...message });
    for (const memberId of vault.members) {
        if (memberId !== senderId) {
            const client = clients.get(memberId);
            if (client && client.readyState === WebSocket.OPEN) {
                client.send(jsonMessage);
            } else {
                if (!offlineMessages.has(memberId)) {
                    offlineMessages.set(memberId, []);
                }
                offlineMessages.get(memberId).push({ vaultId, message });
            }
        }
    }
}

function checkAndSendOfflineMessages(userId) {
    if (offlineMessages.has(userId)) {
        const messagesToSend = offlineMessages.get(userId);
        const client = clients.get(userId);
        if (client && client.readyState === WebSocket.OPEN) {
            const messageData = messagesToSend.map(m => m.message);
            client.send(JSON.stringify({ type: 'offline_messages', messages: messageData }));
            offlineMessages.delete(userId);
        }
    }
}

console.log(`✅ Kyber-secure WebSocket server running on port ${PORT}`);
