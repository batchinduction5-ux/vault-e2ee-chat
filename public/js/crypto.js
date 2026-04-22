/* ═══════════════════════════════════════════════════════════════════
   Vault – E2EE Crypto Module
   ECDH P-256 key exchange  →  HKDF  →  AES-256-GCM
   All operations use the native Web Crypto API (SubtleCrypto).
   ═══════════════════════════════════════════════════════════════════ */

const VaultCrypto = (() => {
  const subtle = crypto.subtle;
  const CURVE = 'P-256';
  const HKDF_INFO = new TextEncoder().encode('vault-e2ee-v1');
  const HKDF_SALT = new Uint8Array(32);           // fixed empty salt
  const IV_BYTES = 12;                             // 96-bit IV for GCM

  // ── Key Pair Generation ────────────────────────────────────────
  async function generateKeyPair() {
    return subtle.generateKey(
      { name: 'ECDH', namedCurve: CURVE },
      true,                                        // extractable
      ['deriveKey', 'deriveBits']
    );
  }

  // ── Export / Import ────────────────────────────────────────────
  async function exportPublicKey(key) {
    return subtle.exportKey('jwk', key);
  }

  async function exportPrivateKey(key) {
    return subtle.exportKey('jwk', key);
  }

  async function importPublicKey(jwk) {
    return subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: CURVE },
      true, []
    );
  }

  async function importPrivateKey(jwk) {
    return subtle.importKey(
      'jwk', jwk,
      { name: 'ECDH', namedCurve: CURVE },
      true, ['deriveKey', 'deriveBits']
    );
  }

  // ── Shared Key Derivation (ECDH → HKDF → AES-256-GCM) ────────
  async function deriveSharedKey(myPrivateKey, theirPublicKey) {
    // Step 1 – ECDH: derive raw shared bits
    const rawBits = await subtle.deriveBits(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      256
    );

    // Step 2 – import as HKDF key material
    const hkdfKey = await subtle.importKey(
      'raw', rawBits, 'HKDF', false, ['deriveKey']
    );

    // Step 3 – HKDF → AES-256-GCM key
    return subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: HKDF_SALT,
        info: HKDF_INFO,
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,                                       // non-extractable
      ['encrypt', 'decrypt']
    );
  }

  // ── Encrypt ────────────────────────────────────────────────────
  async function encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const encoded = new TextEncoder().encode(plaintext);
    const cipherBuf = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encoded
    );
    return {
      ciphertext: bufToBase64(cipherBuf),
      iv: bufToBase64(iv),
    };
  }

  // ── Decrypt ────────────────────────────────────────────────────
  async function decrypt(aesKey, ciphertextB64, ivB64) {
    const ct = base64ToBuf(ciphertextB64);
    const iv = base64ToBuf(ivB64);
    const plainBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ct
    );
    return new TextDecoder().decode(plainBuf);
  }

  // ── Helpers ────────────────────────────────────────────────────
  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  // ── Local Key Persistence (localStorage) ───────────────────────
  function storeKeyPair(username, publicJwk, privateJwk) {
    localStorage.setItem(`vault_pub_${username}`, JSON.stringify(publicJwk));
    localStorage.setItem(`vault_priv_${username}`, JSON.stringify(privateJwk));
  }

  function loadKeyPair(username) {
    const pub = localStorage.getItem(`vault_pub_${username}`);
    const priv = localStorage.getItem(`vault_priv_${username}`);
    if (pub && priv) return { publicJwk: JSON.parse(pub), privateJwk: JSON.parse(priv) };
    return null;
  }

  // ── Public API ─────────────────────────────────────────────────
  return {
    generateKeyPair,
    exportPublicKey,
    exportPrivateKey,
    importPublicKey,
    importPrivateKey,
    deriveSharedKey,
    encrypt,
    decrypt,
    storeKeyPair,
    loadKeyPair,
  };
})();
