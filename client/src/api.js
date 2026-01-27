const API_URL = "http://localhost:3000";

// Turn Password into a 16-byte AES Key (Hex)
// We use the browser's native crypto for PBKDF2 (standard for key derivation)
export const deriveKeyFromPassword = async (password, salt = "static-salt-for-demo") => {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );
    
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: enc.encode(salt),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        128 
    );

    const byteArray = new Uint8Array(derivedBits);
    return Array.from(byteArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
};


export const registerUser = async (username, password, publicKey, encryptedPrivKey) => {
    const response = await fetch(`${API_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, publicKey, encryptedPrivKey })
    });
    if (!response.ok) throw new Error("Registration Failed");
    return response.json();
};

export const loginUser = async (username, password) => {
    const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    if (!response.ok) throw new Error("Invalid Credentials");
    return response.json(); // Returns { token, encryptedPrivKey, publicKey }
};

export const lookupUser = async (username) => {
    const response = await fetch(`${API_URL}/lookup/${username}`);
    if (!response.ok) throw new Error("User not found");
    return response.json(); // Returns { publicKey }
};