import { useEffect, useState } from 'react';
import './App.css';

// Helper to generate a random 16-byte AES key string
const generateSessionKey = () => {
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array, byte => String.fromCharCode(byte)).join('');
};

function App() {
  const [pgpEngine, setPgpEngine] = useState(null);
  const [status, setStatus] = useState("Loading...");
  
  // --- IDENTITY STATE ---
  const [myIdentity, setMyIdentity] = useState({ publicKey: "", privateKey: "" });
  const [isGenerating, setIsGenerating] = useState(false);

  // --- HANDSHAKE STATE ---
  const [partnerPubKey, setPartnerPubKey] = useState("");
  const [sessionKey, setSessionKey] = useState(""); // The AES Key we will use

  // --- CHAT STATE ---
  const [message, setMessage] = useState("Hello Secret World");
  const [fullPacket, setFullPacket] = useState(null);

  useEffect(() => {
    const script = document.createElement('script');
    script.src = "/secure_chat.js";
    script.async = true;
    script.onload = () => {
      window.PGPCore().then((module) => {
        const engine = new module.PgpContext();
        setPgpEngine(engine);
        setStatus(engine.checkStatus());
        // Auto-generate a session key on load
        setSessionKey(generateSessionKey());
      });
    };
    document.body.appendChild(script);
  }, []);

  const handleGenerateIdentity = () => {
    setIsGenerating(true);
    // Timeout allows the UI to update "Generating..." before Wasm freezes the thread
    setTimeout(() => {
      const keys = pgpEngine.generateKeys();
      setMyIdentity(keys);
      setIsGenerating(false);
    }, 100);
  };

  const handleSendMessage = () => {
    if(!partnerPubKey) { alert("Need Partner's Public Key!"); return; }
    if(!myIdentity.privateKey) { alert("Need My Private Key (Generate Identity first)!"); return; }

    // 1. ENCRYPT MESSAGE (Symmetric)
    // In a real app, 'encrypt' would accept the key as a param. 
    // For this demo, we assume the C++ uses its internal 0-key or we modify C++ to take it.
    // Ideally: pgpEngine.encrypt(message, sessionKey);
    const aesCipher = pgpEngine.encrypt(message);

    // 2. ENCRYPT SESSION KEY (Asymmetric)
    // Only the partner can decrypt this to get the AES key
    const encryptedKey = pgpEngine.rsaEncryptKey(sessionKey, partnerPubKey);

    // 3. SIGN MESSAGE (Integrity)
    // Proves I sent it
    const signature = pgpEngine.signMessage(aesCipher, myIdentity.privateKey);

    setFullPacket({
      aesCipher,
      encryptedKey,
      signature
    });
  };

  return (
    <div style={{ fontFamily: 'sans-serif', maxWidth: '800px', margin: '20px auto', padding: '20px' }}>
      <h1>🔐 PGP Chat Client</h1>
      <div style={{ background: '#eef', padding: '10px', marginBottom: '20px', borderLeft: '4px solid #007bff' }}>
        <strong>System:</strong> {status}
      </div>

      {/* STEP 1: IDENTITY */}
      <div style={styles.section}>
        <h2>1. My Identity</h2>
        <button onClick={handleGenerateIdentity} disabled={!pgpEngine || isGenerating} style={styles.btn}>
          {isGenerating ? "Generating RSA-2048 Pair..." : "Generate New Keypair"}
        </button>
        {myIdentity.publicKey && (
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
            <textarea readOnly value={myIdentity.publicKey} style={styles.keyBox} placeholder="Public Key" />
            <textarea readOnly value={myIdentity.privateKey} style={{...styles.keyBox, background: '#fff0f0'}} placeholder="Private Key (Hidden)" />
          </div>
        )}
      </div>

      {/* STEP 2: PARTNER */}
      <div style={styles.section}>
        <h2>2. Partner Setup</h2>
        <p>Paste the <strong>Public Key</strong> of the person you want to chat with:</p>
        <textarea 
          value={partnerPubKey} 
          onChange={(e) => setPartnerPubKey(e.target.value)} 
          style={{...styles.keyBox, width: '100%', height: '120px'}} 
          placeholder="-----BEGIN PUBLIC KEY-----..."
        />
      </div>

      {/* STEP 3: SEND */}
      <div style={styles.section}>
        <h2>3. Secure Message</h2>
        <input 
          value={message} 
          onChange={e => setMessage(e.target.value)} 
          style={{ width: '100%', padding: '10px', marginBottom: '10px' }} 
        />
        <button onClick={handleSendMessage} style={{...styles.btn, background: '#28a745'}}>
          Encrypt & Sign Packet
        </button>

        {fullPacket && (
          <div style={{ marginTop: '20px', background: '#333', color: '#fff', padding: '15px', borderRadius: '5px' }}>
            <h4 style={{marginTop:0}}>📦 JSON Packet to Send via WebSocket:</h4>
            <pre style={{ overflowX: 'auto', fontSize: '0.85em' }}>
              {JSON.stringify(fullPacket, null, 2)}
            </pre>
            <p style={{fontSize: '0.8em', color: '#aaa'}}>
              * Contains: Encrypted Message (AES), Encrypted Key (RSA), Signature (RSA-SHA256)
            </p>
          </div>
        )}
      </div>

    </div>
  );
}

const styles = {
  section: { border: '1px solid #ddd', padding: '20px', borderRadius: '8px', marginBottom: '20px' },
  btn: { padding: '10px 20px', fontSize: '1em', cursor: 'pointer', background: '#007bff', color: 'white', border: 'none', borderRadius: '4px' },
  keyBox: { width: '50%', height: '100px', fontSize: '0.75em', fontFamily: 'monospace', padding: '5px' }
};

export default App;