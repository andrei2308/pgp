import { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [pgpEngine, setPgpEngine] = useState(null);
  const [status, setStatus] = useState("Loading Wasm...");
  
  // --- STATE FOR AES (Symmetric) ---
  const [aesInput, setAesInput] = useState("Hello World");
  const [aesCipher, setAesCipher] = useState("");
  const [aesDecrypted, setAesDecrypted] = useState("");

  // --- STATE FOR RSA (Asymmetric) ---
  const [sessionKey, setSessionKey] = useState("1234567812345678"); // 16 bytes for AES-128
  const [pubKeyPem, setPubKeyPem] = useState("");
  const [privKeyPem, setPrivKeyPem] = useState("");
  const [encryptedSessionKey, setEncryptedSessionKey] = useState("");
  const [signature, setSignature] = useState("");

  // Load Wasm Engine
  useEffect(() => {
    const script = document.createElement('script');
    script.src = "/secure_chat.js";
    script.async = true;

    script.onload = () => {
      window.PGPCore().then((module) => {
        setStatus("Wasm Loaded. Initializing Engine...");
        const engine = new module.PgpContext();
        setPgpEngine(engine);
        setStatus(engine.checkStatus());
      });
    };

    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  // --- HANDLERS ---

  const handleAesEncrypt = () => {
    if (!pgpEngine) return;
    try {
      // 1. Encrypt Plaintext -> Hex
      const hex = pgpEngine.encrypt(aesInput);
      setAesCipher(hex);
      
      // 2. Immediately try to decrypt it back to verify integrity
      const plain = pgpEngine.decrypt(hex);
      setAesDecrypted(plain);
    } catch (e) {
      alert("AES Error: " + e);
    }
  };

  const handleRsaEncrypt = () => {
    if (!pgpEngine) return;
    if (!pubKeyPem.includes("BEGIN PUBLIC KEY")) {
      alert("Please paste a valid RSA Public Key (PEM format)!");
      return;
    }
    // Encrypt the 16-byte session key using the Public Key
    const result = pgpEngine.rsaEncryptKey(sessionKey, pubKeyPem);
    setEncryptedSessionKey(result);
  };

  const handleSign = () => {
    if (!pgpEngine) return;
    if (!privKeyPem.includes("BEGIN PRIVATE KEY")) {
      alert("Please paste a valid RSA Private Key (PEM format)!");
      return;
    }
    // Sign the AES ciphertext to prove it came from us
    const sig = pgpEngine.signMessage(aesCipher, privKeyPem);
    setSignature(sig);
  };

  return (
    <div style={{ fontFamily: 'Segoe UI, sans-serif', maxWidth: '900px', margin: '0 auto', padding: '20px' }}>
      
      {/* HEADER */}
      <h1 style={{ color: '#2c3e50', borderBottom: '2px solid #eee', paddingBottom: '10px' }}>
        🔐 Secure Chat <span style={{color: '#007bff'}}>PGP Core</span>
      </h1>
      
      <div style={{ 
        padding: '12px 20px', 
        background: '#e8f0fe', 
        borderLeft: '5px solid #007bff',
        marginBottom: '30px', 
        color: '#1a73e8',
        borderRadius: '4px',
        fontWeight: '500'
      }}>
        Status: {status}
      </div>

      {/* SECTION 1: AES PLAYGROUND */}
      <div style={styles.card}>
        <h2 style={styles.cardHeader}>1. Symmetric Encryption (AES-128-CBC)</h2>
        <div style={{ display: 'flex', gap: '20px' }}>
          
          <div style={{ flex: 1 }}>
            <label style={styles.label}>Plaintext Message</label>
            <input 
              style={styles.input} 
              value={aesInput} 
              onChange={(e) => setAesInput(e.target.value)} 
            />
            <button 
              onClick={handleAesEncrypt} 
              disabled={!pgpEngine}
              style={styles.button}
            >
              Encrypt & Verify
            </button>
          </div>

          <div style={{ flex: 1 }}>
            <label style={styles.label}>Resulting Ciphertext (Hex)</label>
            <div style={styles.codeBlock}>{aesCipher || "Waiting..."}</div>
            
            <label style={styles.label}>Decryption Verification (Round-trip)</label>
            <div style={{...styles.codeBlock, color: '#28a745'}}>
              {aesDecrypted || "..."}
            </div>
          </div>
        
        </div>
      </div>

      {/* SECTION 2: RSA KEY EXCHANGE */}
      <div style={styles.card}>
        <h2 style={styles.cardHeader}>2. Key Exchange (RSA-OAEP)</h2>
        <p style={{fontSize: '0.9em', color: '#666', marginBottom: '15px'}}>
          Simulates encrypting the random Session Key (16 bytes) so only the recipient can read it.
        </p>
        
        <div style={{ display: 'flex', gap: '20px' }}>
          <div style={{ flex: 1 }}>
             <label style={styles.label}>Session Key (16 chars)</label>
             <input style={styles.input} value={sessionKey} onChange={e => setSessionKey(e.target.value)} />
             
             <label style={styles.label}>Recipient Public Key (PEM)</label>
             <textarea 
               style={styles.textarea} 
               placeholder="-----BEGIN PUBLIC KEY-----..."
               value={pubKeyPem}
               onChange={e => setPubKeyPem(e.target.value)}
             />
             <button onClick={handleRsaEncrypt} style={styles.button} disabled={!pgpEngine}>
                Encrypt Session Key
             </button>
          </div>
          
          <div style={{ flex: 1 }}>
             <label style={styles.label}>Encrypted Key (Hex)</label>
             <div style={{...styles.codeBlock, height: '140px'}}>
               {encryptedSessionKey || "Output will appear here..."}
             </div>
          </div>
        </div>
      </div>

      {/* SECTION 3: SIGNING */}
      <div style={styles.card}>
        <h2 style={styles.cardHeader}>3. Digital Signature (RSA-SHA256)</h2>
        <p style={{fontSize: '0.9em', color: '#666', marginBottom: '15px'}}>
          Signs the AES Ciphertext hash to prove authenticity.
        </p>
        
        <div style={{ display: 'flex', gap: '20px' }}>
          <div style={{ flex: 1 }}>
             <label style={styles.label}>Sender Private Key (PEM)</label>
             <textarea 
               style={styles.textarea} 
               placeholder="-----BEGIN PRIVATE KEY-----..."
               value={privKeyPem}
               onChange={e => setPrivKeyPem(e.target.value)}
             />
             <button onClick={handleSign} style={{...styles.button, background: '#6f42c1'}} disabled={!pgpEngine || !aesCipher}>
                Sign Ciphertext
             </button>
          </div>
          
          <div style={{ flex: 1 }}>
             <label style={styles.label}>Digital Signature (Hex)</label>
             <div style={{...styles.codeBlock, height: '140px'}}>
               {signature || "Sign the AES Ciphertext above to generate..."}
             </div>
          </div>
        </div>
      </div>

    </div>
  );
}

// Simple internal styles object
const styles = {
  card: {
    background: 'white',
    borderRadius: '8px',
    padding: '25px',
    marginBottom: '30px',
    boxShadow: '0 2px 5px rgba(0,0,0,0.05)',
    border: '1px solid #e1e4e8'
  },
  cardHeader: {
    marginTop: 0,
    fontSize: '1.2rem',
    color: '#333',
    borderBottom: '1px solid #eee',
    paddingBottom: '10px',
    marginBottom: '20px'
  },
  label: {
    display: 'block',
    fontWeight: '600',
    marginBottom: '8px',
    fontSize: '0.9rem',
    color: '#555'
  },
  input: {
    width: '100%',
    padding: '10px',
    marginBottom: '15px',
    borderRadius: '4px',
    border: '1px solid #ccc',
    fontFamily: 'monospace'
  },
  textarea: {
    width: '100%',
    height: '100px',
    padding: '10px',
    marginBottom: '15px',
    borderRadius: '4px',
    border: '1px solid #ccc',
    fontFamily: 'monospace',
    fontSize: '0.8rem'
  },
  button: {
    background: '#007bff',
    color: 'white',
    border: 'none',
    padding: '10px 20px',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1rem',
    fontWeight: '500'
  },
  codeBlock: {
    background: '#2d2d2d',
    color: '#f8f8f2',
    padding: '15px',
    borderRadius: '4px',
    fontFamily: 'Consolas, monospace',
    fontSize: '0.85rem',
    wordBreak: 'break-all',
    minHeight: '40px',
    marginBottom: '15px'
  }
};

export default App;