import { useEffect, useState, useRef } from 'react';
import { io } from "socket.io-client";
import { deriveKeyFromPassword, registerUser, loginUser, lookupUser } from './api';
import './App.css';

// Helper: Generate a random 16-byte session key as a Hex string
const generateSessionKey = () => {
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

function App() {
  // --- STATE ---
  const [pgpEngine, setPgpEngine] = useState(null);
  const [status, setStatus] = useState("Loading Wasm...");
  
  // Auth
  const [user, setUser] = useState(null); // { username, token, keypair }
  const [authMode, setAuthMode] = useState("login");
  const [usernameInput, setUsernameInput] = useState("");
  const [passwordInput, setPasswordInput] = useState("");

  // Chat
  const [targetUsername, setTargetUsername] = useState("");
  const [partnerPubKey, setPartnerPubKey] = useState("");
  const [message, setMessage] = useState("");
  const [chatLog, setChatLog] = useState([]);

  // Socket
  const socketRef = useRef();

  // --- INITIALIZATION ---

  useEffect(() => {
    const script = document.createElement('script');
    script.src = "/secure_chat.js";
    script.async = true;
    script.onload = () => {
      window.PGPCore().then((module) => {
        const engine = new module.PgpContext();
        setPgpEngine(engine);
        setStatus("Ready");
      });
    };
    document.body.appendChild(script);
  }, []);

  // Connect Socket when User Logs In
  useEffect(() => {
    if (user) {
      socketRef.current = io("http://localhost:3000");
      
      socketRef.current.emit("join", user.username);

      socketRef.current.on("receive_message", (data) => {
        // Add incoming encrypted packet to log
        setChatLog(prev => [...prev, { 
          from: data.from, 
          packet: data.packet, 
          decrypted: null // Will be decrypted on render
        }]);
      });

      return () => {
        socketRef.current.disconnect();
      };
    }
  }, [user]);

  // --- HANDLERS: AUTH ---

  const handleRegister = async () => {
    if (!pgpEngine) return;
    setStatus("Generating Keys...");
    try {
      // 1. Generate RSA Keys
      await new Promise(r => setTimeout(r, 100)); // UI flush
      const keys = pgpEngine.generateKeys();

      // 2. Encrypt Private Key with Password
      const aesKey = await deriveKeyFromPassword(passwordInput);
      const encryptedPrivKey = pgpEngine.encrypt(keys.privateKey, aesKey);

      // 3. Register
      await registerUser(usernameInput, passwordInput, keys.publicKey, encryptedPrivKey);
      
      alert("Registration Successful! Please Log In.");
      setAuthMode("login");
      setStatus("Ready");
    } catch (e) {
      alert("Registration Error: " + e.message);
      setStatus("Error");
    }
  };

  const handleLogin = async () => {
    if (!pgpEngine) return;
    setStatus("Logging in...");
    try {
      // 1. Get Encrypted Blob
      const data = await loginUser(usernameInput, passwordInput);
      
      // 2. Derive Key & Decrypt Identity
      const aesKey = await deriveKeyFromPassword(passwordInput);
      const privateKey = pgpEngine.decrypt(data.encryptedPrivKey, aesKey);

      if (privateKey.startsWith("Error")) {
        throw new Error("Wrong Password (Decryption failed)");
      }

      setUser({
        username: data.username,
        token: data.token,
        keypair: { publicKey: data.publicKey, privateKey }
      });
      setStatus(`Logged in as ${data.username}`);
    } catch (e) {
      alert("Login Error: " + e.message);
      setStatus("Ready");
    }
  };

  // --- HANDLERS: CHAT ---

  const handleLookup = async () => {
    try {
      const data = await lookupUser(targetUsername);
      setPartnerPubKey(data.publicKey);
      alert(`Found Public Key for ${targetUsername}`);
    } catch (e) {
      alert("User not found");
    }
  };

  const handleSendMessage = () => {
    if (!partnerPubKey || !user) return;

    // 1. Generate Session Key
    const sessionKey = generateSessionKey();

    // 2. Encrypt Message (AES)
    const aesCipher = pgpEngine.encrypt(message, sessionKey);

    // 3. Encrypt Session Key (RSA) - so Partner can read it
    const encryptedKey = pgpEngine.rsaEncryptKey(sessionKey, partnerPubKey);

    // 4. Sign Message (RSA) - so Partner knows it's me
    const signature = pgpEngine.signMessage(aesCipher, user.keypair.privateKey);

    const packet = { aesCipher, encryptedKey, signature };

    // 5. Send via Socket
    socketRef.current.emit("send_message", { 
      to: targetUsername, 
      packet 
    });

    // 6. Log locally (We already know the plaintext)
    setChatLog(prev => [...prev, { 
      from: "Me", 
      packet, 
      decrypted: message 
    }]);
    setMessage("");
  };

  // --- RENDER LOGIC ---

  // Tries to decrypt a log item on the fly
  const tryDecrypt = (logItem) => {
    // If we already have the text (sent by us), return it
    if (logItem.decrypted) return logItem.decrypted;
    
    // Safety checks
    if (!pgpEngine || !user) return "...";

    try {
      // 1. Unwrap Session Key using MY Private Key
      const sessionKey = pgpEngine.rsaDecryptKey(logItem.packet.encryptedKey, user.keypair.privateKey);
      
      if (sessionKey.startsWith("Error")) return "RSA Decrypt Failed";

      // 2. Decrypt Message using Session Key
      const text = pgpEngine.decrypt(logItem.packet.aesCipher, sessionKey);
      return text;
    } catch (e) {
      return "Decryption Error";
    }
  };

  // --- UI RENDER ---

  if (!user) {
    return (
      <div className="container">
        <h1>🔐 SecureChat</h1>
        <div style={styles.card}>
          <p>Status: {status}</p>
          <input 
            style={styles.input} 
            placeholder="Username" 
            value={usernameInput} 
            onChange={e => setUsernameInput(e.target.value)} 
          />
          <input 
            style={styles.input} 
            type="password" 
            placeholder="Password" 
            value={passwordInput} 
            onChange={e => setPasswordInput(e.target.value)} 
          />
          
          {authMode === 'login' ? (
            <div style={{display: 'flex', gap: '10px', alignItems: 'center'}}>
              <button style={styles.btn} onClick={handleLogin}>Log In</button>
              <span style={styles.link} onClick={() => setAuthMode('register')}>Or Create Account</span>
            </div>
          ) : (
            <div style={{display: 'flex', gap: '10px', alignItems: 'center'}}>
              <button style={{...styles.btn, background: '#28a745'}} onClick={handleRegister}>Register</button>
              <span style={styles.link} onClick={() => setAuthMode('login')}>Or Log In</span>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
        <h1>👋 {user.username}</h1>
        <button style={{...styles.btn, background: '#666', fontSize: '0.8em'}} onClick={() => window.location.reload()}>Logout</button>
      </div>

      <div style={{display: 'flex', gap: '20px', marginBottom: '20px'}}>
        {/* Connect Box */}
        <div style={{flex: 1, ...styles.card}}>
          <h3>Find User</h3>
          <input 
            style={styles.input} 
            placeholder="Username" 
            value={targetUsername} 
            onChange={e => setTargetUsername(e.target.value)} 
          />
          <button style={styles.btn} onClick={handleLookup}>Connect</button>
          {partnerPubKey && <div style={{color: 'green', marginTop: '5px'}}>✅ Connected</div>}
        </div>

        {/* Compose Box */}
        <div style={{flex: 1, ...styles.card}}>
          <h3>Send Message</h3>
          <input 
            style={styles.input} 
            placeholder="Message..." 
            value={message} 
            onChange={e => setMessage(e.target.value)} 
            disabled={!partnerPubKey}
          />
          <button 
            style={{...styles.btn, background: partnerPubKey ? '#007bff' : '#ccc'}} 
            onClick={handleSendMessage}
            disabled={!partnerPubKey}
          >
            Encrypt & Send
          </button>
        </div>
      </div>

      {/* Chat Log */}
      <div style={styles.chatWindow}>
        {chatLog.length === 0 && <div style={{textAlign: 'center', color: '#999'}}>No messages yet</div>}
        
        {chatLog.map((log, i) => (
          <div key={i} style={{
            textAlign: log.from === "Me" ? 'right' : 'left',
            margin: '10px 0'
          }}>
            <div style={{
              display: 'inline-block',
              padding: '10px 15px',
              borderRadius: '15px',
              background: log.from === "Me" ? '#dcf8c6' : '#fff',
              border: '1px solid #ddd',
              maxWidth: '70%',
              textAlign: 'left'
            }}>
              <div style={{fontSize: '0.8em', color: '#555', marginBottom: '4px'}}>
                {log.from}
              </div>
              <div style={{fontSize: '1.1em'}}>
                {tryDecrypt(log)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

const styles = {
  container: { maxWidth: '800px', margin: '0 auto', padding: '20px', fontFamily: 'sans-serif' },
  card: { padding: '20px', borderRadius: '8px', border: '1px solid #ddd', background: 'white' },
  input: { display: 'block', width: '100%', padding: '10px', marginBottom: '10px', borderRadius: '4px', border: '1px solid #ccc', boxSizing: 'border-box' },
  btn: { padding: '10px 20px', color: 'white', background: '#333', border: 'none', borderRadius: '4px', cursor: 'pointer' },
  link: { fontSize: '0.9em', color: 'blue', cursor: 'pointer', textDecoration: 'underline' },
  chatWindow: { height: '400px', overflowY: 'auto', border: '1px solid #ccc', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }
};

export default App;