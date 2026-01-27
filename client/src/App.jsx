import { useEffect, useState, useRef } from 'react';
import { io } from "socket.io-client";
import { deriveKeyFromPassword, registerUser, loginUser, lookupUser } from './api';
import './App.css';

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

  useEffect(() => {
    if (user) {
      socketRef.current = io("http://localhost:3000");
      
      socketRef.current.emit("join", user.username);

      socketRef.current.on("receive_message", (data) => {
        setChatLog(prev => [...prev, { 
          from: data.from, 
          packet: data.packet, 
          decrypted: null
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
      await new Promise(r => setTimeout(r, 100));
      const keys = pgpEngine.generateKeys();

      const aesKey = await deriveKeyFromPassword(passwordInput);
      const encryptedPrivKey = pgpEngine.encrypt(keys.privateKey, aesKey);

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
      const data = await loginUser(usernameInput, passwordInput);
      
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

    const sessionKey = generateSessionKey();

    const aesCipher = pgpEngine.encrypt(message, sessionKey);

    const encryptedKey = pgpEngine.rsaEncryptKey(sessionKey, partnerPubKey);

    const signature = pgpEngine.signMessage(aesCipher, user.keypair.privateKey);

    const packet = { aesCipher, encryptedKey, signature };

    socketRef.current.emit("send_message", { 
      to: targetUsername, 
      packet 
    });

    setChatLog(prev => [...prev, { 
      from: "Me", 
      packet, 
      decrypted: message 
    }]);
    setMessage("");
  };

  // --- RENDER LOGIC ---

  const tryDecrypt = (logItem) => {
    if (logItem.decrypted) return logItem.decrypted;
    
    if (!pgpEngine || !user) return "...";

    try {
      const sessionKey = pgpEngine.rsaDecryptKey(logItem.packet.encryptedKey, user.keypair.privateKey);
      
      if (sessionKey.startsWith("Error")) return "RSA Decrypt Failed";

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
            <div style={{display: 'flex', flexDirection: 'column', gap: '15px', marginTop: '10px'}}>
              <button style={{...styles.btn, width: '100%'}} onClick={handleLogin}>Log In</button>
              <span style={{...styles.link, textAlign: 'center'}} onClick={() => setAuthMode('register')}>
                Or Create Account
              </span>
            </div>
          ) : (
            <div style={{display: 'flex', flexDirection: 'column', gap: '15px', marginTop: '10px'}}>
              <button style={{...styles.btn, background: '#28a745', width: '100%'}} onClick={handleRegister}>
                Register
              </button>
              <span style={{...styles.link, textAlign: 'center'}} onClick={() => setAuthMode('login')}>
                Or Log In
              </span>
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
  container: { 
    maxWidth: '900px', 
    margin: '0 auto', 
    padding: '40px 20px', 
    fontFamily: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif',
    color: '#333'
  },
  card: { 
    padding: '25px', 
    borderRadius: '12px', 
    border: '1px solid #e1e4e8', 
    background: '#ffffff',
    boxShadow: '0 4px 6px rgba(0,0,0,0.05)',
    marginBottom: '20px'
  },
  input: { 
    display: 'block', 
    width: '100%', 
    padding: '12px', 
    marginBottom: '15px', 
    borderRadius: '6px', 
    border: '1px solid #ced4da', 
    boxSizing: 'border-box',
    fontSize: '16px',
    color: '#333',
    backgroundColor: '#fff'
  },
  btn: { 
    padding: '12px 20px', 
    color: 'white', 
    background: '#333', 
    border: 'none', 
    borderRadius: '6px', 
    cursor: 'pointer',
    fontSize: '16px',
    fontWeight: '600'
  },
  link: { 
    fontSize: '0.9em', 
    color: '#007bff', 
    cursor: 'pointer', 
    textDecoration: 'underline' 
  },
  chatWindow: { 
    height: '500px', 
    overflowY: 'auto', 
    border: '1px solid #e1e4e8', 
    borderRadius: '12px', 
    padding: '20px', 
    background: '#f8f9fa' 
  }
};

export default App;