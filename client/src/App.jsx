import { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [pgpEngine, setPgpEngine] = useState(null);
  const [status, setStatus] = useState("Loading Wasm...");
  const [testOutput, setTestOutput] = useState("");

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

  const runTest = () => {
    if (!pgpEngine) return;
    // call a func just to test the bridge
    const result = pgpEngine.encrypt("Hello form React!");
    setTestOutput(result);
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif' }}>
      <h1>Secure Chat PGP (Wasm)</h1>
      
      <div style={{ 
        padding: '15px', 
        background: '#f0f0f0', 
        borderLeft: '5px solid #007bff',
        marginBottom: '20px' ,
        color: '#333333'
      }}>
        <strong>Engine Status:</strong> {status}
      </div>

      <button 
        onClick={runTest} 
        disabled={!pgpEngine}
        style={{ padding: '10px 20px', fontSize: '16px', cursor: 'pointer' }}
      >
        Test Encryption Bridge
      </button>

      {testOutput && (
        <div style={{ marginTop: '20px' }}>
          <h3>C++ Output:</h3>
          <code style={{ background: '#333', color: '#ff0000', padding: '10px', display: 'block' }}>
            {testOutput}
          </code>
        </div>
      )}
    </div>
  );
}

export default App;