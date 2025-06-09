import { useEffect, useState } from 'react';
import './App.css';
import cerberusLogo from './assets/cerberusLogo.png';

function App() {
  const [results, setResults] = useState([]);

  useEffect(() => {
    const fetchData = () => {
      fetch('/api/scan/')
        .then(res => res.json())
        .then(data => setResults(data))
        .catch(err => console.error(err));
    };

    fetchData(); // first call
    const interval = setInterval(fetchData, 5000); // poll every 5 sec
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <div className="title-bar">
      <img src={cerberusLogo} alt="Cerberus Logo" className="logo" />
      <div>
        <h1 className="title">Cerberus AI</h1>
        <p className="subtitle">AI-Based Real-Time Intrusion Detection System</p>
      </div>
    </div>
      <div className="main-content">
        <div className="scan-title">
          <h2>Scanning</h2>
          <div className="spinner"></div>
        </div>
        <table className="scan-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Protocol</th>
              <th>Size</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {results.map((entry, idx) => (
              <tr key={idx} className={entry.attack ? 'threat' : 'safe'}>
                <td>{entry.ip}</td>
                <td>{entry.protocol}</td>
                <td>{entry.packet_size}</td>
                <td>{entry.attack ? "Threat" : "Safe"}</td>
              </tr>
            ))}
          </tbody>
        </table>


      </div>
    </div>
  );
}

export default App;
