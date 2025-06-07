import { useEffect, useState } from 'react';

function App() {
  const [msg, setMsg] = useState("");

  useEffect(() => {
    fetch('/api/test/')
      .then(res => res.json())
      .then(data => setMsg(data.message))
      .catch(err => console.error(err));
  }, []);

  return (
    <div>
      <h1>Cerberus AI Frontend</h1>
      <p>API says: {msg}</p>
    </div>
  );
}

export default App;
