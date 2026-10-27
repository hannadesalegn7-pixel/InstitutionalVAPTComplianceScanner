import { useState } from 'react';
import './App.css';

const API_BASE_URL = 'http://10.42.0.252:3000';
const API_KEY = 'demo-key-123';

function App() {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState('idle');
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  async function handleScan(event) {
    event.preventDefault();

    const trimmedTarget = target.trim();

    if (!trimmedTarget) {
      setError('Please enter a target IP address.');
      return;
    }

    setError('');
    setResults(null);
    setStatus('loading');

    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
    };

    try {
      // 1. Start the scan
      const res = await fetch(`${API_BASE_URL}/api/scans`, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ target: trimmedTarget }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error?.message || 'Scan request failed.');
        setStatus('idle');
        return;
      }

      // 2. Check the scan every 2 seconds until it finishes
      const scanId = data.scan_id;
      while (true) {
        await new Promise((r) => setTimeout(r, 2000));

        const r = await fetch(API_BASE_URL + '/api/scans/' + scanId, {
          headers: headers,
        });
        const scan = await r.json();

        if (scan.status !== 'running') {
          setResults(scan);
          if (scan.status !== 'completed') {
            setError(scan.error || 'Scan ' + scan.status + '.');
          }
          break;
        }
      }
    } catch {
      setError('Could not reach the backend API.');
    }

    setStatus('idle');
  }

  return (
    <div className="dashboard">
      <header>
        <h1>Cybersecurity Dashboard</h1>
        <p>Network Security Monitoring</p>
      </header>

      <main>
        <section className="scan-section">
          <h2>Start a Security Scan</h2>

          <p>
            Enter a target you own or have permission to scan.
          </p>

          <form onSubmit={handleScan}>
            <input
              type="text"
              placeholder="Enter target IP address"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              required
              disabled={status === 'loading'}
            />

            <button
              type="submit"
              disabled={status === 'loading'}
            >
              {status === 'loading' ? 'Scanning...' : 'Start Scan'}
            </button>
          </form>

          {error && (
            <p className="error-message" role="alert">
              {error}
            </p>
          )}
        </section>

        <section className="results-section">
          <h2>Scan Results</h2>

          {status === 'loading' && (
            <p>Scanning, please wait...</p>
          )}

          {results === null && !error && status === 'idle' && (
            <p>No scan results yet. Start a scan to begin.</p>
          )}

          {results !== null && (
            <pre>{JSON.stringify(results, null, 2)}</pre>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;