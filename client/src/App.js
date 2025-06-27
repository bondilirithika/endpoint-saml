import React, { useEffect, useState } from "react";
import logo from './logo.svg';
import './App.css';

const API_BASE = process.env.REACT_APP_API_BASE;
const redirectUri = window.location.origin;

// Only ONE handleLogin function, outside App()
const handleLogin = async () => {
  // 1. Store redirect URI in backend session
  await fetch(`${API_BASE}/api/auth/store-redirect?redirectUri=${encodeURIComponent(redirectUri)}`, {
    method: "POST",
    credentials: "include" // important: so session cookie is sent!
  });
  // 2. Start SAML login (no query params needed)
  window.location.href = `${API_BASE}/saml2/authenticate/google`;
};

function App() {
  const [jwt, setJwt] = useState(localStorage.getItem("jwt"));
  const [user, setUser] = useState(null);

  // On mount, check for JWT in URL (after SAML login)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("jwt");
    if (token) {
      localStorage.setItem("jwt", token);
      setJwt(token);
      window.history.replaceState({}, document.title, "/");
    }
  }, []);

  // Validate JWT if present
  useEffect(() => {
    if (jwt) {
      fetch(`${API_BASE}/api/auth/validate?token=${jwt}`)
        .then(res => res.json())
        .then(data => {
          if (data.valid) setUser(data);
          else {
            setUser(null);
            setJwt(null);
            localStorage.removeItem("jwt");
          }
        });
    }
  }, [jwt]);

  // Start logout flow
  const handleLogout = () => {
    localStorage.removeItem("jwt");
    // ...clear any other state...
    window.location.href = `${API_BASE}/api/auth/custom-logout?redirect_uri=${encodeURIComponent(window.location.origin)}`;
  };

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <h1>React SAML Client</h1>
        {!jwt && <button onClick={handleLogin}>Login with SAML</button>}
        {jwt && user && (
          <div>
            <p>Welcome, {user.username} ({user.email})</p>
            <button onClick={handleLogout}>Logout</button>
            <pre style={{ background: "#eee", padding: 10 }}>{jwt}</pre>
          </div>
        )}
      </header>
    </div>
  );
}

export default App;
