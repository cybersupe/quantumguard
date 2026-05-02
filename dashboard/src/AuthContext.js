// ============================================================
// QuantumGuard — AuthContext.js
// JWT Authentication Context
// Handles: register, login, logout, token persistence,
//          auto-refresh, and attaching token to API calls
// ============================================================

import { createContext, useContext, useState, useEffect, useCallback } from "react";

const AuthContext = createContext(null);
const API = "https://quantumguard-api.onrender.com";
const TOKEN_KEY = "qg_token";

export function AuthProvider({ children }) {
  const [jwtUser, setJwtUser]   = useState(null);   // email/password user
  const [jwtToken, setJwtToken] = useState(() => localStorage.getItem(TOKEN_KEY));
  const [jwtLoading, setJwtLoading] = useState(true);

  // ── On mount: verify stored token and fetch user profile ──
  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) { setJwtLoading(false); return; }

    fetch(`${API}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    .then(r => {
      if (r.ok) return r.json();
      // Token invalid/expired — clear it
      localStorage.removeItem(TOKEN_KEY);
      setJwtToken(null);
      return null;
    })
    .then(data => { if (data) setJwtUser(data); })
    .catch(() => { localStorage.removeItem(TOKEN_KEY); setJwtToken(null); })
    .finally(() => setJwtLoading(false));
  }, []);

  // ── Register ──────────────────────────────────────────────
  const jwtRegister = useCallback(async (email, password, name = "") => {
    const res  = await fetch(`${API}/auth/register`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ email, password, name }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Registration failed");
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setJwtToken(data.access_token);
    setJwtUser(data.user);
    return data.user;
  }, []);

  // ── Login ─────────────────────────────────────────────────
  const jwtLogin = useCallback(async (email, password) => {
    const res  = await fetch(`${API}/auth/login`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Login failed");
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setJwtToken(data.access_token);
    setJwtUser(data.user);
    return data.user;
  }, []);

  // ── Logout ────────────────────────────────────────────────
  const jwtLogout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setJwtToken(null);
    setJwtUser(null);
  }, []);

  // ── Fetch wrapper — auto-attaches Authorization header ───
  const apiFetch = useCallback((url, options = {}) => {
    const token = localStorage.getItem(TOKEN_KEY);
    return fetch(url, {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(!options.body || options.body instanceof FormData
          ? {}
          : { "Content-Type": "application/json" }),
      },
    });
  }, []);

  return (
    <AuthContext.Provider value={{
      jwtUser, jwtToken, jwtLoading,
      jwtLogin, jwtRegister, jwtLogout,
      apiFetch,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
};
