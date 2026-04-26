import React from "react";

export default function LandingPage({ onStart }) {
  return (
    <div style={{padding:"40px",fontFamily:"Arial",background:"#f8fafc",minHeight:"100vh"}}>

      {/* NAVBAR */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"40px"}}>
        <h2>QuantumGuard</h2>
        <button onClick={onStart} style={{background:"#16a34a",color:"white",padding:"10px 20px",border:"none",borderRadius:"6px"}}>
          Get Started
        </button>
      </div>

      {/* HERO */}
      <div style={{maxWidth:"700px"}}>
        <h1 style={{fontSize:"48px",marginBottom:"10px"}}>
          Find Quantum <span style={{color:"#16a34a"}}>Vulnerabilities</span>
        </h1>

        <h2 style={{marginBottom:"20px"}}>Secure Tomorrow.</h2>

        <p style={{color:"#555",marginBottom:"20px"}}>
          Scan your codebase and detect weak encryption that could be broken by quantum computers.
        </p>

        <button onClick={onStart} style={{background:"#16a34a",color:"white",padding:"12px 24px",border:"none",borderRadius:"6px"}}>
          Run a Scan Now
        </button>
      </div>

    </div>
  );
}
