import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Scans from './pages/Scans';
import Findings from './pages/Findings';

function App() {
  return (
    <Router>
      <div className="App">
        {/* Navigation */}
        <nav className="navbar">
          <div className="nav-brand">
            <h1>🛡️ VulnScan Platform</h1>
          </div>
          <div className="nav-links">
            <Link to="/">Dashboard</Link>
            <Link to="/assets">Assets</Link>
            <Link to="/scans">Scans</Link>
            <Link to="/findings">Findings</Link>
          </div>
        </nav>

        {/* Main Content */}
        <div className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/findings" element={<Findings />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
