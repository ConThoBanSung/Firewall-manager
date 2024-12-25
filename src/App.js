import React, { useState } from 'react';
import './App.css';

function App() {
  const [rules, setRules] = useState('');
  const [logs, setLogs] = useState('');
  const [syslogs, setSyslogs] = useState('');
  const [port, setPort] = useState('');
  const [action, setAction] = useState('ACCEPT');
  const [ruleNumber, setRuleNumber] = useState('');
  const [suspiciousIPs, setSuspiciousIPs] = useState([]); // Đảm bảo luôn là mảng rỗng ban đầu
  const [bandwidthLimit, setBandwidthLimit] = useState('');
  const [ipRange, setIpRange] = useState('');
  const [serviceName, setServiceName] = useState('');
  const [monitoring, setMonitoring] = useState(false); // Trạng thái giám sát

  // Fetch current rules
  const fetchRules = async () => {
    const response = await fetch('http://localhost:5001/rules');
    const data = await response.json();
    setRules(data.rules);
  };

  // Fetch logs
  const fetchLogs = async () => {
    const response = await fetch('http://localhost:5001/logs');
    const data = await response.json();
    setLogs(data.logs);
  };

  // Fetch syslogs
  const fetchSyslogs = async () => {
    const response = await fetch('http://localhost:5001/syslog');
    const data = await response.json();
    setSyslogs(data.logs);
  };

  // Add a rule
  const addRule = async () => {
    const response = await fetch('http://localhost:5001/add_rule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port, action }),
    });
    const data = await response.json();
    alert(data.message);
    fetchRules(); // Refresh rules
  };

  // Delete a rule
  const deleteRule = async () => {
    const response = await fetch('http://localhost:5001/delete_rule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_number: ruleNumber }),
    });
    const data = await response.json();
    alert(data.message);
    fetchRules(); // Refresh rules
  };

  // Block suspicious IPs
  const blockSuspiciousIPs = async () => {
    const response = await fetch('http://localhost:5001/block_suspicious_ips', {
      method: 'POST',
    });
    const data = await response.json();
    const blockedIPs = data.blocked_ips || []; // Đảm bảo blocked_ips là mảng
    setSuspiciousIPs(blockedIPs); // Cập nhật lại danh sách IP bị chặn
    alert(`Blocked IPs: ${blockedIPs.join(', ')}`); // Join array với dấu phẩy
  };

  // Start monitoring for suspicious IPs
  const startMonitoring = async () => {
    const response = await fetch('http://localhost:5001/start_monitoring', {
      method: 'POST',
    });
    const data = await response.json();
    alert(data.message);
    setMonitoring(true);  // Bật chế độ giám sát
  };

  // Configure firewall with advanced options
  const configureFirewall = async () => {
    const response = await fetch('http://localhost:5001/configure_firewall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        port,
        action,
        bandwidth_limit: bandwidthLimit,
        ip_range: ipRange,
        service_name: serviceName,
      }),
    });
    const data = await response.json();
    alert(data.message);
  };

  // Download the firewall guide
  const downloadGuide = async () => {
    const response = await fetch('http://localhost:5001/download_guide');
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'firewall_config_guide.txt';
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h1>Firewall Manager</h1>

      {/* View Current Rules */}
      <section>
        <h2>View Rules</h2>
        <button onClick={fetchRules}>Fetch Rules</button>
        <pre>{rules}</pre>
      </section>

      {/* Add Rule */}
      <section>
        <h2>Add Rule</h2>
        <label>
          Port:
          <input type="number" value={port} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label>
          Action:
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="ACCEPT">ACCEPT</option>
            <option value="DROP">DROP</option>
          </select>
        </label>
        <button onClick={addRule}>Add Rule</button>
      </section>

      {/* Delete Rule */}
      <section>
        <h2>Delete Rule</h2>
        <label>
          Rule Number:
          <input type="number" value={ruleNumber} onChange={(e) => setRuleNumber(e.target.value)} />
        </label>
        <button onClick={deleteRule}>Delete Rule</button>
      </section>

      {/* View Logs */}
      <section>
        <h2>View Logs</h2>
        <button onClick={fetchLogs}>Fetch Logs</button>
        <pre>{logs}</pre>
      </section>

      {/* View Syslogs */}
      <section>
        <h2>View Syslogs</h2>
        <button onClick={fetchSyslogs}>Fetch Syslogs</button>
        <pre>{syslogs}</pre>
      </section>

      {/* Block Suspicious IPs */}
      <section>
        <h2>Block Suspicious IPs</h2>
        <button onClick={blockSuspiciousIPs}>Block Suspicious IPs</button>
        <ul>
          {suspiciousIPs && suspiciousIPs.length > 0 ? (
            suspiciousIPs.map((ip, index) => (
              <li key={index}>{ip}</li>
            ))
          ) : (
            <li>No suspicious IPs to block.</li>
          )}
        </ul>
      </section>

      {/* Start Monitoring */}
      <section>
        <h2>Start Monitoring</h2>
        {!monitoring ? (
          <button onClick={startMonitoring}>Start Monitoring</button>
        ) : (
          <p>Monitoring is active.</p>
        )}
      </section>

      {/* Configure Firewall with Advanced Options */}
      <section>
        <h2>Configure Firewall</h2>
        <label>
          Port:
          <input type="number" value={port} onChange={(e) => setPort(e.target.value)} />
        </label>
        <label>
          Action:
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="ACCEPT">ACCEPT</option>
            <option value="DROP">DROP</option>
          </select>
        </label>
        <label>
          Bandwidth Limit (kbps):
          <input type="number" value={bandwidthLimit} onChange={(e) => setBandwidthLimit(e.target.value)} />
        </label>
        <label>
          IP Range:
          <input type="text" value={ipRange} onChange={(e) => setIpRange(e.target.value)} />
        </label>
        <label>
          Service Name:
          <input type="text" value={serviceName} onChange={(e) => setServiceName(e.target.value)} />
        </label>
        <button onClick={configureFirewall}>Configure Firewall</button>
      </section>

      {/* Download Guide */}
      <section>
        <h2>Download Firewall Configuration Guide</h2>
        <button onClick={downloadGuide}>Download Guide</button>
      </section>
    </div>
  );
}

export default App;
