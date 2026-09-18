import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, AlertCircle,
  UploadCloud, FileText, Globe, Server, Link, Hash, Mail,
  Clock, ArrowRight, RefreshCw, Eye, ExternalLink, Copy, Check,
  Layers, Lock, Database, Search, Download, FileCheck
} from 'lucide-react';

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api';
export default function App() {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload', 'dossier', 'cases', 'gmail'
  const [apiOnline, setApiOnline] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [liveNotification, setLiveNotification] = useState(null);

  // Upload & Investigation States
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStage, setAnalysisStage] = useState('');
  const [currentCase, setCurrentCase] = useState(null);
  const [uploadError, setUploadError] = useState(null);

  // Cases Ledger States
  const [casesList, setCasesList] = useState([]);
  const [loadingCases, setLoadingCases] = useState(false);
  const [riskFilter, setRiskFilter] = useState('ALL');

  // Dossier Sub-tab
  const [dossierTab, setDossierTab] = useState('summary');
  const [copiedText, setCopiedText] = useState(null);
  const [caseGraph, setCaseGraph] = useState(null);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const [caseIntegrity, setCaseIntegrity] = useState(null);

  // Fetch threat graph when graph subtab is opened or current case changes
  useEffect(() => {
    if (dossierTab === 'graph' && currentCase?.case_id) {
      fetchCaseGraph(currentCase.case_id);
    }
  }, [dossierTab, currentCase]);

  // Fetch integrity seal when case is loaded
  useEffect(() => {
    if (currentCase?.case_id) {
      fetch(`${API_BASE}/cases/${currentCase.case_id}/integrity`)
        .then(res => res.json())
        .then(data => {
          if (data.success) setCaseIntegrity(data.data);
        })
        .catch(() => { });
    }
  }, [currentCase]);

  const fetchCaseGraph = async (caseId) => {
    setLoadingGraph(true);
    try {
      const res = await fetch(`${API_BASE}/cases/${caseId}/graph`);
      const data = await res.json();
      if (data.success) {
        setCaseGraph(data.data);
        if (data.data.nodes?.length > 0) {
          setSelectedGraphNode(data.data.nodes[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch case threat graph:', err);
    } finally {
      setLoadingGraph(false);
    }
  };

  // Check API health on mount
  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then(res => res.json())
      .then(data => {
        if (data.success) setApiOnline(true);
      })
      .catch(() => setApiOnline(false));
  }, []);

  // Real-time WebSocket connection for live SOC streaming
  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    const connectWebSocket = () => {
      try {
        const WS_BASE =
          import.meta.env.VITE_WS_BASE_URL || 'ws://127.0.0.1:8000';

        ws = new WebSocket(`${WS_BASE}/api/ws/cases`);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.event === 'stage_update') {
              setAnalysisStage(`${payload.data.stage} (Step ${payload.data.step}/${payload.data.total_steps})`);
            } else if (payload.event === 'case_completed') {
              setLiveNotification({
                type: 'case_completed',
                case_id: payload.data.case_id,
                score: payload.data.threat_score,
                risk: payload.data.risk_level,
                subject: payload.data.subject
              });
              fetchCases();
              setTimeout(() => setLiveNotification(null), 6000);
            }
          } catch (e) {
            console.error('WebSocket message parsing error:', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (e) {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      }
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // Fetch cases when switching to cases tab
  useEffect(() => {
    if (activeTab === 'cases') {
      fetchCases();
    }
  }, [activeTab, riskFilter]);

  const fetchCases = async () => {
    setLoadingCases(true);
    try {
      const url = riskFilter === 'ALL'
        ? `${API_BASE}/cases`
        : `${API_BASE}/cases?risk_level=${riskFilter}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.success) {
        setCasesList(data.data.cases);
      }
    } catch (err) {
      console.error('Failed to fetch cases:', err);
    } finally {
      setLoadingCases(false);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!file.name.toLowerCase().endsWith('.eml')) {
        setUploadError('Only .eml files are supported.');
        setSelectedFile(null);
        return;
      }
      setUploadError(null);
      setSelectedFile(file);
    }
  };

  const runInvestigation = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    setUploadError(null);

    const stages = [
      'Ingesting .eml email file...',
      'Parsing RFC 822 headers & MIME body...',
      'Analyzing spoofing & routing hops...',
      'Evaluating SPF / DKIM / DMARC authentication...',
      'Extracting and deduplicating IOCs...',
      'Statically inspecting embedded URLs...',
      'Querying live DNS, RDAP & Threat Intelligence...',
      'Evaluating NLP & Semantic Phishing Intent...',
      'Calculating explainable threat score...',
      'Persisting forensic case into database...'
    ];

    let stageIdx = 0;
    const interval = setInterval(() => {
      if (stageIdx < stages.length) {
        setAnalysisStage(stages[stageIdx]);
        stageIdx++;
      }
    }, 450);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch(`${API_BASE}/emails/upload`, {
        method: 'POST',
        body: formData,
      });
      const data = await response.json();

      clearInterval(interval);
      setIsAnalyzing(false);

      if (data.success) {
        setCurrentCase(data.data);
        setActiveTab('dossier');
      } else {
        setUploadError(data.error?.message || 'Investigation failed');
      }
    } catch (err) {
      clearInterval(interval);
      setIsAnalyzing(false);
      setUploadError('Network error connecting to TRACE-X Backend.');
    }
  };

  const loadCaseDossier = async (caseId) => {
    try {
      const res = await fetch(`${API_BASE}/cases/${caseId}`);
      const data = await res.json();
      if (data.success) {
        setCurrentCase({
          case_id: data.data.case_id,
          status: data.data.status,
          threat_score: data.data.threat_score_details,
          email: data.data.email,
          header_analysis: data.data.header_analysis,
          authentication: data.data.authentication,
          iocs: data.data.iocs,
          url_analysis: data.data.url_analysis,
          intelligence: data.data.intelligence,
          nlp_analysis: data.data.nlp_analysis
        });
        setActiveTab('dossier');
      }
    } catch (err) {
      console.error('Failed to load case:', err);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const getRiskBadgeColor = (risk) => {
    switch ((risk || '').toUpperCase()) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': default: return '#10b981';
    }
  };

  const getAuthBadge = (status) => {
    const s = (status || '').toLowerCase();
    if (s === 'pass') {
      return <span style={{ background: '#064e3b', color: '#34d399', padding: '3px 8px', borderRadius: '4px', fontWeight: 'bold', fontSize: '0.8rem' }}>PASS</span>;
    } else if (s === 'fail' || s === 'softfail') {
      return <span style={{ background: '#7f1d1d', color: '#f87171', padding: '3px 8px', borderRadius: '4px', fontWeight: 'bold', fontSize: '0.8rem' }}>{status.toUpperCase()}</span>;
    } else {
      return <span style={{ background: '#334155', color: '#94a3b8', padding: '3px 8px', borderRadius: '4px', fontSize: '0.8rem' }}>{status.toUpperCase() || 'NONE'}</span>;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      {/* Top Navbar */}
      <header style={{
        background: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-color)',
        padding: '14px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            padding: '8px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#ffffff' }}>TRACE-X</h1>
              <span style={{ fontSize: '0.7rem', background: '#1e293b', border: '1px solid #334155', color: '#38bdf8', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>v1.0 REAL-DATA</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Email Threat Investigation & Forensic Intelligence</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setActiveTab('upload')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              border: activeTab === 'upload' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
              background: activeTab === 'upload' ? '#162338' : 'transparent',
              color: activeTab === 'upload' ? '#38bdf8' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '0.85rem'
            }}
          >
            <UploadCloud size={16} /> Investigate (.eml)
          </button>

          <button
            onClick={() => setActiveTab('dossier')}
            disabled={!currentCase}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              border: activeTab === 'dossier' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
              background: activeTab === 'dossier' ? '#162338' : 'transparent',
              color: currentCase ? (activeTab === 'dossier' ? '#38bdf8' : 'var(--text-secondary)') : '#475569',
              cursor: currentCase ? 'pointer' : 'not-allowed',
              fontWeight: 600,
              fontSize: '0.85rem'
            }}
          >
            <Eye size={16} /> Case Dossier {currentCase && <span style={{ fontSize: '0.7rem', background: '#0f172a', padding: '2px 5px', borderRadius: '3px' }}>{currentCase.case_id}</span>}
          </button>

          <button
            onClick={() => setActiveTab('cases')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              border: activeTab === 'cases' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
              background: activeTab === 'cases' ? '#162338' : 'transparent',
              color: activeTab === 'cases' ? '#38bdf8' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '0.85rem'
            }}
          >
            <Database size={16} /> Cases Ledger
          </button>

          <button
            onClick={() => setActiveTab('gmail')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              border: activeTab === 'gmail' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
              background: activeTab === 'gmail' ? '#162338' : 'transparent',
              color: activeTab === 'gmail' ? '#38bdf8' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '0.85rem'
            }}
          >
            <Mail size={16} /> Gmail Live Watch
          </button>
        </nav>

        {/* Backend API and WebSocket status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: wsConnected ? '#064e3b' : '#334155',
            padding: '5px 10px',
            borderRadius: '20px',
            fontSize: '0.75rem',
            color: wsConnected ? '#34d399' : '#94a3b8',
            fontWeight: 600
          }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: wsConnected ? '#34d399' : '#94a3b8', display: 'inline-block' }}></span>
            {wsConnected ? 'WebSocket Live' : 'WS Disconnected'}
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: apiOnline ? '#064e3b' : '#7f1d1d',
            padding: '5px 10px',
            borderRadius: '20px',
            fontSize: '0.75rem',
            color: apiOnline ? '#34d399' : '#f87171',
            fontWeight: 600
          }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: apiOnline ? '#34d399' : '#f87171', display: 'inline-block' }}></span>
            {apiOnline ? 'API Connected' : 'API Offline'}
          </div>
        </div>
      </header>

      {/* Real-time Case Completed Toast / Notification Banner */}
      {liveNotification && (
        <div style={{
          background: liveNotification.score >= 70 ? 'linear-gradient(90deg, #7f1d1d, #991b1b)' : (liveNotification.score >= 40 ? 'linear-gradient(90deg, #78350f, #92400e)' : 'linear-gradient(90deg, #064e3b, #047857)'),
          color: '#ffffff',
          padding: '10px 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid rgba(255,255,255,0.2)',
          animation: 'fadeIn 0.3s ease-in-out'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} />
            <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>Real-time Detection:</span>
            <span style={{ fontSize: '0.85rem' }}>
              Case <strong style={{ fontFamily: 'var(--font-mono)' }}>{liveNotification.case_id}</strong> analyzed & saved — Risk: <strong>{liveNotification.risk} ({liveNotification.score}/100)</strong> — {liveNotification.subject}
            </span>
          </div>
          <button
            onClick={() => {
              loadCaseDossier(liveNotification.case_id);
              setLiveNotification(null);
            }}
            style={{
              background: '#ffffff',
              color: '#0f172a',
              border: 'none',
              padding: '4px 12px',
              borderRadius: '4px',
              fontWeight: 700,
              fontSize: '0.75rem',
              cursor: 'pointer'
            }}
          >
            View Live Dossier
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '28px', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
        {/* ========================================================================= */}
        {/* TAB 1: UPLOAD & INVESTIGATE */}
        {/* ========================================================================= */}
        {activeTab === 'upload' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <UploadCloud color="var(--accent-cyan)" /> On-Demand Real Email Investigation
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '20px' }}>
                Select an authentic <code style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>.eml</code> email message to initiate real-time SPF/DKIM/DMARC verification, header spoofing analysis, IOC extraction, NLP intent analysis, and explainable threat scoring.
              </p>

              {/* Upload Dropzone */}
              <div
                style={{
                  border: '2px dashed var(--border-light)',
                  borderRadius: '10px',
                  padding: '40px 20px',
                  textAlign: 'center',
                  background: 'var(--bg-card)',
                  cursor: 'pointer',
                  position: 'relative'
                }}
              >
                <input
                  type="file"
                  accept=".eml"
                  onChange={handleFileChange}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    height: '100%',
                    opacity: 0,
                    cursor: 'pointer'
                  }}
                />
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#1e293b', padding: '16px', borderRadius: '50%', color: '#38bdf8' }}>
                    <FileText size={32} />
                  </div>
                  <div>
                    <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc' }}>
                      {selectedFile ? selectedFile.name : 'Click or Drag & Drop .eml email file here'}
                    </h3>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB — Ready to investigate` : 'RFC 822 raw email format up to 10 MB'}
                    </p>
                  </div>
                </div>
              </div>

              {uploadError && (
                <div style={{ background: '#450a0a', border: '1px solid #7f1d1d', color: '#fca5a5', padding: '12px', borderRadius: '8px', marginTop: '16px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertCircle size={16} /> {uploadError}
                </div>
              )}

              {/* Action Button */}
              <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                <button
                  onClick={runInvestigation}
                  disabled={!selectedFile || isAnalyzing}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '12px 24px',
                    borderRadius: '8px',
                    border: 'none',
                    background: selectedFile && !isAnalyzing ? 'linear-gradient(135deg, #0284c7, #2563eb)' : '#334155',
                    color: '#ffffff',
                    fontWeight: 700,
                    fontSize: '0.95rem',
                    cursor: selectedFile && !isAnalyzing ? 'pointer' : 'not-allowed',
                    boxShadow: selectedFile && !isAnalyzing ? '0 0 15px rgba(37, 99, 235, 0.4)' : 'none'
                  }}
                >
                  {isAnalyzing ? <RefreshCw size={18} className="pulse-animation" /> : <Shield size={18} />}
                  {isAnalyzing ? 'Investigating Threat...' : 'Start Forensic Investigation'}
                </button>
              </div>

              {/* Investigation Progress Tracker */}
              {isAnalyzing && (
                <div style={{ marginTop: '24px', padding: '16px', background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#38bdf8' }} className="pulse-animation" />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#38bdf8' }}>{analysisStage}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: ACTIVE CASE DOSSIER */}
        {/* ========================================================================= */}
        {activeTab === 'dossier' && currentCase && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Case Header Banner */}
            <div style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: '12px',
              padding: '20px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px'
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                    CASE: {currentCase.case_id}
                  </h2>
                  <span style={{
                    background: getRiskBadgeColor(currentCase.threat_score?.risk_level),
                    color: '#ffffff',
                    padding: '3px 10px',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: 800,
                    letterSpacing: '0.05em'
                  }}>
                    {currentCase.threat_score?.risk_level || 'UNKNOWN'} RISK
                  </span>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Subject: <strong style={{ color: '#f8fafc' }}>{currentCase.email?.headers?.subject || 'No Subject'}</strong>
                </p>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Sender: <span style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{currentCase.header_analysis?.sender?.address || currentCase.email?.headers?.from || 'Unknown'}</span>
                </div>
              </div>

              {/* Export Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <a
                  href={`${API_BASE}/cases/${currentCase.case_id}/export/pdf`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'linear-gradient(135deg, #0284c7, #2563eb)',
                    color: '#ffffff',
                    padding: '8px 14px',
                    borderRadius: '6px',
                    textDecoration: 'none',
                    fontWeight: 700,
                    fontSize: '0.8rem',
                    boxShadow: '0 0 10px rgba(37, 99, 235, 0.3)'
                  }}
                >
                  <Download size={15} /> Export PDF Report
                </a>

                <a
                  href={`${API_BASE}/cases/${currentCase.case_id}/export/json`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: '#1e293b',
                    border: '1px solid #334155',
                    color: '#cbd5e1',
                    padding: '8px 14px',
                    borderRadius: '6px',
                    textDecoration: 'none',
                    fontWeight: 600,
                    fontSize: '0.8rem'
                  }}
                >
                  <FileText size={15} /> JSON Dossier
                </a>
              </div>
            </div>

            {/* Cryptographic Chain of Custody & Evidence Integrity Bar */}
            {caseIntegrity && (
              <div style={{
                background: '#070a12',
                border: '1px solid #1e293b',
                borderRadius: '8px',
                padding: '10px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.8rem',
                flexWrap: 'wrap',
                gap: '8px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileCheck size={16} color="#10b981" />
                  <span style={{ fontWeight: 700, color: '#10b981' }}>Chain of Custody Verified:</span>
                  <span style={{ color: 'var(--text-muted)' }}>SHA-256:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: '#38bdf8', fontSize: '0.75rem' }}>
                    {caseIntegrity.sha256_hash}
                  </span>
                  <button
                    onClick={() => copyToClipboard(caseIntegrity.sha256_hash)}
                    title="Copy SHA-256 Checksum"
                    style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}
                  >
                    <Copy size={13} />
                  </button>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Algorithm: {caseIntegrity.algorithm} | Immutable Artifact Sealed
                </div>
              </div>
            )}

            {/* Top Metrics Grid: Threat Score Gauge + Authentication Overview */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
              {/* Threat Score Card */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.05em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Composite Threat Score
                </div>
                <div style={{
                  fontSize: '3.5rem',
                  fontWeight: 900,
                  fontFamily: 'var(--font-mono)',
                  color: getRiskBadgeColor(currentCase.threat_score?.risk_level),
                  marginTop: '8px'
                }}>
                  {currentCase.threat_score?.score ?? 0}
                  <span style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>/100</span>
                </div>
                <div style={{
                  marginTop: '10px',
                  fontSize: '0.85rem',
                  color: 'var(--text-secondary)',
                  lineHeight: '1.4'
                }}>
                  {currentCase.threat_score?.summary}
                </div>
              </div>

              {/* Authentication & Evidence Snapshot */}
              <div style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-color)',
                borderRadius: '12px',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '16px'
              }}>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, letterSpacing: '0.05em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Authentication & Evidence Snapshot
                </div>

                {/* Badges Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                  <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>SPF</div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      {getAuthBadge(currentCase.authentication?.spf?.status)}
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>DKIM</div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      {getAuthBadge(currentCase.authentication?.dkim?.status)}
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px' }}>DMARC</div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      {getAuthBadge(currentCase.authentication?.dmarc?.status)}
                    </div>
                  </div>
                </div>

                {/* Top Evidence Reasons */}
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#94a3b8', marginBottom: '8px' }}>
                    Key Forensic Reasons ({currentCase.threat_score?.evidence_count || 0} findings):
                  </div>
                  {(!currentCase.threat_score?.evidence || currentCase.threat_score.evidence.length === 0) ? (
                    <div style={{ fontSize: '0.85rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle2 size={16} /> No threat anomalies detected in this message.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {currentCase.threat_score.evidence.slice(0, 3).map((ev, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem', background: '#131c2e', padding: '6px 10px', borderRadius: '6px' }}>
                          <span style={{ color: ev.severity === 'high' ? '#f87171' : '#fbbf24' }}>•</span>
                          <span style={{ color: '#e2e8f0' }}>{ev.reason}</span>
                          <span style={{ marginLeft: 'auto', color: '#38bdf8', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', fontWeight: 700 }}>+{ev.points} pts</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Dossier Tabs */}
            <div style={{
              display: 'flex',
              gap: '4px',
              borderBottom: '1px solid var(--border-color)',
              paddingBottom: '2px'
            }}>
              {[
                { id: 'summary', label: 'Explainable Evidence', icon: Shield },
                { id: 'graph', label: `Threat Graph (${caseGraph?.stats?.node_count || '...'})`, icon: Layers },
                { id: 'nlp', label: 'ML / NLP Intent', icon: FileText },
                { id: 'email', label: 'Email & MIME Body', icon: Mail },
                { id: 'headers', label: 'Header Spoofing & Hops', icon: Server },
                { id: 'iocs', label: `IOCs (${currentCase.iocs?.counts?.total || 0})`, icon: Hash },
                { id: 'urls', label: `URLs (${currentCase.url_analysis?.length || 0})`, icon: Link },
                { id: 'intelligence', label: 'Threat Intelligence', icon: Globe }
              ].map(t => {
                const IconComponent = t.icon;
                const isSelected = dossierTab === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setDossierTab(t.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px',
                      padding: '10px 16px',
                      background: isSelected ? 'var(--bg-secondary)' : 'transparent',
                      color: isSelected ? '#38bdf8' : 'var(--text-secondary)',
                      border: '1px solid',
                      borderColor: isSelected ? 'var(--border-color) var(--border-color) transparent var(--border-color)' : 'transparent',
                      borderTopLeftRadius: '8px',
                      borderTopRightRadius: '8px',
                      fontWeight: 600,
                      fontSize: '0.85rem',
                      cursor: 'pointer'
                    }}
                  >
                    <IconComponent size={15} /> {t.label}
                  </button>
                );
              })}
            </div>

            {/* Sub-Tab Content */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px' }}>
              {/* 1. Explainable Evidence */}
              {dossierTab === 'summary' && (
                <div>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '16px' }}>Detailed Forensic Evidence Breakdown</h3>
                  {(!currentCase.threat_score?.evidence || currentCase.threat_score.evidence.length === 0) ? (
                    <p style={{ color: 'var(--text-secondary)' }}>No risk points assigned.</p>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                          <th style={{ padding: '10px' }}>Category</th>
                          <th style={{ padding: '10px' }}>Severity</th>
                          <th style={{ padding: '10px' }}>Forensic Finding / Reason</th>
                          <th style={{ padding: '10px', textAlign: 'right' }}>Score Impact</th>
                        </tr>
                      </thead>
                      <tbody>
                        {currentCase.threat_score.evidence.map((ev, idx) => (
                          <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                            <td style={{ padding: '12px 10px', color: '#38bdf8', fontWeight: 600 }}>{ev.category}</td>
                            <td style={{ padding: '12px 10px' }}>
                              <span style={{
                                background: ev.severity === 'high' ? '#7f1d1d' : (ev.severity === 'medium' ? '#78350f' : '#1e293b'),
                                color: ev.severity === 'high' ? '#fca5a5' : (ev.severity === 'medium' ? '#fde68a' : '#94a3b8'),
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: 700
                              }}>
                                {ev.severity.toUpperCase()}
                              </span>
                            </td>
                            <td style={{ padding: '12px 10px', color: '#f1f5f9' }}>{ev.reason}</td>
                            <td style={{ padding: '12px 10px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: '#f87171', fontWeight: 700 }}>
                              +{ev.points} pts
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* 1.5 Threat Graph & Relationship Correlation */}
              {dossierTab === 'graph' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Forensic Threat Graph & Cross-Case Correlation</h3>
                      <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                        Visual node-link topology linking Send Identity, Origin IPs, Hops, Embedded Domains, Hashes, and Correlated Attacks.
                      </p>
                    </div>

                    <div style={{ display: 'flex', gap: '10px' }}>
                      <span style={{ fontSize: '0.75rem', background: '#1e293b', border: '1px solid #334155', color: '#38bdf8', padding: '4px 10px', borderRadius: '20px', fontFamily: 'var(--font-mono)' }}>
                        Nodes: {caseGraph?.stats?.node_count || 0} | Edges: {caseGraph?.stats?.edge_count || 0}
                      </span>
                      <span style={{ fontSize: '0.75rem', background: '#1e293b', border: '1px solid #334155', color: '#a855f7', padding: '4px 10px', borderRadius: '20px', fontFamily: 'var(--font-mono)' }}>
                        Correlated Cases: {caseGraph?.stats?.correlated_cases_count || 0}
                      </span>
                    </div>
                  </div>

                  {loadingGraph ? (
                    <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>Building forensic threat graph...</div>
                  ) : !caseGraph ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Graph data unavailable</div>
                  ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: '20px' }}>
                      {/* SVG Visual Graph Canvas */}
                      <div style={{
                        background: '#070a12',
                        border: '1px solid var(--border-color)',
                        borderRadius: '10px',
                        overflow: 'hidden',
                        position: 'relative',
                        height: '520px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                      }}>
                        {(() => {
                          const nodes = caseGraph.nodes || [];
                          const edges = caseGraph.edges || [];
                          const centerNode = nodes.find(n => n.type === 'case' && n.id.includes(currentCase.case_id)) || nodes[0];
                          const otherNodes = nodes.filter(n => n.id !== centerNode?.id);

                          const width = 760;
                          const height = 500;
                          const cx = width / 2;
                          const cy = height / 2;
                          const rx = 270;
                          const ry = 180;

                          const nodePositions = {};
                          if (centerNode) {
                            nodePositions[centerNode.id] = { x: cx, y: cy };
                          }

                          otherNodes.forEach((n, idx) => {
                            const angle = (2 * Math.PI * idx) / (otherNodes.length || 1) - Math.PI / 2;
                            nodePositions[n.id] = {
                              x: cx + rx * Math.cos(angle),
                              y: cy + ry * Math.sin(angle)
                            };
                          });

                          const getNodeColor = (node) => {
                            switch (node.type) {
                              case 'case': return node.risk === 'critical' ? '#ef4444' : (node.risk === 'high' ? '#f97316' : '#0284c7');
                              case 'sender': return '#a855f7';
                              case 'domain': return '#f59e0b';
                              case 'ip': return '#06b6d4';
                              case 'url': return node.risk === 'high_risk' ? '#ef4444' : '#fb923c';
                              case 'hash': return '#ec4899';
                              default: return '#64748b';
                            }
                          };

                          return (
                            <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} style={{ userSelect: 'none' }}>
                              <defs>
                                <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
                                </marker>
                              </defs>

                              {/* Edges */}
                              {edges.map((edge, idx) => {
                                const sourcePos = nodePositions[edge.source];
                                const targetPos = nodePositions[edge.target];
                                if (!sourcePos || !targetPos) return null;

                                const midX = (sourcePos.x + targetPos.x) / 2;
                                const midY = (sourcePos.y + targetPos.y) / 2;

                                return (
                                  <g key={idx}>
                                    <line
                                      x1={sourcePos.x}
                                      y1={sourcePos.y}
                                      x2={targetPos.x}
                                      y2={targetPos.y}
                                      stroke="#334155"
                                      strokeWidth="1.8"
                                      strokeDasharray={edge.relationship === 'SHARES_INDICATOR' ? '4,4' : 'none'}
                                      markerEnd="url(#arrow)"
                                    />
                                    <text
                                      x={midX}
                                      y={midY - 4}
                                      fill="#64748b"
                                      fontSize="9"
                                      fontFamily="monospace"
                                      textAnchor="middle"
                                    >
                                      {edge.relationship}
                                    </text>
                                  </g>
                                );
                              })}

                              {/* Nodes */}
                              {nodes.map((node) => {
                                const pos = nodePositions[node.id];
                                if (!pos) return null;
                                const isSelected = selectedGraphNode?.id === node.id;
                                const isCenter = node.id === centerNode?.id;
                                const color = getNodeColor(node);

                                return (
                                  <g
                                    key={node.id}
                                    transform={`translate(${pos.x}, ${pos.y})`}
                                    onClick={() => setSelectedGraphNode(node)}
                                    style={{ cursor: 'pointer' }}
                                  >
                                    <circle
                                      r={isCenter ? 26 : (isSelected ? 20 : 16)}
                                      fill={color}
                                      stroke={isSelected ? '#ffffff' : 'rgba(255,255,255,0.2)'}
                                      strokeWidth={isSelected ? 3 : 1.5}
                                      opacity={0.9}
                                      style={{ transition: 'all 0.2s' }}
                                    />
                                    <text
                                      y={isCenter ? 38 : 28}
                                      fill={isSelected ? '#38bdf8' : '#cbd5e1'}
                                      fontSize={isCenter ? "11" : "10"}
                                      fontWeight={isCenter || isSelected ? "bold" : "normal"}
                                      fontFamily="sans-serif"
                                      textAnchor="middle"
                                    >
                                      {node.label}
                                    </text>
                                    <text
                                      y="4"
                                      fill="#ffffff"
                                      fontSize="9"
                                      fontWeight="bold"
                                      textAnchor="middle"
                                      fontFamily="monospace"
                                    >
                                      {node.type.toUpperCase().slice(0, 3)}
                                    </text>
                                  </g>
                                );
                              })}
                            </svg>
                          );
                        })()}
                      </div>

                      {/* Node Inspector Sidecard */}
                      <div style={{
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '10px',
                        padding: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '12px'
                      }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          Node Inspector
                        </div>

                        {selectedGraphNode ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            <div>
                              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Type:</div>
                              <span style={{
                                background: '#1e293b',
                                color: '#38bdf8',
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)'
                              }}>
                                {selectedGraphNode.type.toUpperCase()}
                              </span>
                            </div>

                            <div>
                              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Identifier / Label:</div>
                              <div style={{ fontSize: '0.85rem', color: '#f8fafc', fontWeight: 600, wordBreak: 'break-all' }}>
                                {selectedGraphNode.label}
                              </div>
                            </div>

                            <div>
                              <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Risk Status:</div>
                              <span style={{
                                background: selectedGraphNode.risk === 'high_risk' || selectedGraphNode.risk === 'critical' ? '#7f1d1d' : (selectedGraphNode.risk === 'suspicious' ? '#78350f' : '#064e3b'),
                                color: selectedGraphNode.risk === 'high_risk' || selectedGraphNode.risk === 'critical' ? '#fca5a5' : (selectedGraphNode.risk === 'suspicious' ? '#fde68a' : '#34d399'),
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: 700
                              }}>
                                {(selectedGraphNode.risk || 'safe').toUpperCase()}
                              </span>
                            </div>

                            <div>
                              <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '4px' }}>Properties:</div>
                              <pre style={{
                                background: '#090d16',
                                padding: '10px',
                                borderRadius: '6px',
                                fontSize: '0.75rem',
                                color: '#cbd5e1',
                                maxHeight: '180px',
                                overflowY: 'auto',
                                fontFamily: 'var(--font-mono)'
                              }}>
                                {JSON.stringify(selectedGraphNode.details, null, 2)}
                              </pre>
                            </div>
                          </div>
                        ) : (
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Click any node in the graph to inspect forensic attributes.</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Correlated Cases Table */}
                  {caseGraph?.correlated_cases?.length > 0 && (
                    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '16px' }}>
                      <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f87171', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertTriangle size={16} /> Connected Campaign Correlated Attacks ({caseGraph.correlated_cases.length})
                      </h4>
                      <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                            <th style={{ padding: '8px' }}>Correlated Case</th>
                            <th style={{ padding: '8px' }}>Risk Tier</th>
                            <th style={{ padding: '8px' }}>Shared Forensic Indicator</th>
                            <th style={{ padding: '8px', textAlign: 'right' }}>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {caseGraph.correlated_cases.map((cc, i) => (
                            <tr key={i} style={{ borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                              <td style={{ padding: '8px', color: '#38bdf8', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{cc.case_id}</td>
                              <td style={{ padding: '8px' }}>
                                <span style={{
                                  background: getRiskBadgeColor(cc.risk_level),
                                  color: '#ffffff',
                                  padding: '2px 6px',
                                  borderRadius: '3px',
                                  fontSize: '0.7rem',
                                  fontWeight: 700
                                }}>
                                  {cc.risk_level}
                                </span>
                              </td>
                              <td style={{ padding: '8px', color: '#cbd5e1', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                                <span style={{ color: '#94a3b8' }}>[{cc.indicator_type}]</span> {cc.shared_indicator}
                              </td>
                              <td style={{ padding: '8px', textAlign: 'right' }}>
                                <button
                                  onClick={() => loadCaseDossier(cc.case_id)}
                                  style={{
                                    background: '#1e293b',
                                    border: '1px solid #334155',
                                    color: '#38bdf8',
                                    padding: '4px 10px',
                                    borderRadius: '4px',
                                    fontSize: '0.75rem',
                                    fontWeight: 600,
                                    cursor: 'pointer'
                                  }}
                                >
                                  Open Case
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* 1.8 ML & NLP Phishing Content Intent */}
              {dossierTab === 'nlp' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Machine Learning & Semantic Phishing Content Analysis</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                      Heuristic NLP intent classification, urgency metrics, credential solicitation language, and statistical phishing probability.
                    </p>
                  </div>

                  {!currentCase.nlp_analysis ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>No NLP analysis record found for this case.</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                      {/* Top Metrics Row */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
                        {/* Phishing Probability */}
                        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '20px', textAlign: 'center' }}>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Phishing Probability</div>
                          <div style={{
                            fontSize: '2.5rem',
                            fontWeight: 900,
                            fontFamily: 'var(--font-mono)',
                            color: currentCase.nlp_analysis.phishing_probability >= 0.7 ? '#ef4444' : (currentCase.nlp_analysis.phishing_probability >= 0.4 ? '#f59e0b' : '#10b981'),
                            marginTop: '6px'
                          }}>
                            {(currentCase.nlp_analysis.phishing_probability * 100).toFixed(0)}%
                          </div>
                          <span style={{
                            background: getRiskBadgeColor(currentCase.nlp_analysis.risk_tier),
                            color: '#ffffff',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '0.7rem',
                            fontWeight: 800
                          }}>
                            {currentCase.nlp_analysis.risk_tier} INTENT RISK
                          </span>
                        </div>

                        {/* Semantic Intents Detected */}
                        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Detected Semantic Intents</div>
                          {currentCase.nlp_analysis.intents_detected?.length === 0 ? (
                            <div style={{ fontSize: '0.85rem', color: '#10b981', marginTop: '8px' }}>No hostile intents detected.</div>
                          ) : (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                              {currentCase.nlp_analysis.intents_detected?.map((intent, i) => (
                                <span key={i} style={{
                                  background: '#1e293b',
                                  border: '1px solid #334155',
                                  color: '#38bdf8',
                                  padding: '4px 8px',
                                  borderRadius: '4px',
                                  fontSize: '0.75rem',
                                  fontWeight: 600,
                                  fontFamily: 'var(--font-mono)'
                                }}>
                                  {intent.replace('_', ' ').toUpperCase()}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>

                        {/* Lexical Features */}
                        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Lexical Statistics</div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px', marginTop: '4px' }}>
                            <div>Word Count: <span style={{ color: '#f8fafc', fontWeight: 700 }}>{currentCase.nlp_analysis.lexical_features?.word_count || 0}</span></div>
                            <div>Caps Ratio: <span style={{ color: '#f8fafc', fontWeight: 700 }}>{((currentCase.nlp_analysis.lexical_features?.caps_ratio || 0) * 100).toFixed(1)}%</span></div>
                            <div>Exclamations: <span style={{ color: '#f8fafc', fontWeight: 700 }}>{currentCase.nlp_analysis.lexical_features?.exclamation_count || 0}</span></div>
                            <div>Urgency Score: <span style={{ color: '#38bdf8', fontWeight: 700 }}>{currentCase.nlp_analysis.lexical_features?.urgency_score || 0}</span></div>
                          </div>
                        </div>
                      </div>

                      {/* Summary Banner */}
                      <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '14px 18px', fontSize: '0.85rem', color: '#cbd5e1' }}>
                        <strong>NLP Diagnostic:</strong> {currentCase.nlp_analysis.summary}
                      </div>

                      {/* Trigger Phrases & Context Snippets */}
                      <div>
                        <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '12px' }}>
                          Matched Trigger Phrases & Excerpt Context ({currentCase.nlp_analysis.matched_keywords?.length || 0})
                        </h4>
                        {(!currentCase.nlp_analysis.matched_keywords || currentCase.nlp_analysis.matched_keywords.length === 0) ? (
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No hostile keyword patterns matched in text body.</div>
                        ) : (
                          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                            <thead>
                              <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                                <th style={{ padding: '10px' }}>Category</th>
                                <th style={{ padding: '10px' }}>Trigger Phrase</th>
                                <th style={{ padding: '10px' }}>Pattern Description</th>
                                <th style={{ padding: '10px' }}>Context Excerpt</th>
                                <th style={{ padding: '10px', textAlign: 'right' }}>Weight</th>
                              </tr>
                            </thead>
                            <tbody>
                              {currentCase.nlp_analysis.matched_keywords.map((kw, i) => (
                                <tr key={i} style={{ borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                                  <td style={{ padding: '10px', color: '#38bdf8', fontWeight: 600 }}>{kw.category}</td>
                                  <td style={{ padding: '10px', color: '#f87171', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>"{kw.phrase}"</td>
                                  <td style={{ padding: '10px', color: '#cbd5e1' }}>{kw.description}</td>
                                  <td style={{ padding: '10px', color: '#94a3b8', fontSize: '0.8rem', fontStyle: 'italic', maxWidth: '340px' }}>{kw.context}</td>
                                  <td style={{ padding: '10px', textAlign: 'right', color: '#fbbf24', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>+{kw.weight}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* 2. Email & MIME Body */}
              {dossierTab === 'email' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px', background: 'var(--bg-card)', padding: '16px', borderRadius: '8px' }}>
                    <div><span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>From:</span> <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#f1f5f9' }}>{currentCase.email?.headers?.from || 'N/A'}</div></div>
                    <div><span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>To:</span> <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#f1f5f9' }}>{currentCase.email?.headers?.to || 'N/A'}</div></div>
                    <div><span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Subject:</span> <div style={{ fontSize: '0.85rem', color: '#f1f5f9', fontWeight: 600 }}>{currentCase.email?.headers?.subject || 'N/A'}</div></div>
                    <div><span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Date:</span> <div style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>{currentCase.email?.headers?.date || 'N/A'}</div></div>
                  </div>

                  <div>
                    <h4 style={{ fontSize: '0.9rem', color: '#94a3b8', marginBottom: '8px' }}>Plain Text Body</h4>
                    <pre style={{
                      background: '#090d16',
                      border: '1px solid var(--border-color)',
                      borderRadius: '8px',
                      padding: '16px',
                      color: '#cbd5e1',
                      fontSize: '0.85rem',
                      whiteSpace: 'pre-wrap',
                      maxHeight: '300px',
                      overflowY: 'auto',
                      fontFamily: 'var(--font-mono)'
                    }}>
                      {currentCase.email?.body?.plain_text || '(No plain text body content found)'}
                    </pre>
                  </div>
                </div>
              )}

              {/* 3. Header Spoofing & Hops */}
              {dossierTab === 'headers' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f1f5f9' }}>Routing Hop Chain (Chronological Origin to Destination)</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {currentCase.header_analysis?.hops?.map((hop, i) => (
                      <div key={i} style={{ background: 'var(--bg-card)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ background: '#1e293b', color: '#38bdf8', padding: '2px 6px', borderRadius: '4px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>Hop #{hop.hop_number}</span>
                            <span style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>{hop.from_host || 'Unknown Host'}</span>
                            <ArrowRight size={14} color="var(--text-muted)" />
                            <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>{hop.by_host || 'Gateway'}</span>
                          </div>
                          {hop.public_ip && <div style={{ fontSize: '0.75rem', color: '#38bdf8', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>IP: {hop.public_ip}</div>}
                        </div>
                        <div>
                          {hop.is_encrypted ? (
                            <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#34d399', fontSize: '0.75rem' }}><Lock size={12} /> TLS Encrypted</span>
                          ) : (
                            <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>Plain Transport</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* 4. IOCs */}
              {dossierTab === 'iocs' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f1f5f9' }}>Extracted Indicators of Compromise (Deduplicated)</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '16px' }}>
                    {/* Domains */}
                    <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8', marginBottom: '8px' }}>Domains ({currentCase.iocs?.domains?.length || 0})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {currentCase.iocs?.domains?.map((d, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.8rem', fontFamily: 'var(--font-mono)', background: '#090d16', padding: '6px 10px', borderRadius: '4px' }}>
                            <span>{d}</span>
                            <button onClick={() => copyToClipboard(d)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}><Copy size={13} /></button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* IPs */}
                    <div style={{ background: 'var(--bg-card)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8', marginBottom: '8px' }}>IPv4 Addresses ({currentCase.iocs?.ips?.length || 0})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {currentCase.iocs?.ips?.map((ip, i) => (
                          <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.8rem', fontFamily: 'var(--font-mono)', background: '#090d16', padding: '6px 10px', borderRadius: '4px' }}>
                            <span>{ip}</span>
                            <button onClick={() => copyToClipboard(ip)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}><Copy size={13} /></button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* 5. Safe URL Analysis */}
              {dossierTab === 'urls' && (
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '16px' }}>Static URL Security Assessment</h4>
                  {(!currentCase.url_analysis || currentCase.url_analysis.length === 0) ? (
                    <p style={{ color: 'var(--text-secondary)' }}>No URLs detected in this email.</p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {currentCase.url_analysis.map((u, i) => (
                        <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '14px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#38bdf8', wordBreak: 'break-all' }}>{u.url}</span>
                            <span style={{
                              background: u.risk_level === 'high_risk' ? '#7f1d1d' : (u.risk_level === 'suspicious' ? '#78350f' : '#064e3b'),
                              color: u.risk_level === 'high_risk' ? '#fca5a5' : (u.risk_level === 'suspicious' ? '#fde68a' : '#34d399'),
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '0.75rem',
                              fontWeight: 700
                            }}>
                              {u.risk_level.toUpperCase()}
                            </span>
                          </div>
                          {u.flags && u.flags.length > 0 && (
                            <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              {u.flags.map((f, fi) => (
                                <div key={fi} style={{ fontSize: '0.8rem', color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                  <AlertTriangle size={12} /> {f.message}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* 6. Threat Intelligence */}
              {dossierTab === 'intelligence' && (
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '16px' }}>Live Domain & IP Intelligence (Real Lookups)</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {/* Domain intel */}
                    {Object.entries(currentCase.intelligence?.domains || {}).map(([domain, data], i) => (
                      <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                          <span style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff' }}>Domain: {domain}</span>
                          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Registrar: {data.rdap?.registrar || 'N/A'}</span>
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                          <div>MX Records: <span style={{ color: '#f1f5f9' }}>{data.dns?.mx_records?.join(', ') || 'None found'}</span></div>
                          <div>A Records: <span style={{ color: '#f1f5f9' }}>{data.dns?.a_records?.join(', ') || 'None found'}</span></div>
                        </div>
                      </div>
                    ))}

                    {/* IP intel */}
                    {Object.entries(currentCase.intelligence?.ips || {}).map(([ip, data], i) => (
                      <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                          <span style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>IP: {ip}</span>
                          {data.is_private ? (
                            <span style={{ fontSize: '0.75rem', background: '#334155', color: '#cbd5e1', padding: '2px 6px', borderRadius: '4px' }}>Private Network</span>
                          ) : (
                            <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>{data.geolocation?.country} ({data.geolocation?.city || 'N/A'})</span>
                          )}
                        </div>
                        {!data.is_private && data.geolocation?.status === 'available' && (
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                            <div>ISP: <span style={{ color: '#f1f5f9' }}>{data.geolocation?.isp}</span></div>
                            <div>ASN: <span style={{ color: '#f1f5f9' }}>{data.geolocation?.asn}</span></div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: CASES LEDGER */}
        {/* ========================================================================= */}
        {activeTab === 'cases' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Forensic Cases Ledger</h2>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Persistent database history of all investigated emails.</p>
              </div>

              {/* Risk Filter Buttons */}
              <div style={{ display: 'flex', gap: '6px' }}>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(r => (
                  <button
                    key={r}
                    onClick={() => setRiskFilter(r)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: '6px',
                      border: '1px solid',
                      borderColor: riskFilter === r ? '#38bdf8' : 'var(--border-color)',
                      background: riskFilter === r ? '#1e293b' : 'transparent',
                      color: riskFilter === r ? '#38bdf8' : 'var(--text-secondary)',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>

            {loadingCases ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>Loading cases...</div>
            ) : casesList.length === 0 ? (
              <div style={{ padding: '60px', textAlign: 'center', background: 'var(--bg-secondary)', borderRadius: '12px', border: '1px solid var(--border-color)' }}>
                <Database size={40} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
                <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>No investigations yet</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '4px' }}>
                  Upload a real .eml file to create and store your first forensic case.
                </p>
              </div>
            ) : (
              <div style={{ background: 'var(--bg-secondary)', borderRadius: '12px', border: '1px solid var(--border-color)', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                      <th style={{ padding: '12px 16px' }}>Case ID</th>
                      <th style={{ padding: '12px 16px' }}>Risk Tier</th>
                      <th style={{ padding: '12px 16px' }}>Threat Score</th>
                      <th style={{ padding: '12px 16px' }}>Subject</th>
                      <th style={{ padding: '12px 16px' }}>Sender</th>
                      <th style={{ padding: '12px 16px' }}>Source</th>
                      <th style={{ padding: '12px 16px', textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {casesList.map((c, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                        <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#38bdf8' }}>{c.case_id}</td>
                        <td style={{ padding: '14px 16px' }}>
                          <span style={{
                            background: getRiskBadgeColor(c.risk_level),
                            color: '#ffffff',
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontWeight: 800
                          }}>
                            {c.risk_level}
                          </span>
                        </td>
                        <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                          {c.threat_score}/100
                        </td>
                        <td style={{ padding: '14px 16px', color: '#f1f5f9', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {c.subject}
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {c.sender}
                        </td>
                        <td style={{ padding: '14px 16px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                          {c.source}
                        </td>
                        <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                          <button
                            onClick={() => loadCaseDossier(c.case_id)}
                            style={{
                              background: '#1e293b',
                              border: '1px solid #334155',
                              color: '#38bdf8',
                              padding: '5px 12px',
                              borderRadius: '6px',
                              fontSize: '0.8rem',
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            View Dossier
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: GMAIL LIVE WATCH */}
        {/* ========================================================================= */}
        {activeTab === 'gmail' && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', borderRadius: '12px', padding: '24px' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Mail color="var(--accent-cyan)" /> Automatic Gmail Detection & Real-Time Watch
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '24px' }}>
              Automatic Gmail monitoring uses OAuth 2.0 and Google Cloud Pub/Sub webhooks to ingest incoming emails in real time without polling.
            </p>

            <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '24px', maxWidth: '640px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ background: '#1e293b', padding: '10px', borderRadius: '8px' }}>
                    <Mail size={24} color="#38bdf8" />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>Gmail Account Authorization</div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Official Google OAuth 2.0 (Read-Only Security Auditing)</div>
                  </div>
                </div>
              </div>

              <div style={{ background: '#090d16', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '8px', fontWeight: 600 }}>OAuth Credentials (.env Setup):</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#cbd5e1', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div>GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com</div>
                  <div>GOOGLE_CLIENT_SECRET=your-google-client-secret</div>
                  <div>GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/gmail/callback</div>
                </div>
              </div>

              <button
                onClick={async () => {
                  try {
                    const res = await fetch(`${API_BASE}/gmail/connect`);
                    const data = await res.json();
                    if (data.success && data.data.auth_url) {
                      window.location.href = data.data.auth_url;
                    } else {
                      alert(data.error?.message || 'Google OAuth is not configured in backend .env');
                    }
                  } catch (err) {
                    alert('Failed to contact backend OAuth endpoint');
                  }
                }}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: 'linear-gradient(135deg, #0284c7, #2563eb)',
                  border: 'none',
                  color: '#ffffff',
                  borderRadius: '8px',
                  fontWeight: 700,
                  fontSize: '0.9rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px'
                }}
              >
                <Lock size={16} /> Connect Gmail Account via OAuth 2.0
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
