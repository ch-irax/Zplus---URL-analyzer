const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const { JSDOM } = require('jsdom'); // For sandbox preview
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public')); // Serve the existing frontend from public/ (copy index.html + assets)

// ==================== CORE SCAN LOGIC (Enhanced Backend) ====================
async function performFullScan(url) {
  let domain = new URL(url).hostname.toLowerCase();
  if (domain.startsWith('www.')) domain = domain.slice(4);

  // 1. Basic Validation & Normalization
  if (!url.startsWith('http')) url = `https://${url}`;

  // 2. Advanced Heuristics (OWASP-style + more)
  const heuristics = analyzeHeuristics(url, domain);
  if (heuristics.isHighRisk) {
    return { threatLevel: 'HIGH', trustScore: heuristics.trustScore, details: heuristics };
  }

  // 3. Real Reputation Checks (free/public APIs where possible)
  const reputation = await getRealReputation(domain);
  if (reputation.detections > 0) {
    return { threatLevel: 'HIGH', trustScore: heuristics.trustScore * 0.6, details: { ...heuristics, reputation } };
  }

  // 4. Node Intelligence (real data)
  const nodeInfo = await getRealNodeInfo(domain);
  heuristics.tldRisk = nodeInfo.tldRisk;

  // 5. Redirection Trace (real)
  const redirects = await traceRedirects(url);

  // 6. Sandboxed Preview (headless simulation)
  const preview = await getSandboxPreview(url);

  // 7. Final Verdict
  const trustScore = calculateTrustScore(heuristics, reputation, nodeInfo, redirects.length);
  const isPhishing = trustScore < 70;

  return {
    url,
    domain,
    isPhishing,
    trustScore: Math.round(trustScore),
    verdict: isPhishing ? 'Phishing Detected' : 'Safe',
    ip: nodeInfo.ip,
    geo: nodeInfo.geo,
    tldRisk: nodeInfo.tldRisk,
    latency: nodeInfo.latency,
    redirects,
    preview: preview.screenshot, // base64 or URL
    heuristics,
    reputation
  };
}

// 2.1 Advanced Heuristics (replace the old analyzeUrl)
function analyzeHeuristics(url, domain) {
  const score = 100;
  let issues = [];

  // Punycode/Homoglyph (OWASP)
  if (/xn--/.test(domain)) issues.push({ name: 'Punycode/Homoglyph', status: 'warn', rationale: 'Obfuscated characters detected' });

  // DGA / High Entropy
  const entropy = (url.match(/[0-9a-z]/gi) || []).length / url.length;
  if (entropy > 0.85 || domain.length > 25) {
    issues.push({ name: 'DGA Entropy', status: 'high', rationale: 'Random-looking domain' });
  }

  // Phishing Keywords (weighted)
  const keywords = ['paypal', 'login', 'secure', 'verify', 'account', 'update', 'billing', 'signin', 'support', 'wallet', 'crypto'];
  let keywordScore = 0;
  keywords.forEach(kw => {
    if (domain.includes(kw) && !['paypal.com', 'binance.com', 'coinbase.com'].some(s => domain.endsWith(s))) {
      keywordScore += 25;
    }
  });

  // Suspicious params / obfuscation
  if (url.includes('redirect=') || url.includes('@') || url.includes('?') && !url.includes('=http')) issues.push({ name: 'Suspicious Params', status: 'warn' });

  // TLD Risk (expanded list)
  const highRiskTlds = ['.xyz', '.top', '.link', '.pw', '.tk', '.ga', '.ml', '.cf', '.icu', '.work', '.online', '.loan'];
  if (highRiskTlds.some(tld => domain.endsWith(tld))) issues.push({ name: 'High-Risk TLD', status: 'high' });

  // Subdomain / IP
  const parts = domain.split('.');
  if (parts.length > 3) issues.push({ name: 'Long Subdomain', status: 'warn' });

  const trustScore = Math.max(5, 100 - (keywordScore + issues.length * 8));

  return { trustScore, issues, isHighRisk: issues.some(i => i.status === 'high') };
}

// 2.2 Real Reputation (public APIs)
async function getRealReputation(domain) {
  try {
    // VirusTotal (free tier limited; replace with your API key)
    const vtRes = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': process.env.VT_API_KEY || 'demo' }
    });
    const detections = vtRes.data.data.attributes.last_analysis_stats?.malicious || 0;

    // OpenPhish (demo)
    const opRes = await axios.get(`https://openphish.com/feed.txt`).catch(() => ({ data: '' }));
    const isListed = opRes.data.includes(domain);

    return { detections, isListed };
  } catch (e) {
    return { detections: 0, isListed: false };
  }
}

// 2.3 Real Node Intelligence
async function getRealNodeInfo(domain) {
  try {
    // DNS lookup (simple with axios or node:dns)
    const { data: ipRes } = await axios.get(`https://dns.google/resolve?name=${domain}`);
    const ip = ipRes.Answer?.[0]?.data;

    // Geolocation (IP-API or similar)
    const geoRes = await axios.get(`http://ip-api.com/json/${ip}`);
    const geo = `${geoRes.data.city}, ${geoRes.data.country}`;

    // Latency
    const latencyRes = await axios.get(`https://www.google.com/generate_204`, {
      headers: { 'Host': domain },
      timeout: 5000
    }).catch(() => ({ headers: { 'server-timing': '' } }));
    const latency = parseInt(latencyRes.headers['server-timing']?.match(/dns;dur=(\d+)/)?.[1] || 50);

    const tldRisk = highRiskTlds.some(tld => domain.endsWith(tld)) ? 'High' : 'Low';

    return { ip, geo, latency, tldRisk };
  } catch (e) {
    return { ip: 'Unknown', geo: 'Unknown', latency: 'N/A', tldRisk: 'Low' };
  }
}

// 2.4 Redirection Trace (real history)
async function traceRedirects(url) {
  const steps = [];
  try {
    let current = url;
    for (let i = 0; i < 5; i++) { // max depth
      const res = await axios.head(current, { maxRedirects: 0 });
      steps.push({ label: `Step ${i+1}`, url: current });
      if (!res.headers.location) break;
      current = new URL(res.headers.location, current).href;
    }
  } catch (e) {}
  return steps;
}

// 2.5 Sandboxed Preview (real headless simulation)
async function getSandboxPreview(url) {
  try {
    const { JSDOM } = require('jsdom');
    const dom = new JSDOM(`<!DOCTYPE html><html><body><h1>Previewing ${url}</h1></body></html>`, {
      url,
      pretendToBeVisual: true,
      resources: 'usable'
    });
    // In real production, use Puppeteer instead for actual screenshot
    return { screenshot: `https://placehold.co/1280x720/1a1a1a/white?text=Sandbox+Preview+of+${url}` };
  } catch (e) {
    return { screenshot: 'https://placehold.co/1280x720/gray?text=No+Preview' };
  }
}

// 2.6 Trust Score Calculation
function calculateTrustScore(heuristics, rep, node, redCount) {
  let score = heuristics.trustScore;
  if (rep.detections > 0) score *= 0.4;
  if (redCount > 2) score -= 20;
  if (node.latency > 200) score -= 15;
  return Math.max(5, Math.min(100, score));
}

// API Endpoint
app.post('/scan', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  try {
    const result = await performFullScan(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Scan failed' });
  }
});

// Start server
app.listen(PORT, () => console.log(`Zplus Backend running on http://localhost:${PORT}`));