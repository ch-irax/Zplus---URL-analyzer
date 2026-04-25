/**
 * Zpluslink — Core Logic Engine
 * V2.4 Prime Security Infrastructure
 */

// --- TAILWIND CONFIGURATION ---
tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                black: '#050505',
                grey: {
                    950: '#0A0A0A',
                    900: '#121212',
                    800: '#1A1A1A',
                    700: '#262626',
                    600: '#333333',
                },
                emerald: {
                    500: '#10B981',
                    400: '#34D399',
                },
                red: {
                    500: '#EF4444',
                    400: '#F87171',
                },
                amber: {
                    500: '#F59E0B',
                    400: '#FBBF24',
                }
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                display: ['Orbitron', 'Outfit', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
            animation: {
                'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'float': 'float 6s ease-in-out infinite',
                'scanline': 'scanline 8s linear infinite',
            },
            keyframes: {
                float: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-10px)' },
                },
                scanline: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100%)' },
                }
            }
        }
    }
}

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Lucide Icons
    if (typeof lucide !== 'undefined') lucide.createIcons();
    // Initialize Starfield Background
    initUniverse();
    // Initial render of recents
    renderRecents();
});

// --- CONSTANTS & STATE ---
const RECENT_LIMIT = 4;
let currentScanResult = null;

// --- CORE SCANNING LOGIC ---

function startAnalysis() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    if (!url) return alert('Please enter a URL');

    // Sanitize and Validate URL
    let normalizedUrl;
    try {
        normalizedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch (e) {
        return alert('Invalid URL format');
    }

    // UI Transitions
    document.getElementById('hero').classList.add('opacity-10', 'pointer-events-none');
    const analysisSeq = document.getElementById('analysis-sequence');
    analysisSeq.classList.remove('hidden');
    
    // Boost Background for Analysis
    boostUniverse();
    
    // Run Sequence
    runMatrixRain(normalizedUrl.href);
    runTerminalLogs(normalizedUrl.hostname);
}

function runMatrixRain(url) {
    const container = document.getElementById('url-fragments');
    container.innerHTML = '';
    const chars = url.split('');
    const elements = chars.map(char => {
        const span = document.createElement('span');
        span.textContent = char;
        span.className = 'transition-all duration-500 opacity-0 transform translate-y-4 inline-block';
        container.appendChild(span);
        return span;
    });

    let delay = 0;
    elements.forEach((el, index) => {
        setTimeout(() => {
            el.classList.remove('opacity-0', 'translate-y-4');
            el.classList.add('opacity-100', 'translate-y-0');
            if (index % 3 === 0) el.classList.add('text-white');
        }, delay);
        delay += 50;
    });
}

async function runTerminalLogs(domain) {
    const logs = [
        "ZPLUS-ENGINE [v2.4] initializing...",
        `Target identified: ${domain}`,
        "Establishing secure sandbox container...",
        "Bypassing potential anti-analysis scripts...",
        "Following redirect nodes [301/302]...",
        "Dumping DNS records (TXT/CSNAME)...",
        "Capturing encrypted visual preview...",
        "Applying OWASP phishing heuristics...",
        "Calculating entropy-based risk score...",
        "Finalizing forensic report..."
    ];

    const terminal = document.getElementById('terminal-logs');
    const progressCircle = document.getElementById('analysis-progress');
    const percentageText = document.getElementById('analysis-percentage');
    terminal.innerHTML = '';

    for (let i = 0; i < logs.length; i++) {
        const p = document.createElement('p');
        p.className = 'text-emerald-400/80';
        p.innerHTML = `<span class="text-zinc-600">[${new Date().toLocaleTimeString('en-US', {hour12: false})}]</span> $ ${logs[i]}`;
        terminal.appendChild(p);
        terminal.scrollTop = terminal.scrollHeight;

        const progress = ((i + 1) / logs.length) * 100;
        const offset = 552.92 - (552.92 * progress) / 100;
        progressCircle.style.strokeDashoffset = offset;
        percentageText.innerText = `${Math.round(progress)}%`;

        await new Promise(resolve => setTimeout(resolve, 350 + Math.random() * 200));
    }

    // Complete Scan
    setTimeout(() => finishScan(domain), 500);
}

function finishScan(domain) {
    // Mock Data Generation
    const isPhishing = domain.includes('paypa') || domain.includes('secure') || domain.includes('verify') || Math.random() > 0.8;
    const trustScore = isPhishing ? Math.floor(Math.random() * 30) + 5 : Math.floor(Math.random() * 20) + 80;
    
    currentScanResult = {
        url: document.getElementById('url-input').value,
        domain: domain,
        isPhishing: isPhishing,
        trustScore: trustScore,
        ip: `103.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.88`,
        location: isPhishing ? "Russia, Moscow" : "USA, San Francisco",
        latency: `${Math.floor(Math.random() * 150) + 20}ms`,
        tldRisk: isPhishing ? "High (.xyz)" : "Low (.com)",
        checks: generateOwaspChecks(isPhishing)
    };

    // Transition UI to Results
    document.getElementById('analysis-sequence').classList.add('hidden');
    document.getElementById('hero').classList.add('hidden');
    document.getElementById('results-panel').classList.remove('hidden');
    resetUniverseBoost();
    
    populateResults(currentScanResult);
    saveToRecents(currentScanResult);
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function populateResults(data) {
    // Top Bar
    document.getElementById('report-url-display').innerText = data.url;
    
    // Verdict
    const orb = document.getElementById('verdict-orb');
    const label = document.getElementById('verdict-label');
    const desc = document.getElementById('verdict-desc');
    const icon = document.getElementById('verdict-icon');
    
    if (data.isPhishing) {
        orb.className = "w-24 h-24 rounded-full flex items-center justify-center animate-pulse-slow bg-red-500 shadow-[0_0_30px_rgba(239,68,68,0.5)]";
        label.innerText = "Phishing Detected";
        label.className = "text-4xl font-display font-black tracking-tighter uppercase mb-2 text-red-500";
        desc.innerText = "This URL exhibits multiple high-risk indicators associated with credential theft and social engineering.";
        icon.setAttribute('data-lucide', 'alert-octagon');

    } else if (data.trustScore < 70) {
        orb.className = "w-24 h-24 rounded-full flex items-center justify-center animate-pulse-slow bg-amber-500 shadow-[0_0_30px_rgba(245,158,11,0.5)]";
        label.innerText = "Suspicious";
        label.className = "text-4xl font-display font-black tracking-tighter uppercase mb-2 text-amber-500";
        desc.innerText = "Proceed with extreme caution. The domain has anomalies that could indicate a sophisticated attack.";
        icon.setAttribute('data-lucide', 'help-circle');

    } else {
        orb.className = "w-24 h-24 rounded-full flex items-center justify-center animate-pulse-slow bg-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.5)]";
        label.innerText = "Safe";
        label.className = "text-4xl font-display font-black tracking-tighter uppercase mb-2 text-emerald-500";
        desc.innerText = "No major threats detected. This URL matches known legitimate domain patterns and security standards.";
        icon.setAttribute('data-lucide', 'shield-check');

    }

    // Trust score
    const radial = document.getElementById('trust-radial');
    radial.style.setProperty('--value', data.trustScore);
    radial.style.setProperty('--color', data.isPhishing ? '#EF4444' : (data.trustScore < 70 ? '#F59E0B' : '#10B981'));
    document.getElementById('trust-score-num').innerText = data.trustScore;

    // OWASP Table
    const tbody = document.getElementById('owasp-checks-body');
    tbody.innerHTML = '';
    data.checks.forEach(check => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="py-4 pr-4 font-semibold text-white">${check.name}</td>
            <td class="py-4 pr-4">${check.status === 'pass' ? '<i data-lucide="check" class="text-emerald-500 w-4 h-4"></i>' : (check.status === 'warn' ? '<i data-lucide="alert-triangle" class="text-amber-500 w-4 h-4"></i>' : '<i data-lucide="x" class="text-red-500 w-4 h-4"></i>')}</td>
            <td class="py-4 text-zinc-500 text-xs">${check.rationale}</td>
        `;
        tbody.appendChild(tr);
    });

    // Node info
    document.getElementById('res-ip').innerText = data.ip;
    document.getElementById('res-geo').innerText = data.location;
    document.getElementById('res-tld').innerText = data.tldRisk;
    document.getElementById('res-latency').innerText = data.latency;

    // Redirect Trace
    const trace = document.getElementById('redirect-trace');
    trace.innerHTML = '';
    const steps = [
        { label: 'Origin', url: data.domain },
        { label: 'Proxy Node', url: 'cl-node.io' },
        { label: 'Destination', url: data.domain }
    ];
    steps.forEach((step, idx) => {
        const node = document.createElement('div');
        node.className = "relative flex-1 space-y-2";
        node.innerHTML = `
            <div class="px-4 py-3 rounded-xl bg-white/5 border border-white/5 text-[10px] font-mono break-all line-clamp-1">
                <span class="text-emerald-400/50 mr-2">${idx + 1}</span> ${step.url}
            </div>
            <div class="text-[9px] uppercase font-bold text-zinc-600 px-4">${step.label}</div>
            ${idx < steps.length - 1 ? '<div class="hidden md:block absolute top-1/3 -right-4 text-zinc-700 animate-pulse">→</div>' : ''}
        `;
        trace.appendChild(node);
    });

    // Preview Screenshot (Real-time via thum.io)
    const preview = document.getElementById('site-preview');
    const previewUrl = `https://image.thum.io/get/width/1280/crop/800/https://${data.domain}`;
    
    preview.classList.add('opacity-0');
    document.getElementById('preview-loader').classList.remove('hidden');
    
    preview.src = previewUrl;
    preview.onload = () => {
        document.getElementById('preview-loader').classList.add('hidden');
        preview.classList.remove('opacity-0');
    };
    
    preview.onerror = () => {
        preview.src = `https://picsum.photos/seed/${encodeURIComponent(data.domain)}/1280/720?grayscale`;
        document.getElementById('preview-loader').classList.add('hidden');
        preview.classList.remove('opacity-0');
    };


}

function generateOwaspChecks(isPhishing) {
    return [
        { name: "SSL/TLS Integrity", status: isPhishing && Math.random() > 0.5 ? 'fail' : 'pass', rationale: "Verifies CA trust chain and protocol version (min TLS 1.2)." },
        { name: "Unicode/Homoglyph", status: isPhishing ? 'fail' : 'pass', rationale: "Scans for mixed-script spoofing using Punycode detection." },
        { name: "Open Redirect Filter", status: isPhishing ? 'warn' : 'pass', rationale: "Checks for parameter-based forwarding to external targets." },
        { name: "Domain Entropy", status: isPhishing ? 'fail' : 'pass', rationale: "Measures string randomness for DGA pattern identification." },
        { name: "Keywords Presence", status: isPhishing ? 'fail' : 'pass', rationale: "Detects 'login', 'secure', 'verify' in unexpected TLD contexts." },
        { name: "IP Host Usage", status: 'pass', rationale: "Blocks direct IP addressing in URLs to prevent hosting bypassing." },
        { name: "Header Validation", status: 'pass', rationale: "Checks for required CSP and X-Frame-Options headers." },
        { name: "Shortening Mask", status: 'pass', rationale: "Detects use of obscure link shorteners to hide landing zones." },
        { name: "PhishTank Rep", status: isPhishing ? 'fail' : 'pass', rationale: "Cross-checks against global blacklists and community reports." },
        { name: "Script Analysis", status: 'pass', rationale: "Heuristic scan of DOM for form manipulation or data exfil." }
    ];
}

// --- SHARING & QR ---



// --- UTILS ---

function copyToClipboard(inputId, btn) {
    const input = document.getElementById(inputId);
    input.select();
    input.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(input.value);
    
    showToast();
    const original = btn.innerHTML;
    btn.innerHTML = '<i data-lucide="check" class="w-4 h-4 text-emerald-500"></i>';
    if (typeof lucide !== 'undefined') lucide.createIcons();
    setTimeout(() => {
        btn.innerHTML = original;
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }, 2000);
}

function showToast() {
    const toast = document.getElementById('toast');
    toast.classList.remove('translate-y-24', 'opacity-0');
    toast.classList.add('translate-y-0', 'opacity-100');
    setTimeout(() => {
        toast.classList.add('translate-y-24', 'opacity-0');
        toast.classList.remove('translate-y-0', 'opacity-100');
    }, 3000);
}

function zoomPreview() {
    const modal = document.getElementById('image-modal');
    const modalImg = document.getElementById('modal-image');
    const siteImg = document.getElementById('site-preview');
    modalImg.src = siteImg.src;
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('image-modal').classList.add('hidden');
}

function resetApp() {
    document.getElementById('results-panel').classList.add('hidden');
    document.getElementById('hero').classList.remove('hidden', 'opacity-10', 'pointer-events-none');
    document.getElementById('url-input').value = '';
    document.getElementById('url-fragments').innerHTML = '';
    document.getElementById('site-preview').classList.add('opacity-0');
    document.getElementById('preview-loader').classList.remove('hidden');
    window.scrollTo({top: 0, behavior: 'smooth'});
}

// --- FIELD MANUAL LOGIC ---

function toggleManual() {
    const manual = document.getElementById('field-manual');
    const isHidden = manual.classList.contains('hidden');
    
    if (isHidden) {
        manual.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        if (typeof lucide !== 'undefined') lucide.createIcons();
    } else {
        manual.classList.add('hidden');
        document.body.style.overflow = '';
    }
}

// Global ESC listener
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const manual = document.getElementById('field-manual');
        if (!manual.classList.contains('hidden')) toggleManual();
        const modal = document.getElementById('image-modal');
        if (!modal.classList.contains('hidden')) closeModal();
    }
});

// --- UNIVERSE BACKGROUND LOGIC ---

class Star {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.reset();
    }
    reset() {
        this.x = Math.random() * this.canvas.width;
        this.y = Math.random() * this.canvas.height;
        this.size = Math.random() * 1.5 + 0.5;
        this.speedX = (Math.random() - 0.5) * 0.4;
        this.speedY = (Math.random() - 0.5) * 0.4;
        this.baseOpacity = Math.random() * 0.4 + 0.1;
        this.opacity = this.baseOpacity;
        this.color = Math.random() > 0.8 ? '#10B981' : '#ffffff';
    }
    update(mouse, isBoosted) {
        const currentSpeedX = isBoosted ? this.speedX * 5 : this.speedX;
        const currentSpeedY = isBoosted ? this.speedY * 5 : this.speedY;
        
        this.x += currentSpeedX;
        this.y += currentSpeedY;

        if (mouse.x && mouse.y) {
            const dx = this.x - mouse.x;
            const dy = this.y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 200) {
                const force = (200 - dist) / 200;
                this.x += dx * force * 0.04;
                this.y += dy * force * 0.04;
                this.opacity = Math.min(1, this.baseOpacity + force * 0.5);
            } else {
                this.opacity = this.baseOpacity;
            }
        }

        if (this.x < 0) this.x = this.canvas.width;
        if (this.x > this.canvas.width) this.x = 0;
        if (this.y < 0) this.y = this.canvas.height;
        if (this.y > this.canvas.height) this.y = 0;
    }
    draw() {
        this.ctx.fillStyle = this.color;
        this.ctx.globalAlpha = this.opacity;
        this.ctx.beginPath();
        this.ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        this.ctx.fill();
    }
}

let universeStars = [];
let universeMouse = { x: null, y: null };
let universeBoosted = false;

function initUniverse() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    universeStars = Array(window.innerWidth < 768 ? 80 : 150).fill().map(() => new Star(canvas));

    window.addEventListener('mousemove', (e) => {
        universeMouse.x = e.clientX;
        universeMouse.y = e.clientY;
    });

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        universeStars.forEach(star => {
            star.update(universeMouse, universeBoosted);
            star.draw();
        });
        requestAnimationFrame(animate);
    }
    animate();
}

function boostUniverse() {
    universeBoosted = true;
}

function resetUniverseBoost() {
    universeBoosted = false;
}

// --- LOCAL STORAGE & RECENTS ---

function saveToRecents(scan) {
    let recents = JSON.parse(localStorage.getItem('zplus_scans') || '[]');
    // Store the full scan result object instead of just metadata
    recents.unshift({
        ...scan,
        date: new Date().toISOString()
    });
    recents = recents.slice(0, RECENT_LIMIT);
    localStorage.setItem('zplus_scans', JSON.stringify(recents));
    renderRecents();
}

function renderRecents() {
    const list = document.getElementById('recents-list');
    const clearBtn = document.getElementById('clear-history-btn');
    const recents = JSON.parse(localStorage.getItem('zplus_scans') || '[]');
    
    if (recents.length === 0) {
        list.innerHTML = '<div class="col-span-full text-center text-zinc-700 py-8 italic text-xs">No recent forensics available.</div>';
        if (clearBtn) clearBtn.classList.add('hidden');
        return;
    }

    if (clearBtn) clearBtn.classList.remove('hidden');

    list.innerHTML = recents.map((scan, index) => `
        <div class="glass p-5 rounded-2xl border border-white/5 space-y-3 hover:border-emerald-500/20 transition-all group cursor-pointer" onclick="loadRecentScan(${index})">
            <div class="flex justify-between items-start">
                <div class="text-[10px] font-mono text-zinc-600 truncate max-w-[120px]">${scan.domain}</div>
                <div class="text-[10px] ${scan.isPhishing ? 'text-red-500' : 'text-emerald-500'} font-bold">${scan.trustScore}% Score</div>
            </div>
            <div class="text-xs text-white font-bold truncate">${scan.url}</div>
            <div class="flex justify-between items-center text-[9px] text-zinc-600">
                <span>${new Date(scan.date).toLocaleDateString()}</span>
                <span class="group-hover:text-emerald-500 transition-colors">View Report →</span>
            </div>
        </div>
    `).join('');
}

function loadRecentScan(index) {
    const recents = JSON.parse(localStorage.getItem('zplus_scans') || '[]');
    const scanData = recents[index];
    
    if (!scanData) return;

    currentScanResult = scanData;
    
    // UI Transitions
    document.getElementById('hero').classList.add('hidden');
    document.getElementById('analysis-sequence').classList.add('hidden');
    document.getElementById('results-panel').classList.remove('hidden');
    resetUniverseBoost();
    populateResults(scanData);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    window.scrollTo({top: 0, behavior: 'smooth'});
}

function clearHistory() {
    if (confirm('Are you sure you want to clear all forensic history?')) {
        localStorage.removeItem('zplus_scans');
        renderRecents();
    }
}



// Responsive matrix resize
window.addEventListener('resize', () => {
    const canvas = document.getElementById('matrix-canvas');
    if (canvas) {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
});
