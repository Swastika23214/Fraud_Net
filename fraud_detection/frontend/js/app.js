const API = 'http://localhost:8080/api';

function animateCount(el, target, duration = 800) {
    const start = performance.now();
    const from = 0;
    function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(from + (target - from) * ease);
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = target;
    }
    requestAnimationFrame(step);
}

async function loadSummary() {
    try {
        const res  = await fetch(`${API}/summary`);
        const data = await res.json();

        const total      = data.total_records      || 0;
        const blacklist  = data.blacklist_hits      || 0;
        const suspicious = data.suspicious_callers  || 0;
        const rings      = data.fraud_rings         || 0;

        animateCount(document.getElementById('stat-total'),      total);
        animateCount(document.getElementById('stat-blacklist'),  blacklist);
        animateCount(document.getElementById('stat-suspicious'), suspicious);
        animateCount(document.getElementById('stat-rings'),      rings);

        setTimeout(() => {
            document.getElementById('bar-blacklist').style.width  = total ? Math.min((blacklist  / total) * 100 * 10, 100) + '%' : '0%';
            document.getElementById('bar-suspicious').style.width = total ? Math.min((suspicious / total) * 100 * 20, 100) + '%' : '0%';
            document.getElementById('bar-rings').style.width      = rings  ? Math.min(rings * 25, 100) + '%' : '0%';
        }, 200);

        document.getElementById('status-text').textContent = 'LIVE';
        document.getElementById('last-updated').textContent =
            'Last run: ' + new Date().toLocaleTimeString();

    } catch (e) {
        document.getElementById('status-text').textContent = 'SERVER OFFLINE';
        document.querySelector('.pulse-dot').style.background = '#ff4560';
        showOfflineMessage();
    }
}

async function loadSuspicious() {
    const tbody = document.getElementById('suspicious-tbody');
    try {
        const res   = await fetch(`${API}/suspicious`);
        const data  = await res.json();

        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No suspicious callers detected</td></tr>';
            return;
        }

        tbody.innerHTML = data.map((c, i) => {
            const scoreClass = c.score >= 100 ? 'score-high' : c.score >= 50 ? 'score-mid' : 'score-low';
            const violations = c.violations
                ? c.violations.split(',').map(v =>
                    `<span class="violation-badge">${v.trim()}</span>`).join('')
                : '';
            const avgDur = typeof c.avg_duration === 'number'
                ? c.avg_duration.toFixed(1) + 's'
                : c.avg_duration + 's';

            return `<tr style="animation: fadeInRow 0.3s ease ${i * 0.05}s both">
                <td>${i + 1}</td>
                <td><span class="caller-id">${c.caller_id}</span></td>
                <td><span class="${scoreClass}">${c.score}</span></td>
                <td>${c.total_calls}</td>
                <td>${avgDur}</td>
                <td>${c.unique_receivers}</td>
                <td>${violations}</td>
            </tr>`;
        }).join('');

    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Failed to load — is the server running?</td></tr>';
    }
}

async function loadFraudRings() {
    const container = document.getElementById('rings-container');
    try {
        const res  = await fetch(`${API}/fraud-rings`);
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = '<div class="loading-cell">No fraud rings detected</div>';
            return;
        }

        container.innerHTML = data.map((ring, i) => {
            const membersHtml = ring.members
                .split(' -> ')
                .map(m => m.trim())
                .map((part, idx, arr) => {
                    const isNum = /^\d{10}$/.test(part);
                    if (isNum) return `<span class="number">${part}</span>`;
                    return part;
                })
                .join('<span class="arrow">→</span>');

            return `<div class="ring-card" style="animation-delay: ${i * 0.08}s">
                <div class="ring-id">RING #${ring.ring_id}</div>
                <div class="ring-members">${membersHtml}</div>
                <div class="ring-size">${ring.size} members</div>
            </div>`;
        }).join('');

    } catch (e) {
        container.innerHTML = '<div class="loading-cell">Failed to load fraud rings</div>';
    }
}

async function loadCDRSample() {
    const tbody = document.getElementById('cdr-tbody');
    try {
        const res  = await fetch(`${API}/cdr-sample`);
        const data = await res.json();

        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">No records found</td></tr>';
            return;
        }

        tbody.innerHTML = data.map((r, i) => `
            <tr style="animation: fadeInRow 0.3s ease ${i * 0.03}s both">
                <td><span class="caller-id">${r.caller_id}</span></td>
                <td style="color:var(--text)">${r.receiver_id}</td>
                <td style="font-family:var(--font-mono);color:${r.duration < 10 ? 'var(--red)' : 'var(--text2)'}">${r.duration}s</td>
                <td style="font-family:var(--font-mono);font-size:0.75rem">${r.timestamp}</td>
            </tr>`
        ).join('');

    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">Failed to load</td></tr>';
    }
}

function showOfflineMessage() {
    const msg = `
        <div style="text-align:center;padding:3rem;font-family:var(--font-mono);color:var(--text3)">
            <div style="font-size:2rem;margin-bottom:1rem;color:var(--red)">⚠</div>
            <div style="font-size:0.8rem;letter-spacing:0.1em;margin-bottom:0.5rem">SERVER NOT RUNNING</div>
            <div style="font-size:0.7rem;color:var(--text3);max-width:400px;margin:0 auto;line-height:1.8">
                Start the C++ server first:<br>
                <code style="color:var(--accent)">./fraud_detector</code><br>
                then refresh this page.
            </div>
        </div>`;

    document.getElementById('suspicious-tbody').innerHTML =
        `<tr><td colspan="7">${msg}</td></tr>`;
    document.getElementById('rings-container').innerHTML = msg;
    document.getElementById('cdr-tbody').innerHTML =
        `<tr><td colspan="4">${msg}</td></tr>`;
}

const style = document.createElement('style');
style.textContent = `
@keyframes fadeInRow {
    from { opacity: 0; transform: translateY(4px); }
    to   { opacity: 1; transform: translateY(0); }
}`;
document.head.appendChild(style);

async function lookupNumber() {
    const input  = document.getElementById('search-input');
    const btn    = document.getElementById('search-btn');
    const result = document.getElementById('search-result');
    const number = input.value.trim();

    if (number.length !== 10) {
        input.style.borderColor = 'var(--red)';
        setTimeout(() => input.style.borderColor = '', 1000);
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Checking...';
    result.style.display = 'none';

    try {
        const res  = await fetch(`${API}/lookup?number=${number}`);
        const data = await res.json();

        if (data.error) {
            result.innerHTML = `<div class="sr-header suspicious"><span>${data.error}</span></div>`;
            result.style.display = 'block';
            return;
        }

        const v      = data.verdict.toLowerCase().replace('_', '-');
        const vColor = v === 'dangerous' ? 'red' : v === 'suspicious' ? 'amber' : v === 'not-found' ? 'dim' : 'green';
        const icon   = v === 'dangerous' ? '✕' : v === 'suspicious' ? '!' : v === 'not-found' ? '?' : '✓';

        const yesRed   = `<span class="sr-val red">YES</span>`;
        const noGreen  = `<span class="sr-val green">No</span>`;
        const na       = `<span class="sr-val" style="color:var(--text3)">—</span>`;

        const ringHtml = data.in_fraud_ring
            ? `<div class="sr-ring">Ring #${data.ring_id}: ${data.ring_members}</div>`
            : '';

        const violHtml = data.violations
            ? `<span class="sr-val ${vColor}">${data.violations}</span>`
            : na;

        result.innerHTML = `
            <div class="sr-header ${v}">
                <span class="sr-verdict ${v}">${icon} ${data.verdict}</span>
                <span style="color:var(--text3);font-family:var(--font-mono);font-size:.7rem">${data.number}</span>
            </div>
            <div class="sr-body">
                <div class="sr-row">
                    <span class="sr-key">Blacklisted</span>
                    ${data.is_blacklisted ? yesRed : noGreen}
                </div>
                <div class="sr-row">
                    <span class="sr-key">Prefix match</span>
                    ${data.prefix_match ? `<span class="sr-val amber">${data.prefix_match}</span>` : noGreen}
                </div>
                <div class="sr-row">
                    <span class="sr-key">Suspicion score</span>
                    ${data.suspicion_score > 0 ? `<span class="sr-val red">${data.suspicion_score}</span>` : na}
                </div>
                <div class="sr-row">
                    <span class="sr-key">Total calls</span>
                    ${data.total_calls > 0 ? `<span class="sr-val">${data.total_calls}</span>` : na}
                </div>
                <div class="sr-row">
                    <span class="sr-key">Avg duration</span>
                    ${data.avg_duration > 0 ? `<span class="sr-val">${data.avg_duration.toFixed(1)}s</span>` : na}
                </div>
                <div class="sr-row">
                    <span class="sr-key">Unique receivers</span>
                    ${data.unique_receivers > 0 ? `<span class="sr-val">${data.unique_receivers}</span>` : na}
                </div>
                <div class="sr-row" style="grid-column:1/-1">
                    <span class="sr-key">Rule violations</span>
                    ${violHtml}
                </div>
                <div class="sr-row" style="grid-column:1/-1">
                    <span class="sr-key">In fraud ring</span>
                    ${data.in_fraud_ring ? `<span class="sr-val amber">YES — Ring #${data.ring_id}</span>` : noGreen}
                </div>
                ${ringHtml}
            </div>`;
        result.style.display = 'block';

    } catch (e) {
        result.innerHTML = `<div class="sr-header suspicious"><span style="color:var(--text2)">Server offline — start ./fraud_detector first</span></div>`;
        result.style.display = 'block';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Check number';
    }
}

document.getElementById('search-input')
    .addEventListener('keydown', e => { if (e.key === 'Enter') lookupNumber(); });


(async function init() {
    await loadSummary();
    await Promise.all([
        loadSuspicious(),
        loadFraudRings(),
        loadCDRSample()
    ]);
})();