/* OSINT Threat Intelligence Platform v3 - Clean Professional UI */

let DATA = { emails: [], stats: {} };
let filtered = [];
let page = 1;
const perPage = 20;
let currentFilter = 'all';
let searchQuery = '';
let currentView = 'dashboard';
let selectedActor = null;

// Helper: Convert virustotal/blacklist object to array
// Returns domains with actual malicious/suspicious detections
function getVTArray(p) {
    if (!p.virustotal) return [];
    if (Array.isArray(p.virustotal)) return p.virustotal.filter(v => v.malicious > 0 || v.suspicious > 0);
    return Object.entries(p.virustotal)
        .filter(([_, v]) => v && v.found && (v.malicious > 0 || v.suspicious > 0))
        .map(([domain, data]) => ({ domain, ...data }));
}

// Helper: Get total threat domains (blacklisted + VT malicious)
function getThreatCount(p) {
    const blCount = getBLArray(p).filter(b => b.blacklisted).length;
    const vtCount = getVTArray(p).length;
    // Avoid double counting - get unique domains
    const blDomains = new Set(getBLArray(p).filter(b => b.blacklisted).map(b => b.domain));
    const vtDomains = new Set(getVTArray(p).map(v => v.domain));
    const allThreats = new Set([...blDomains, ...vtDomains]);
    return allThreats.size;
}

function getBLArray(p) {
    if (!p.blacklist) return [];
    if (Array.isArray(p.blacklist)) return p.blacklist;
    return Object.entries(p.blacklist)
        .filter(([_, v]) => v && (v.blacklisted || v.brand_impersonation?.length))
        .map(([domain, data]) => ({ domain, ...data }));
}

// Helper: Get all brand impersonations from blacklist
function getBrandArray(p) {
    const brands = new Set();
    if (!p.blacklist) return [];
    const entries = Array.isArray(p.blacklist) ? p.blacklist :
        Object.entries(p.blacklist).map(([domain, data]) => ({ domain, ...data }));
    entries.forEach(bl => {
        (bl.brand_impersonation || []).forEach(b => brands.add(b));
    });
    return [...brands];
}

// Helper: Check if actor has any leak data
function hasLeakData(p) {
    return (p.passwords?.length > 0) ||
           (p.leak_info?.num_results > 0) ||
           (p.leak_extended?.databases?.length > 0) ||
           (p.stats?.leak_count > 0) ||
           (p.leaks?.length > 0 && p.leaks.some(l => l.source));
}

// Helper: Get leak count for actor
function getLeakCount(p) {
    let count = 0;
    count += p.passwords?.length || 0;
    count += p.leak_info?.num_results || 0;
    count += p.leak_extended?.databases?.length || 0;
    return count;
}

// Helper: Get total passwords count
function getPasswordCount(p) {
    return p.passwords?.length || 0;
}

// Helper: Get all screenshots from multiple sources
function getActorScreenshots(p) {
    const screenshots = [];
    const seen = new Set();

    // From domain_cards
    (p.domain_cards || []).forEach(d => {
        if (d.screenshot && !seen.has(d.screenshot)) {
            seen.add(d.screenshot);
            screenshots.push(d);
        }
    });

    // From urlscan
    if (p.urlscan && typeof p.urlscan === 'object') {
        Object.entries(p.urlscan).forEach(([domain, data]) => {
            if (data.screenshot && !seen.has(data.screenshot)) {
                seen.add(data.screenshot);
                screenshots.push({ domain, screenshot: data.screenshot, ...data });
            }
        });
    }

    return screenshots;
}

// Icons
const ICONS = {
    malware: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`,
    phishing: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    domain: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    email: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>`,
    phone: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>`,
    user: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    key: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
    leak: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22a7 7 0 0 0 7-7c0-2-1-3.9-3-5.5s-3.5-4-4-6.5c-.5 2.5-2 4.9-4 6.5C6 11.1 5 13 5 15a7 7 0 0 0 7 7z"/></svg>`,
    ip: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
    brand: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>`,
    crypto: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    android: `<svg class="icon" viewBox="0 0 24 24" fill="#3DDC84"><path d="M17.532 15.106a1.003 1.003 0 1 1-.001-2.007 1.003 1.003 0 0 1 .001 2.007zm-11.063 0a1.003 1.003 0 1 1-.001-2.007 1.003 1.003 0 0 1 .001 2.007zm11.371-4.453l1.977-3.424a.416.416 0 0 0-.152-.567.416.416 0 0 0-.567.152l-2.003 3.469a12.013 12.013 0 0 0-5.09-1.123c-1.857 0-3.596.4-5.09 1.123L4.91 6.814a.416.416 0 0 0-.567-.152.416.416 0 0 0-.152.567l1.977 3.424A11.51 11.51 0 0 0 .5 18.094h23C23.5 14.848 21.107 12.063 17.84 10.653z"/></svg>`,
    metamask: `<svg class="icon" viewBox="0 0 24 24"><path fill="#E2761B" d="M21.87 3.34L13.5 9.54l1.54-3.64 6.83-2.56z"/><path fill="#E4761B" d="M2.13 3.34l8.29 6.28-1.46-3.72-6.83-2.56z"/><path fill="#E4761B" d="M18.71 16.87l-2.23 3.42 4.77 1.31 1.37-4.64-3.91-.09z"/><path fill="#E4761B" d="M1.39 17l1.36 4.64 4.77-1.31-2.23-3.42L1.39 17z"/></svg>`,
    virustotal: `<svg class="icon" viewBox="0 0 24 24"><path fill="#394EFF" d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`,
    seal: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
    screenshot: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
    link: `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
    external: `<svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
    google: `<svg class="icon" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>`,
};

document.addEventListener('DOMContentLoaded', init);

async function init() {
    setupNav();
    setupSearch();
    await loadData();
}

function setupNav() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => switchView(item.dataset.view));
    });
}

function setupSearch() {
    const input = document.getElementById('search-input');
    if (!input) return;

    // Create autocomplete dropdown
    let dropdown = document.createElement('div');
    dropdown.className = 'search-dropdown';
    dropdown.id = 'search-dropdown';
    input.parentElement.appendChild(dropdown);

    // Build search index
    let searchIndex = [];
    const buildIndex = () => {
        searchIndex = [];
        DATA.emails.forEach(p => {
            // Add email
            searchIndex.push({ type: 'email', value: p.email, actor: p });
            // Add domains
            (p.domains || []).forEach(d => {
                searchIndex.push({ type: 'domain', value: d, actor: p });
            });
            // Add names
            (p.leak_intel?.real_names || []).forEach(n => {
                searchIndex.push({ type: 'name', value: n, actor: p });
            });
            // Add phones
            (p.leak_intel?.phones || []).map(ph => ph.phone || ph).forEach(ph => {
                searchIndex.push({ type: 'phone', value: ph, actor: p });
            });
        });
    };

    // Show suggestions
    const showSuggestions = (query) => {
        if (!query || query.length < 2) {
            dropdown.innerHTML = '';
            dropdown.classList.remove('active');
            return;
        }

        const q = query.toLowerCase();
        const matches = searchIndex
            .filter(item => item.value.toLowerCase().includes(q))
            .slice(0, 15);

        if (!matches.length) {
            dropdown.innerHTML = '<div class="search-no-results">No results found</div>';
            dropdown.classList.add('active');
            return;
        }

        // Group by type
        const groups = { email: [], domain: [], name: [], phone: [] };
        matches.forEach(m => groups[m.type]?.push(m));

        let html = '';
        const typeLabels = { email: '📧 Emails', domain: '🌐 Domains', name: '👤 Names', phone: '📞 Phones' };

        Object.entries(groups).forEach(([type, items]) => {
            if (!items.length) return;
            html += `<div class="search-group-label">${typeLabels[type]}</div>`;
            items.slice(0, 5).forEach(item => {
                const highlighted = item.value.replace(new RegExp(`(${q})`, 'gi'), '<mark>$1</mark>');
                html += `<div class="search-item" data-email="${esc(item.actor.email)}">
                    <span class="search-value">${highlighted}</span>
                    <span class="search-actor">${esc(item.actor.email)}</span>
                </div>`;
            });
        });

        dropdown.innerHTML = html;
        dropdown.classList.add('active');

        // Click handlers
        dropdown.querySelectorAll('.search-item').forEach(el => {
            el.addEventListener('click', () => {
                const email = el.dataset.email;
                input.value = email;
                searchQuery = email.toLowerCase();
                dropdown.classList.remove('active');
                page = 1;
                applyFilters();
                // Also open profile
                openProfile(email);
            });
        });
    };

    // Event handlers
    input.addEventListener('input', debounce(e => {
        const value = e.target.value.trim();
        if (DATA.emails.length && !searchIndex.length) buildIndex();
        showSuggestions(value);
        searchQuery = value.toLowerCase();
        page = 1;
        applyFilters();
    }, 200));

    input.addEventListener('focus', () => {
        if (input.value.length >= 2) showSuggestions(input.value);
    });

    input.addEventListener('blur', () => {
        setTimeout(() => dropdown.classList.remove('active'), 200);
    });

    // Keyboard navigation
    input.addEventListener('keydown', e => {
        if (e.key === 'Escape') dropdown.classList.remove('active');
    });

    // Build index after data loads
    const originalLoad = loadData;
    window.loadDataWithIndex = async () => {
        await originalLoad();
        buildIndex();
    };

    document.querySelectorAll('.chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentFilter = chip.dataset.filter;
            page = 1;
            applyFilters();
        });
    });
}

function switchView(view) {
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const viewEl = document.getElementById(`${view}-view`);
    if (viewEl) {
        viewEl.classList.add('active');
        // Add animation class
        viewEl.style.animation = 'none';
        viewEl.offsetHeight; // Trigger reflow
        viewEl.style.animation = 'fadeInUp 0.4s var(--ease-out)';
    }

    // Always ensure filtered is populated
    if (!filtered.length && DATA.emails?.length) {
        filtered = [...DATA.emails];
    }

    if (view === 'dashboard') renderDashboard();
    else if (view === 'actors') { page = 1; renderActors(); }
    else if (view === 'threats') renderThreats();
    else if (view === 'graph') renderGraph();
}
window.switchView = switchView;

async function loadData() {
    try {
        // Load main data and registrants in parallel
        const [dataRes, regRes] = await Promise.all([
            fetch('data/data.json'),
            fetch('data/registrants.json').catch(() => null)
        ]);

        DATA = await dataRes.json();

        // Load registrants if available
        if (regRes && regRes.ok) {
            try {
                const registrants = await regRes.json();
                // Group registrants by actor email
                const regByActor = {};
                registrants.forEach(r => {
                    if (!regByActor[r.actor]) regByActor[r.actor] = [];
                    regByActor[r.actor].push(r);
                });
                // Attach registrants to actors
                DATA.emails.forEach(p => {
                    if (regByActor[p.email]) {
                        p.registrants = regByActor[p.email];
                    }
                });
                DATA.registrants = registrants;
            } catch (e) {
                console.warn('Could not parse registrants:', e);
            }
        }

        // Score actors
        DATA.emails.forEach(p => {
            p.threat_score = calcThreatScore(p);
            p.intel_score = calcIntelScore(p);
        });

        updateStats();
        applyFilters();
        renderDashboard();
    } catch (err) {
        console.error('Load error:', err);
    }
}

function calcThreatScore(p) {
    let s = 0;
    s += getVTArray(p).length * 100;
    s += getBLArray(p).length * 80;
    s += getBrandArray(p).length * 50;
    s += (p.crypto_indicators?.length || 0) * 30;
    return s;
}

function calcIntelScore(p) {
    let s = 0;
    // Google account info
    if (p.google?.person_id) s += 50;
    if (p.google?.photo) s += 30;
    if (p.google?.name) s += 20;
    // Leak intel data
    s += (p.leak_intel?.real_names?.length || 0) * 40;
    s += (p.leak_intel?.phones?.length || 0) * 35;
    s += (p.leak_intel?.ips?.length || 0) * 25;
    // Leak info (from breach data)
    if (p.leak_info?.fullname) s += 40;
    if (p.leak_info?.phone) s += 35;
    if (p.leak_info?.nickname) s += 15;
    s += (p.leak_info?.num_results || 0) * 10;
    // Passwords and contacts
    s += (p.passwords?.length || 0) * 25;
    s += (p.contacts?.length || 0) * 15;
    s += (p.leak_extended?.databases?.length || 0) * 30;
    // WHOIS records with real names
    s += (p.whois_records?.filter(w => w.name && !w.name.includes('REDACTED') && !w.name.includes('???')).length || 0) * 20;
    return s;
}

function updateStats() {
    const s = DATA.stats || {};
    // Calculate counts from actual data
    let brandCount = 0;
    let actorsWithLeaks = 0;
    let totalPasswords = 0;
    let phishingDomains = 0;  // From blacklist
    let malwareDomains = 0;   // From VT with detections OR blacklisted domains
    let totalDomains = 0;     // All registered domains
    let registrarsSet = new Set();

    (DATA.emails || []).forEach(p => {
        brandCount += getBrandArray(p).length;
        if (hasLeakData(p)) actorsWithLeaks++;
        totalPasswords += getPasswordCount(p);
        // Phishing = blacklisted domains
        phishingDomains += getBLArray(p).filter(b => b.blacklisted).length;
        // Malware = VT detections OR total unique threat domains
        malwareDomains += getThreatCount(p);
        // Total domains
        totalDomains += p.total_domains || p.domains?.length || 0;
        // Count registrars
        (p.registrars || []).forEach(r => {
            const name = typeof r === 'object' ? r.name : r;
            if (name && name !== '????????????' && !name.includes('REDACTED')) {
                registrarsSet.add(name);
            }
        });
        (p.whois_records || []).forEach(w => {
            if (w.registrar && w.registrar !== '????????????' && !w.registrar.includes('REDACTED')) {
                registrarsSet.add(w.registrar);
            }
        });
    });

    // Use bigger numbers - count domains not actors for threats
    animateNumber('stat-actors', DATA.emails?.length || s.total_emails);
    animateNumber('stat-domains', totalDomains || s.total_domains);
    animateNumber('stat-threats', malwareDomains); // Total unique threat domains
    animateNumber('stat-registrars', registrarsSet.size);
    animateNumber('pill-phishing', phishingDomains || s.blacklisted || 0);
    animateNumber('pill-malware', malwareDomains || phishingDomains || s.malicious_domains || 0);
    animateNumber('pill-brand', brandCount);
    animateNumber('pill-leaks', actorsWithLeaks + totalPasswords); // Combined metric
}

// Animate number counting up
function animateNumber(id, target) {
    const el = document.getElementById(id);
    if (!el) return;

    const duration = 1000;
    const start = parseInt(el.textContent.replace(/,/g, '')) || 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * easeOut);

        el.textContent = fmt(current);

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function applyFilters() {
    let results = [...(DATA.emails || [])];

    if (searchQuery) {
        results = results.filter(p => {
            const text = [
                p.email,
                ...(p.domains || []),
                ...(p.leak_intel?.real_names || []),
                ...(p.leak_intel?.phones?.map(ph => ph.phone) || []),
                ...(p.contacts?.map(c => c.name) || [])
            ].join(' ').toLowerCase();
            return text.includes(searchQuery);
        });
    }

    if (currentFilter !== 'all') {
        results = results.filter(p => {
            switch(currentFilter) {
                case 'phishing': return getBLArray(p).length > 0;
                case 'malware': return getVTArray(p).length > 0;
                case 'brand': return getBrandArray(p).length > 0;
                case 'leaks': return hasLeakData(p);
                default: return true;
            }
        });
    }

    // Sort by threat + intel score
    results.sort((a, b) => (b.threat_score + b.intel_score) - (a.threat_score + a.intel_score));
    filtered = results;

    if (currentView === 'actors') renderActors();
    else if (currentView === 'threats') renderThreats();
}

// High-priority brands for crypto/finance phishing
const HIGH_VALUE_BRANDS = ['metamask', 'ledger', 'trezor', 'coinbase', 'binance', 'phantom', 'trustwallet', 'exodus', 'paypal', 'chase', 'bank'];

function hasCryptoBrand(p) {
    const brands = getBrandArray(p).map(b => b.toLowerCase());
    return brands.some(b => HIGH_VALUE_BRANDS.some(hv => b.includes(hv)));
}

// ==================== DASHBOARD ====================
function renderDashboard() {
    const s = DATA.stats || {};

    // Calculate counts from actual data - count DOMAINS not actors for bigger numbers
    let brandCount = 0;
    let actorsWithLeaks = 0;
    let totalPasswords = 0;
    let phishingDomains = 0;  // Blacklisted domains
    let malwareDomains = 0;   // VT detected
    let totalDomains = 0;     // All registered domains
    let registrarsSet = new Set();

    (DATA.emails || []).forEach(p => {
        brandCount += getBrandArray(p).length;
        if (hasLeakData(p)) actorsWithLeaks++;
        totalPasswords += getPasswordCount(p);
        phishingDomains += getBLArray(p).filter(b => b.blacklisted).length;
        malwareDomains += getThreatCount(p);
        totalDomains += p.total_domains || p.domains?.length || 0;
        // Count registrars - extract name from object or use string directly
        (p.registrars || []).forEach(r => {
            const name = typeof r === 'object' ? r.name : r;
            if (name && name !== '????????????' && !name.includes('REDACTED')) {
                registrarsSet.add(name);
            }
        });
        (p.whois_records || []).forEach(w => {
            if (w.registrar && w.registrar !== '????????????' && !w.registrar.includes('REDACTED')) {
                registrarsSet.add(w.registrar);
            }
        });
    });

    // Animate all dashboard numbers
    animateNumber('dash-actors', DATA.emails?.length || s.total_emails);
    animateNumber('dash-domains', totalDomains || s.total_domains);
    animateNumber('dash-phishing', phishingDomains || s.blacklisted);
    animateNumber('dash-malware', malwareDomains || s.malicious_domains);
    animateNumber('dash-registrars', registrarsSet.size);
    animateNumber('dash-brand', brandCount);
    animateNumber('dash-leaks', actorsWithLeaks + totalPasswords);
    animateNumber('dash-passwords', totalPasswords || s.total_passwords);

    // Critical threats - prioritize crypto/brand phishing, then other threats
    const critical = DATA.emails
        .filter(p => p.threat_score > 0 || getBrandArray(p).length > 0)
        .sort((a, b) => {
            // Prioritize crypto wallet phishing
            const aCrypto = hasCryptoBrand(a) ? 500 : 0;
            const bCrypto = hasCryptoBrand(b) ? 500 : 0;
            // Then by brand count, then by scores
            const aScore = aCrypto + getBrandArray(a).length * 100 + a.threat_score + a.intel_score;
            const bScore = bCrypto + getBrandArray(b).length * 100 + b.threat_score + b.intel_score;
            return bScore - aScore;
        })
        .slice(0, 6);

    const threatContainer = document.getElementById('critical-threats');
    if (threatContainer) {
        threatContainer.innerHTML = critical.length ?
            critical.map(p => renderThreatCard(p)).join('') :
            '<div class="empty-text">No critical threats with identified actors</div>';
    }

    // Top actors with most intel
    const topActors = DATA.emails
        .filter(p => p.intel_score > 50)
        .sort((a, b) => b.intel_score - a.intel_score)
        .slice(0, 6);

    const actorContainer = document.getElementById('top-actors');
    if (actorContainer) {
        actorContainer.innerHTML = topActors.length ?
            topActors.map(p => renderActorPreview(p)).join('') :
            '<div class="empty-text">No identified actors</div>';
    }
}

function renderThreatCard(p) {
    const name = p.leak_intel?.real_names?.[0] || p.google?.name || '';
    const country = getActorCountry(p);
    const vtArr = getVTArray(p);
    const blArr = getBLArray(p);
    const brandArr = getBrandArray(p);
    const isCrypto = hasCryptoBrand(p);
    const threats = [];

    // Show crypto brand first if present
    if (isCrypto) {
        const cryptoBrands = brandArr.filter(b => HIGH_VALUE_BRANDS.some(hv => b.toLowerCase().includes(hv)));
        threats.push(`<span class="threat-tag crypto">\u{1F4B0} ${cryptoBrands.slice(0,2).join(', ')}</span>`);
    }
    if (vtArr.length) threats.push(`<span class="threat-tag malware">${ICONS.malware} ${vtArr.length} Malware</span>`);
    if (blArr.length) threats.push(`<span class="threat-tag phishing">${ICONS.phishing} ${blArr.length} Phishing</span>`);
    if (brandArr.length && !isCrypto) threats.push(`<span class="threat-tag brand">${ICONS.brand} ${brandArr.slice(0,2).join(', ')}</span>`);

    // Find screenshot from domain_cards OR urlscan data
    let screenshot = p.domain_cards?.find(d => d.screenshot)?.screenshot;
    if (!screenshot && p.urlscan) {
        const urlscanScreenshot = Object.values(p.urlscan).find(u => u.screenshot)?.screenshot;
        if (urlscanScreenshot) screenshot = urlscanScreenshot;
    }

    return `
        <div class="threat-card ${isCrypto ? 'crypto-threat' : ''}" onclick="openProfile('${esc(p.email)}')">
            <div class="tc-header">
                <div class="tc-identity">
                    <div class="tc-avatar">${p.google?.photo ? `<img src="${esc(p.google.photo)}">` : getInitial(p.email)}</div>
                    <div class="tc-info">
                        ${name ? `<div class="tc-name">${esc(name)}</div>` : ''}
                        <div class="tc-email">${esc(p.email)}</div>
                        ${country ? `<div class="tc-country">${getFlag(country)} ${country}</div>` : ''}
                    </div>
                </div>
                <div class="tc-score ${isCrypto ? 'crypto' : (p.threat_score > 200 ? 'critical' : 'high')}">${isCrypto ? '\u{1F4B0}' : Math.round((p.threat_score + p.intel_score) / 10)}</div>
            </div>
            <div class="tc-threats">${threats.join('')}</div>
            <div class="tc-evidence">${screenshot ? `<img src="${esc(screenshot)}" loading="lazy" onerror="this.parentElement.innerHTML='<div class=tc-no-screenshot>${ICONS.screenshot}<span>No preview</span></div>'">` : `<div class="tc-no-screenshot">${ICONS.screenshot}<span>No preview</span></div>`}</div>
            <div class="tc-stats">
                <span>${ICONS.domain} ${p.total_domains || 0}</span>
                ${p.leak_intel?.phones?.length ? `<span>${ICONS.phone} ${p.leak_intel.phones.length}</span>` : ''}
                ${p.passwords?.length ? `<span>${ICONS.key} ${p.passwords.length}</span>` : ''}
            </div>
        </div>
    `;
}

function renderActorPreview(p) {
    const name = p.leak_intel?.real_names?.[0] || p.google?.name || '';
    const country = getActorCountry(p);

    return `
        <div class="actor-preview" onclick="openProfile('${esc(p.email)}')">
            <div class="ap-avatar">${p.google?.photo ? `<img src="${esc(p.google.photo)}">` : getInitial(p.email)}</div>
            <div class="ap-info">
                ${name ? `<div class="ap-name">${esc(name)}</div>` : ''}
                <div class="ap-email">${esc(p.email)}</div>
                <div class="ap-meta">
                    ${country ? `<span>${getFlag(country)}</span>` : ''}
                    <span>${p.total_domains || 0} domains</span>
                    ${p.google?.person_id ? `<span class="has-google">${ICONS.google} Google</span>` : ''}
                </div>
            </div>
            <div class="ap-tags">
                ${getVTArray(p).length ? '<span class="tag-danger">MAL</span>' : ''}
                ${getBLArray(p).length ? '<span class="tag-warning">PHISH</span>' : ''}
            </div>
        </div>
    `;
}

// ==================== ACTORS ====================
function renderActors() {
    const container = document.getElementById('actors-container');
    if (!container) return;

    const start = (page - 1) * perPage;
    const pageData = filtered.slice(start, start + perPage);

    if (!pageData.length) {
        container.innerHTML = '<div class="empty-state"><h3>No actors found</h3></div>';
        return;
    }

    container.innerHTML = pageData.map(p => renderActorCard(p)).join('');
    renderPagination();
}

function renderActorCard(p) {
    // Get name from multiple sources
    const name = p.leak_intel?.real_names?.[0] || p.leak_info?.fullname || p.google?.name ||
                 p.contacts?.find(c => c.name && !c.name.includes('REDACTED') && !c.name.includes('???'))?.name || '';
    const country = getActorCountry(p);
    // Get phones from multiple sources
    const phones = dedupePhones([
        ...(p.leak_intel?.phones || []),
        ...(p.leak_info?.phone ? [{ phone: p.leak_info.phone }] : [])
    ]);
    const phone = phones[0] || (p.contacts?.find(c => c.phone && c.phone !== 'REDACTED FOR PRIVACY'));
    const screenshots = getActorScreenshots(p);

    // Threat indicators
    const vtArr = getVTArray(p);
    const blArr = getBLArray(p);
    const brandArr = getBrandArray(p);
    const hasMalware = vtArr.length > 0;
    const hasPhishing = blArr.length > 0;
    const hasBrand = brandArr.length > 0;
    const isCrypto = hasCryptoBrand(p);

    // Calculate threat level
    const threatLevel = hasMalware ? 'critical' : (hasPhishing ? 'high' : (hasBrand ? 'medium' : 'low'));

    // Additional data
    const intelScore = p.intel_score || 0;
    const threatScore = p.threat_score || 0;
    const hasPasswords = p.passwords?.length > 0;
    const topBrand = brandArr[0] || '';

    return `
        <div class="actor-card ${hasMalware ? 'has-malware' : ''} ${hasPhishing ? 'has-phishing' : ''}" onclick="openProfile('${esc(p.email)}')">
            <!-- Header with threat level and score -->
            <div class="ac-header">
                <div class="ac-threat-level ${threatLevel}">
                    <span class="threat-dot"></span>
                    <span>${threatLevel === 'critical' ? 'CRITICAL' : threatLevel === 'high' ? 'HIGH RISK' : threatLevel === 'medium' ? 'MEDIUM' : 'LOW'}</span>
                </div>
                ${threatScore > 0 ? `<div class="ac-score">${threatScore}</div>` : ''}
            </div>

            <!-- Screenshot Gallery -->
            <div class="ac-visual">
                ${screenshots.length ? `
                    <div class="ac-screenshot-main">
                        <img src="${esc(screenshots[0].screenshot)}" loading="lazy" alt="Evidence" onerror="this.closest('.ac-screenshot-main').classList.add('error')">
                        <div class="ac-screenshot-overlay">
                            <div class="ac-screenshot-info">
                                <span class="ac-screenshot-domain">${esc(screenshots[0].domain || 'Unknown domain')}</span>
                                ${screenshots.length > 1 ? `<span class="ac-screenshot-count">📷 ${screenshots.length} screenshots</span>` : ''}
                            </div>
                        </div>
                    </div>
                ` : `
                    <div class="ac-no-screenshot">
                        <div class="ac-no-screenshot-content">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <rect x="3" y="3" width="18" height="18" rx="2"/>
                                <circle cx="8.5" cy="8.5" r="1.5"/>
                                <path d="m21 15-5-5L5 21"/>
                            </svg>
                            <span>No Visual Evidence</span>
                            <small>${p.total_domains || 0} domains registered</small>
                        </div>
                    </div>
                `}
            </div>

            <!-- Identity Section -->
            <div class="ac-identity">
                <div class="ac-avatar-wrapper">
                    <div class="ac-avatar ${p.google?.photo ? 'has-photo' : ''}">
                        ${p.google?.photo ? `<img src="${esc(p.google.photo)}" onerror="this.parentElement.innerHTML='${getInitial(p.email)}'">` : getInitial(p.email)}
                    </div>
                    ${p.google?.person_id ? `<div class="ac-verified" title="Google Account Found">✓</div>` : ''}
                </div>
                <div class="ac-details">
                    ${name ? `<div class="ac-name">${esc(name)}</div>` : ''}
                    <div class="ac-email">${esc(p.email)}</div>
                    <div class="ac-meta">
                        ${country ? `<span class="ac-country">${getFlag(country)} ${country}</span>` : ''}
                        ${phones.length ? `<span class="ac-phone">📱 ${phones.length}</span>` : ''}
                        ${hasAndroid(p) ? `<span class="ac-android" title="Android Device">🤖</span>` : ''}
                    </div>
                </div>
            </div>

            <!-- Threat Indicators -->
            ${(hasMalware || hasPhishing || isCrypto || topBrand || hasPasswords) ? `
                <div class="ac-threats">
                    ${hasMalware ? `<div class="ac-threat-item malware"><span class="ac-threat-icon">☠️</span><span class="ac-threat-label">${vtArr.length} Malware</span></div>` : ''}
                    ${hasPhishing ? `<div class="ac-threat-item phishing"><span class="ac-threat-icon">🎣</span><span class="ac-threat-label">${blArr.length} Phishing</span></div>` : ''}
                    ${isCrypto ? `<div class="ac-threat-item crypto"><span class="ac-threat-icon">💰</span><span class="ac-threat-label">Crypto Scam</span></div>` : ''}
                    ${topBrand && !isCrypto ? `<div class="ac-threat-item brand"><span class="ac-threat-icon">🏷️</span><span class="ac-threat-label">${topBrand}</span></div>` : ''}
                    ${hasPasswords ? `<div class="ac-threat-item leak"><span class="ac-threat-icon">🔑</span><span class="ac-threat-label">${p.passwords.length} Passwords</span></div>` : ''}
                </div>
            ` : ''}

            <!-- Stats Footer -->
            <div class="ac-footer">
                <div class="ac-stat-item">
                    <span class="ac-stat-value">${p.total_domains || 0}</span>
                    <span class="ac-stat-label">Domains</span>
                </div>
                <div class="ac-stat-item ${vtArr.length + blArr.length > 0 ? 'danger' : ''}">
                    <span class="ac-stat-value">${vtArr.length + blArr.length}</span>
                    <span class="ac-stat-label">Threats</span>
                </div>
                <div class="ac-stat-item ${getLeakCount(p) > 0 ? 'warning' : ''}">
                    <span class="ac-stat-value">${getLeakCount(p)}</span>
                    <span class="ac-stat-label">Leaks</span>
                </div>
                <div class="ac-stat-item">
                    <span class="ac-stat-value">${intelScore}</span>
                    <span class="ac-stat-label">Intel</span>
                </div>
            </div>
        </div>
    `;
}

// ==================== THREATS ====================
function renderThreats() {
    const container = document.getElementById('threats-container');
    if (!container) return;

    const threats = [];

    // Collect registrars for filter
    const registrars = new Set();

    // Use filtered list or all emails to collect ALL threats
    const source = filtered.length ? filtered : DATA.emails;
    source.forEach(p => {
        // Convert virustotal object to array if needed
        const vtEntries = Array.isArray(p.virustotal) ? p.virustotal :
            (p.virustotal && typeof p.virustotal === 'object' ?
                Object.entries(p.virustotal).map(([domain, data]) => ({ domain, ...data })) : []);

        // Malware domains - only include if actually malicious
        vtEntries.forEach(vt => {
            if (!vt.malicious && !vt.suspicious) return; // Skip non-malicious
            const card = p.domain_cards?.find(d => d.domain === vt.domain) || p.urlscan?.[vt.domain];
            const registrar = card?.whois?.registrar || card?.whois?.Registrar || null;
            if (registrar) registrars.add(registrar);
            threats.push({
                type: 'malware',
                severity: (vt.malicious || 0) * 10,
                actor: p,
                domain: vt.domain,
                detections: vt.malicious || 0,
                total: (vt.harmless || 0) + (vt.malicious || 0) + (vt.suspicious || 0),
                screenshot: card?.screenshot,
                ip: card?.ip,
                country: card?.country,
                registrar: registrar,
                created: card?.whois?.creation_date || card?.whois?.CreationDate
            });
        });

        // Convert blacklist object to array if needed
        const blEntries = Array.isArray(p.blacklist) ? p.blacklist :
            (p.blacklist && typeof p.blacklist === 'object' ?
                Object.entries(p.blacklist).map(([domain, data]) => ({ domain, ...data })) : []);

        // Phishing domains
        blEntries.forEach(bl => {
            if (!bl.blacklisted && !bl.brand_impersonation?.length) return; // Skip non-blacklisted
            if (threats.find(t => t.domain === bl.domain)) return;
            const card = p.domain_cards?.find(d => d.domain === bl.domain) || p.urlscan?.[bl.domain];
            const registrar = card?.whois?.registrar || card?.whois?.Registrar || null;
            if (registrar) registrars.add(registrar);
            threats.push({
                type: 'phishing',
                severity: bl.risk_score || 50,
                actor: p,
                domain: bl.domain,
                sources: bl.blacklist_sources || bl.sources || [],
                screenshot: card?.screenshot,
                ip: card?.ip,
                country: card?.country,
                registrar: registrar,
                created: card?.whois?.creation_date || card?.whois?.CreationDate
            });
        });
    });

    // Save registrars and threats globally for filters
    window.threatRegistrars = [...registrars].sort();
    allThreats = threats;

    // Populate registrars dropdown
    populateRegistrarFilter();

    // Apply filters and render
    filterThreats();
}

// ==================== GRAPH ====================
function renderGraph() {
    const container = document.getElementById('graph-container');
    if (!container) return;

    container.innerHTML = `
        <div class="graph-layout">
            <div class="graph-sidebar">
                <div class="graph-search">
                    <input type="text" id="graph-search" placeholder="Search actors...">
                </div>
                <div class="graph-actor-list" id="graph-actor-list"></div>
            </div>
            <div class="graph-main">
                <div class="graph-canvas" id="graph-canvas"></div>
                <div class="graph-info-panel" id="graph-info-panel">
                    <div class="info-placeholder">Select a node to view details</div>
                </div>
            </div>
        </div>
    `;

    renderGraphActorList();

    document.getElementById('graph-search')?.addEventListener('input', debounce(e => {
        renderGraphActorList(e.target.value.toLowerCase());
    }, 200));

    // Always use all data for graph
    const allActors = DATA.emails || [];

    if (selectedActor) {
        renderActorGraph(selectedActor);
    } else if (allActors.length) {
        selectedActor = allActors[0];
        renderActorGraph(selectedActor);
    }
}

function renderGraphActorList(search = '') {
    const list = document.getElementById('graph-actor-list');
    if (!list) return;

    // Use ALL emails for graph - sort by threat score
    const source = DATA.emails || [];
    let actors = [...source].sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));
    if (search) actors = actors.filter(p => p.email.toLowerCase().includes(search) ||
        (p.leak_intel?.real_names?.[0] || '').toLowerCase().includes(search));
    actors = actors.slice(0, 150);

    // Count stats
    const totalActors = source.length;
    const threatsCount = source.filter(p => getVTArray(p).length || getBLArray(p).length).length;

    list.innerHTML = `
        <div class="ga-stats">
            <div class="ga-stats-item">
                <span class="ga-stats-value">${totalActors}</span>
                <span class="ga-stats-label">Actors</span>
            </div>
            <div class="ga-stats-item danger">
                <span class="ga-stats-value">${threatsCount}</span>
                <span class="ga-stats-label">Threats</span>
            </div>
        </div>
        ${actors.map((p, idx) => {
            const name = p.leak_intel?.real_names?.[0] || p.leak_info?.fullname || p.google?.name || '';
            const vtCount = getVTArray(p).length;
            const blCount = getBLArray(p).length;
            const hasThreats = vtCount || blCount;
            const threatLevel = vtCount ? 'critical' : (blCount ? 'high' : 'low');
            const screenshots = getActorScreenshots(p);
            const country = getActorCountry(p);

            return `
                <div class="graph-actor ${selectedActor?.email === p.email ? 'active' : ''} ${hasThreats ? 'has-threat' : ''}"
                     onclick="selectGraphActor('${esc(p.email)}')"
                     style="animation-delay: ${idx * 0.02}s">
                    <div class="ga-avatar-wrap">
                        <div class="ga-avatar ${p.google?.photo ? 'has-photo' : ''}">
                            ${p.google?.photo ? `<img src="${esc(p.google.photo)}" onerror="this.parentElement.innerHTML='${getInitial(p.email)}'">` : getInitial(p.email)}
                        </div>
                        ${hasThreats ? `<span class="ga-threat-badge ${threatLevel}">${vtCount + blCount}</span>` : ''}
                    </div>
                    <div class="ga-content">
                        <div class="ga-header">
                            ${name ? `<span class="ga-name">${esc(name.length > 18 ? name.slice(0,16) + '..' : name)}</span>` : ''}
                            ${country ? `<span class="ga-flag">${getFlag(country)}</span>` : ''}
                        </div>
                        <div class="ga-email">${esc(p.email.length > 24 ? p.email.slice(0,22) + '..' : p.email)}</div>
                        <div class="ga-meta">
                            <span class="ga-domains">${p.total_domains || 0} domains</span>
                            ${screenshots.length ? `<span class="ga-screens">📷 ${screenshots.length}</span>` : ''}
                        </div>
                    </div>
                    ${hasThreats ? `
                        <div class="ga-indicators">
                            ${vtCount ? `<span class="ga-ind malware" title="${vtCount} Malware">☠️</span>` : ''}
                            ${blCount ? `<span class="ga-ind phishing" title="${blCount} Phishing">🎣</span>` : ''}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('')}
    `;
}

function selectGraphActor(email) {
    const actor = DATA.emails.find(e => e.email === email);
    if (actor) {
        selectedActor = actor;
        document.querySelectorAll('.graph-actor').forEach(el => {
            el.classList.toggle('active', el.querySelector('.ga-email')?.textContent === email);
        });
        renderActorGraph(actor);
    }
}
window.selectGraphActor = selectGraphActor;

function renderActorGraph(p) {
    const container = document.getElementById('graph-canvas');
    if (!container || !p) return;
    container.innerHTML = '';

    // Get actual dimensions or use sensible defaults
    const rect = container.getBoundingClientRect();
    const width = rect.width > 100 ? rect.width : 800;
    const height = rect.height > 100 ? rect.height : 600;

    const nodes = [];
    const links = [];
    const nodeIds = new Set();

    // Color scheme - modern cyberpunk palette
    const GRAPH_COLORS = {
        email: '#0ea5e9',        // Sky blue - center actor
        google: '#f43f5e',       // Rose red - Google
        services: '#22c55e',     // Green - services
        name: '#a855f7',         // Purple - identity
        phone: '#14b8a6',        // Teal - phone
        passwords_group: '#ef4444', // Red - credentials
        leaked_site: '#fb923c',  // Orange - leaked sites
        leaks_group: '#fbbf24',  // Amber - data breaches
        leak_db: '#facc15',      // Yellow - databases
        threats_group: '#ef4444', // Red - threats
        malware: '#dc2626',      // Dark red - malware
        phishing: '#f59e0b',     // Amber - phishing
        ips_group: '#8b5cf6',    // Violet - IPs
        domains_group: '#06b6d4', // Cyan - domains
        screenshots_group: '#3b82f6', // Blue - scanned
        connected_email: '#64748b', // Slate - connections
    };

    // === CENTER: Actor email ===
    const actorId = 'email_main';
    nodes.push({
        id: actorId,
        type: 'email',
        label: p.email,
        data: p,
        size: 50,
        color: GRAPH_COLORS.email,
        fx: width / 2,
        fy: height / 2
    });
    nodeIds.add(actorId);

    // === GOOGLE ACCOUNT ===
    if (p.google?.person_id) {
        const googleId = 'google';
        nodes.push({
            id: googleId,
            type: 'google',
            label: p.google.name || 'Google Account',
            data: p.google,
            size: 36,
            color: GRAPH_COLORS.google
        });
        links.push({ source: actorId, target: googleId, type: 'has_google' });
        nodeIds.add(googleId);

        // Google services
        if (p.google.services?.length) {
            const servicesId = 'google_services';
            nodes.push({
                id: servicesId,
                type: 'services',
                label: p.google.services.slice(0, 3).join(', '),
                data: p.google.services,
                size: 24,
                color: GRAPH_COLORS.services
            });
            links.push({ source: googleId, target: servicesId, type: 'uses' });
        }
    }

    // === REAL NAME ===
    if (p.leak_intel?.real_names?.length) {
        const nameId = 'real_name';
        nodes.push({
            id: nameId,
            type: 'name',
            label: p.leak_intel.real_names[0],
            data: p.leak_intel.real_names,
            size: 34,
            color: GRAPH_COLORS.name
        });
        links.push({ source: actorId, target: nameId, type: 'identity' });
        nodeIds.add(nameId);
    }

    // === PHONES ===
    const phones = dedupePhones(p.leak_intel?.phones || []);
    phones.slice(0, 3).forEach((ph, i) => {
        const phoneId = `phone_${i}`;
        const country = getCountryFromPhone(ph.phone);
        nodes.push({
            id: phoneId,
            type: 'phone',
            label: ph.phone,
            data: ph,
            country: country,
            size: 28,
            color: GRAPH_COLORS.phone
        });
        links.push({ source: actorId, target: phoneId, type: 'has_phone', label: ph.source });
        nodeIds.add(phoneId);
    });

    // === REGISTRANTS (WHOIS) ===
    if (p.registrants?.length) {
        // Get unique registrant names
        const uniqueNames = [...new Set(p.registrants
            .map(r => r.name)
            .filter(n => n && !n.includes('REDACTED') && !n.includes('???') && n.length > 2)
        )];

        if (uniqueNames.length) {
            const regId = 'registrant';
            const regLabel = uniqueNames.length === 1 ? uniqueNames[0] : `${uniqueNames.length} Registrants`;
            nodes.push({
                id: regId,
                type: 'registrar',
                label: regLabel.slice(0, 22),
                data: { names: uniqueNames, records: p.registrants },
                size: 30,
                color: GRAPH_COLORS.registrar || '#a855f7'
            });
            links.push({ source: actorId, target: regId, type: 'registered_as' });
            nodeIds.add(regId);
        }
    }

    // === PASSWORDS -> SITES ===
    const passwordsByUrl = {};
    (p.passwords || []).forEach(pw => {
        const url = (typeof pw === 'object' ? pw.url : '') || 'unknown';
        const domain = url.replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
        if (!passwordsByUrl[domain]) passwordsByUrl[domain] = [];
        passwordsByUrl[domain].push(pw);
    });

    // Passwords group
    if (Object.keys(passwordsByUrl).length) {
        const pwGroupId = 'passwords';
        nodes.push({
            id: pwGroupId,
            type: 'passwords_group',
            label: `${p.passwords.length} Passwords`,
            data: p.passwords,
            size: 32,
            color: GRAPH_COLORS.passwords_group
        });
        links.push({ source: actorId, target: pwGroupId, type: 'leaked_creds' });

        // Sites where passwords leaked
        Object.entries(passwordsByUrl).slice(0, 6).forEach(([domain, pwds], i) => {
            if (domain === 'unknown' || !domain) return;
            const siteId = `pwd_site_${i}`;
            nodes.push({
                id: siteId,
                type: 'leaked_site',
                label: domain.slice(0, 18),
                data: { domain, passwords: pwds },
                size: 22,
                color: GRAPH_COLORS.leaked_site
            });
            links.push({ source: pwGroupId, target: siteId, type: 'on_site' });
        });
    }

    // === LEAKS (DATABASES) ===
    if (p.leak_extended?.databases?.length) {
        const leaksId = 'leaks';
        nodes.push({
            id: leaksId,
            type: 'leaks_group',
            label: `${p.leak_extended.databases.length} Leaks`,
            data: p.leak_extended.databases,
            size: 30,
            color: GRAPH_COLORS.leaks_group
        });
        links.push({ source: actorId, target: leaksId, type: 'found_in' });

        // Specific databases
        p.leak_extended.databases.slice(0, 5).forEach((db, i) => {
            const dbId = `leak_db_${i}`;
            nodes.push({
                id: dbId,
                type: 'leak_db',
                label: (db.database || db.source || 'Unknown').slice(0, 15),
                data: db,
                size: 20,
                color: GRAPH_COLORS.leak_db
            });
            links.push({ source: leaksId, target: dbId, type: 'database' });
        });
    }

    // === DOMAINS - show ALL domains with screenshots + threats ===
    // Convert objects to arrays if needed
    const vtArray = Array.isArray(p.virustotal) ? p.virustotal :
        (p.virustotal && typeof p.virustotal === 'object' ?
            Object.entries(p.virustotal).filter(([_, v]) => v.malicious || v.suspicious).map(([domain, data]) => ({ domain, ...data })) : []);
    const blArray = Array.isArray(p.blacklist) ? p.blacklist :
        (p.blacklist && typeof p.blacklist === 'object' ?
            Object.entries(p.blacklist).filter(([_, v]) => v.blacklisted || v.brand_impersonation?.length).map(([domain, data]) => ({ domain, ...data })) : []);

    const threatDomains = [
        ...vtArray.map(v => ({ ...v, type: 'malware' })),
        ...blArray.map(b => ({ ...b, type: 'phishing' }))
    ];

    // Collect all domains with screenshots
    const domainsWithScreenshots = (p.domain_cards || []).filter(d => d.screenshot);
    const threatDomainSet = new Set(threatDomains.map(t => t.domain));

    // Domains group
    const totalDomains = p.domains?.length || p.total_domains || 0;
    if (totalDomains > 0) {
        const domainsId = 'domains';
        nodes.push({
            id: domainsId,
            type: 'domains_group',
            label: `${totalDomains} Domains`,
            data: p.domains,
            size: 32,
            color: '#64748b'
        });
        links.push({ source: actorId, target: domainsId, type: 'owns' });

        // Add threats
        if (threatDomains.length) {
            const threatsId = 'threats';
            nodes.push({
                id: threatsId,
                type: 'threats_group',
                label: `${threatDomains.length} Threats`,
                data: threatDomains,
                size: 34,
                color: GRAPH_COLORS.threats_group
            });
            links.push({ source: domainsId, target: threatsId, type: 'includes' });

            threatDomains.slice(0, 10).forEach((td, i) => {
                const domainId = `threat_${i}`;
                const card = p.domain_cards?.find(d => d.domain === td.domain);
                nodes.push({
                    id: domainId,
                    type: td.type,
                    label: td.domain.length > 18 ? td.domain.slice(0, 16) + '..' : td.domain,
                    domain: td.domain,
                    data: { ...td, card },
                    size: 26,
                    color: td.type === 'malware' ? GRAPH_COLORS.malware : GRAPH_COLORS.phishing,
                    hasScreenshot: !!card?.screenshot,
                    screenshot: card?.screenshot
                });
                links.push({
                    source: threatsId,
                    target: domainId,
                    type: td.type,
                    label: td.type === 'malware' ? `${td.malicious} detections` : (td.sources?.slice(0,2).join(', ') || '')
                });
            });
        }

        // Add domains with screenshots (non-threats)
        const screenshotsNotThreats = domainsWithScreenshots.filter(d => !threatDomainSet.has(d.domain)).slice(0, 6);
        if (screenshotsNotThreats.length) {
            const screenshotsId = 'screenshots';
            nodes.push({
                id: screenshotsId,
                type: 'screenshots_group',
                label: `${domainsWithScreenshots.length} Scanned`,
                data: domainsWithScreenshots,
                size: 28,
                color: '#0ea5e9'
            });
            links.push({ source: domainsId, target: screenshotsId, type: 'scanned' });

            screenshotsNotThreats.forEach((d, i) => {
                const domainId = `scanned_${i}`;
                nodes.push({
                    id: domainId,
                    type: 'domain',
                    label: d.domain.length > 18 ? d.domain.slice(0, 16) + '..' : d.domain,
                    domain: d.domain,
                    data: d,
                    size: 22,
                    color: '#38bdf8',
                    hasScreenshot: true,
                    screenshot: d.screenshot
                });
                links.push({ source: screenshotsId, target: domainId, type: 'has_scan' });
            });
        }
    }

    // === IP ADDRESSES ===
    const ips = dedupeIPs(p.leak_intel?.ips || []);
    if (ips.length) {
        const ipsId = 'ips';
        nodes.push({
            id: ipsId,
            type: 'ips_group',
            label: `${ips.length} IPs`,
            data: ips,
            size: 28,
            color: GRAPH_COLORS.ips_group
        });
        links.push({ source: actorId, target: ipsId, type: 'used_ip' });
    }

    // === CONNECTED EMAILS (shared passwords) ===
    const connected = p.connected_emails || [];
    if (connected.length) {
        const connId = 'connections';
        nodes.push({
            id: connId,
            type: 'connections_group',
            label: `${connected.length} Connected`,
            data: connected,
            size: 30,
            color: '#ec4899' // Pink
        });
        links.push({ source: actorId, target: connId, type: 'shared_password' });

        // Show up to 5 connected emails
        connected.slice(0, 5).forEach((email, i) => {
            const connectedActor = DATA.emails.find(e => e.email === email);
            const connEmailId = `conn_${i}`;
            nodes.push({
                id: connEmailId,
                type: 'connected_email',
                label: email.length > 20 ? email.slice(0, 18) + '..' : email,
                email: email,
                data: connectedActor || { email },
                size: 22,
                color: connectedActor?.blacklist?.length ? '#f59e0b' : '#f472b6',
                hasPhoto: !!connectedActor?.google?.photo,
                photo: connectedActor?.google?.photo
            });
            links.push({ source: connId, target: connEmailId, type: 'shared_cred' });
        });
    }

    // D3 Force Graph
    const svg = d3.select(container).append('svg')
        .attr('width', '100%')
        .attr('height', '100%')
        .attr('viewBox', `0 0 ${width} ${height}`);

    // Add gradient definitions
    const defs = svg.append('defs');

    // Create gradients for each node type
    const gradients = {
        email: ['#38bdf8', '#0284c7'],
        google: ['#fb7185', '#e11d48'],
        services: ['#4ade80', '#16a34a'],
        name: ['#c084fc', '#9333ea'],
        phone: ['#2dd4bf', '#0d9488'],
        passwords_group: ['#f87171', '#dc2626'],
        leaked_site: ['#fdba74', '#ea580c'],
        leaks_group: ['#fcd34d', '#d97706'],
        leak_db: ['#fde047', '#ca8a04'],
        threats_group: ['#f87171', '#b91c1c'],
        malware: ['#fca5a5', '#991b1b'],
        phishing: ['#fcd34d', '#b45309'],
        ips_group: ['#c4b5fd', '#7c3aed'],
        domains_group: ['#67e8f9', '#0891b2'],
        screenshots_group: ['#93c5fd', '#2563eb'],
        domain: ['#a5f3fc', '#06b6d4'],
        connected_email: ['#cbd5e1', '#475569'],
        connections_group: ['#a5b4fc', '#4f46e5'],
        registrar: ['#d8b4fe', '#a855f7'],
    };

    Object.entries(gradients).forEach(([type, [c1, c2]]) => {
        const grad = defs.append('radialGradient')
            .attr('id', `grad-${type}`)
            .attr('cx', '30%').attr('cy', '30%').attr('r', '70%');
        grad.append('stop').attr('offset', '0%').attr('stop-color', c1);
        grad.append('stop').attr('offset', '100%').attr('stop-color', c2);
    });

    // Glow filter
    const glowFilter = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
    glowFilter.append('feMerge').html('<feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/>');

    // Danger glow filter
    const dangerGlow = defs.append('filter').attr('id', 'danger-glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    dangerGlow.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'blur');
    dangerGlow.append('feFlood').attr('flood-color', '#ef4444').attr('flood-opacity', '0.5');
    dangerGlow.append('feComposite').attr('in2', 'blur').attr('operator', 'in');
    dangerGlow.append('feMerge').html('<feMergeNode/><feMergeNode in="SourceGraphic"/>');

    const g = svg.append('g');

    svg.call(d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => g.attr('transform', e.transform)));

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => d.size + 10));

    const link = g.append('g').selectAll('line').data(links).join('line')
        .attr('stroke', '#374151').attr('stroke-width', 1.5).attr('stroke-opacity', 0.5);

    let selectedNode = null;

    // Define stroke colors for node types
    function getNodeStroke(d) {
        const strokes = {
            'email': '#38bdf8',
            'registrar': '#c084fc',
            'google': '#fb7185',
            'services': '#4ade80',
            'name': '#c084fc',
            'phone': '#2dd4bf',
            'malware': '#f87171',
            'phishing': '#fbbf24',
            'threats_group': '#f87171',
            'passwords_group': '#f87171',
            'leaked_site': '#fb923c',
            'leaks_group': '#fcd34d',
            'leak_db': '#fde047',
            'ips_group': '#a78bfa',
            'domains_group': '#22d3ee',
            'screenshots_group': '#60a5fa',
            'domain': d.hasScreenshot ? '#38bdf8' : 'rgba(255,255,255,0.3)',
            'connected_email': '#94a3b8',
            'connections_group': '#818cf8',
        };
        return strokes[d.type] || 'rgba(255,255,255,0.2)';
    }

    const node = g.append('g').selectAll('g').data(nodes).join('g')
        .attr('class', 'graph-node')
        .style('cursor', 'pointer')
        .call(d3.drag()
            .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
            .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
            .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); if (d.type !== 'email') { d.fx = null; d.fy = null; } }))
        .on('click', (e, d) => {
            e.stopPropagation();
            // Remove selection from previous
            if (selectedNode) {
                const prevData = d3.select(selectedNode).datum();
                d3.select(selectedNode).select('.main-circle')
                    .attr('stroke-width', (prevData.type === 'malware' || prevData.type === 'phishing') ? 3 : 2)
                    .attr('stroke', getNodeStroke(prevData));
            }
            // Select current
            selectedNode = e.currentTarget;
            d3.select(selectedNode).select('.main-circle')
                .attr('stroke', '#fff')
                .attr('stroke-width', 4);

            // Show info panel
            showNodeInfo(d, p);

            // Make sure panel is visible on mobile
            const panel = document.getElementById('graph-info-panel');
            if (panel) panel.classList.add('active');
        })
        .on('mouseenter', function(e, d) {
            d3.select(this).select('.main-circle')
                .transition().duration(150)
                .attr('r', d.size + 4);
        })
        .on('mouseleave', function(e, d) {
            d3.select(this).select('.main-circle')
                .transition().duration(150)
                .attr('r', d.size);
        });

    // Icons for node types
    const nodeIcons = {
        email: '📧',
        google: '🔍',
        services: '📱',
        name: '👤',
        phone: '📞',
        registrar: '📋',
        passwords_group: '🔑',
        leaked_site: '🌐',
        leaks_group: '💧',
        leak_db: '🗄️',
        threats_group: '⚠️',
        malware: '☠️',
        phishing: '🎣',
        ips_group: '🖥️',
        domains_group: '🌐',
        screenshots_group: '📷',
        domain: '🔗',
        connections_group: '🔗',
        connected_email: '📧',
    };

    node.each(function(d) {
        const el = d3.select(this);

        // Glow effects for different node types
        const glowTypes = ['malware', 'phishing', 'threats_group', 'email', 'passwords_group', 'leaks_group'];
        if (glowTypes.includes(d.type)) {
            el.append('circle')
                .attr('r', d.size + 10)
                .attr('fill', 'none')
                .attr('stroke', d.color)
                .attr('stroke-width', 3)
                .attr('stroke-opacity', 0.25)
                .style('filter', 'blur(6px)');
        }

        // Second glow ring for critical threats
        if (d.type === 'malware' || d.type === 'phishing') {
            el.append('circle')
                .attr('r', d.size + 16)
                .attr('fill', 'none')
                .attr('stroke', d.color)
                .attr('stroke-width', 2)
                .attr('stroke-opacity', 0.15)
                .style('filter', 'blur(10px)');
        }

        // For domains with favicons - special rendering
        if ((d.type === 'malware' || d.type === 'phishing' || d.type === 'domain') && d.domain) {
            // Circle background with gradient
            el.append('circle')
                .attr('class', 'main-circle')
                .attr('r', d.size)
                .attr('fill', `url(#grad-${d.type})`)
                .attr('stroke', getNodeStroke(d))
                .attr('stroke-width', d.type !== 'domain' ? 3 : 2)
                .style('filter', (d.type === 'malware' || d.type === 'phishing') ? 'url(#danger-glow)' : 'url(#glow)');

            // Clip for favicon
            const clipId = `clip-${d.id}`;
            el.append('clipPath')
                .attr('id', clipId)
                .append('circle')
                .attr('r', d.size * 0.65);

            // Favicon
            el.append('image')
                .attr('href', getFavicon(d.domain))
                .attr('x', -d.size * 0.55)
                .attr('y', -d.size * 0.55)
                .attr('width', d.size * 1.1)
                .attr('height', d.size * 1.1)
                .attr('clip-path', `url(#${clipId})`)
                .attr('preserveAspectRatio', 'xMidYMid slice')
                .style('pointer-events', 'none')
                .on('error', function() {
                    d3.select(this).remove();
                    el.append('text')
                        .attr('text-anchor', 'middle')
                        .attr('dominant-baseline', 'central')
                        .attr('font-size', d.size * 0.55)
                        .style('pointer-events', 'none')
                        .text(nodeIcons[d.type] || '🌐');
                });

            // Screenshot indicator
            if (d.hasScreenshot) {
                el.append('circle')
                    .attr('cx', d.size * 0.6)
                    .attr('cy', -d.size * 0.6)
                    .attr('r', 8)
                    .attr('fill', '#22c55e')
                    .attr('stroke', '#fff')
                    .attr('stroke-width', 2);
                el.append('text')
                    .attr('x', d.size * 0.6)
                    .attr('y', -d.size * 0.6)
                    .attr('text-anchor', 'middle')
                    .attr('dominant-baseline', 'central')
                    .attr('font-size', 8)
                    .attr('fill', '#fff')
                    .text('📷');
            }

            // Threat indicator
            if (d.type === 'malware' || d.type === 'phishing') {
                el.append('circle')
                    .attr('cx', -d.size * 0.6)
                    .attr('cy', -d.size * 0.6)
                    .attr('r', 10)
                    .attr('fill', d.type === 'malware' ? '#dc2626' : '#f59e0b')
                    .attr('stroke', '#fff')
                    .attr('stroke-width', 2);
                el.append('text')
                    .attr('x', -d.size * 0.6)
                    .attr('y', -d.size * 0.6)
                    .attr('text-anchor', 'middle')
                    .attr('dominant-baseline', 'central')
                    .attr('font-size', 10)
                    .text(d.type === 'malware' ? '☠️' : '🎣');
            }
        } else {
            // Regular nodes with gradient
            const isDanger = ['malware', 'phishing', 'threats_group', 'passwords_group'].includes(d.type);
            el.append('circle')
                .attr('class', 'main-circle')
                .attr('r', d.size)
                .attr('fill', `url(#grad-${d.type})`)
                .attr('stroke', getNodeStroke(d))
                .attr('stroke-width', isDanger ? 3 : 2)
                .style('filter', isDanger ? 'url(#danger-glow)' : 'url(#glow)');

            // Icon inside
            el.append('text')
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'central')
                .attr('font-size', d.size * 0.55)
                .style('pointer-events', 'none')
                .text(nodeIcons[d.type] || '📄');
        }

        // Country flag for phones
        if (d.type === 'phone' && d.country) {
            el.append('text')
                .attr('x', d.size * 0.7)
                .attr('y', -d.size * 0.7)
                .attr('font-size', 14)
                .text(getCountryEmoji(d.country));
        }
    });

    // Label under node
    node.append('text')
        .attr('dy', d => d.size + 14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#e5e7eb')
        .attr('font-size', '11px')
        .attr('font-weight', '500')
        .style('text-shadow', '0 1px 3px rgba(0,0,0,0.8)')
        .text(d => d.label.length > 22 ? d.label.slice(0, 20) + '..' : d.label);

    simulation.on('tick', () => {
        link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Auto-select actor node
    showNodeInfo(nodes[0], p);
}

function showNodeInfo(node, profile) {
    const panel = document.getElementById('graph-info-panel');
    if (!panel) return;

    let html = '';
    const nodeType = node.type;

    // === EMAIL (central actor node) ===
    if (nodeType === 'email') {
        const p = node.data;
        const name = p.leak_intel?.real_names?.[0] || p.google?.name || '';
        const country = getActorCountry(p);
        const isCrypto = hasCryptoBrand(p);
        const brandArr = getBrandArray(p);
        const threatCount = getThreatCount(p);
        const phones = p.leak_intel?.phones || p.leak_info?.phone ? [p.leak_info?.phone] : [];

        // Get screenshots from domain_cards OR urlscan
        let screenshots = p.domain_cards?.filter(d => d.screenshot) || [];
        if (!screenshots.length && p.urlscan) {
            screenshots = Object.entries(p.urlscan)
                .filter(([_, u]) => u.screenshot)
                .map(([domain, u]) => ({ domain, screenshot: u.screenshot, ...u }))
                .slice(0, 6);
        }

        html = `
            <div class="panel-header ${isCrypto ? 'crypto' : ''}">
                <div class="panel-avatar">${p.google?.photo ? `<img src="${esc(p.google.photo)}">` : getInitial(p.email)}</div>
                <div class="panel-identity">
                    ${name ? `<div class="panel-name">${esc(name)}</div>` : ''}
                    <div class="panel-email">${esc(p.email)}</div>
                    ${country ? `<div class="panel-location">${getFlag(country)} ${country.toUpperCase()}</div>` : ''}
                </div>
            </div>

            ${brandArr.length ? `
                <div class="panel-brands">
                    ${isCrypto ? '<span class="brand-tag crypto">💰 Crypto</span>' : ''}
                    ${brandArr.slice(0, 3).map(b => `<span class="brand-tag">${esc(b)}</span>`).join('')}
                </div>
            ` : ''}

            <div class="panel-stats">
                ${p.total_domains ? `<div class="ps-item"><span>${p.total_domains}</span>Domains</div>` : ''}
                ${threatCount > 0 ? `<div class="ps-item danger"><span>${threatCount}</span>Threats</div>` : ''}
                ${p.passwords?.length ? `<div class="ps-item"><span>${p.passwords.length}</span>Creds</div>` : ''}
                ${phones.length ? `<div class="ps-item"><span>${phones.length}</span>Phones</div>` : ''}
            </div>

            ${screenshots.length ? `
                <div class="panel-section-title">📷 Phishing Sites</div>
                <div class="panel-screenshots">
                    ${screenshots.slice(0, 4).map(d => `
                        <div class="panel-thumb" onclick="openModal('${esc(d.screenshot)}', '${esc(d.domain)}')">
                            <img src="${esc(d.screenshot)}" loading="lazy">
                            <span>${esc(d.domain.slice(0, 20))}</span>
                        </div>
                    `).join('')}
                </div>
            ` : ''}

            ${p.leak_info?.nickname || p.leak_info?.address ? `
                <div class="panel-section-title">🔍 Leaked Info</div>
                <div class="panel-details">
                    ${p.leak_info?.nickname ? `<div class="pd-row"><span>Nickname</span>${esc(p.leak_info.nickname)}</div>` : ''}
                    ${p.leak_info?.address ? `<div class="pd-row"><span>Address</span>${esc(p.leak_info.address.slice(0,50))}</div>` : ''}
                    ${phones[0] ? `<div class="pd-row"><span>Phone</span>${esc(phones[0])}</div>` : ''}
                </div>
            ` : ''}

            <button class="btn-profile" onclick="openProfile('${esc(p.email)}')">View Full Profile</button>
        `;
    }
    // === GOOGLE ACCOUNT ===
    else if (nodeType === 'google') {
        const g = node.data;
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-google">${g.photo ? `<img src="${esc(g.photo)}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">` : '🔍'}</div>
                    <div class="node-info-title">
                        <h3>${esc(g.name || 'Google Account')}</h3>
                        <span class="node-type-badge info">GOOGLE</span>
                    </div>
                </div>

                <div class="node-info-section">
                    <h4>Account Details</h4>
                    <div class="node-info-row">
                        <span class="label">Person ID</span>
                        <span class="value monospace" style="font-size:11px">${esc(g.person_id)}</span>
                    </div>
                    ${g.name ? `
                    <div class="node-info-row">
                        <span class="label">Name</span>
                        <span class="value">${esc(g.name)}</span>
                    </div>
                    ` : ''}
                    ${g.last_updated ? `
                    <div class="node-info-row">
                        <span class="label">Last Updated</span>
                        <span class="value">${esc(g.last_updated)}</span>
                    </div>
                    ` : ''}
                    ${g.uses_android ? `
                    <div class="node-info-row">
                        <span class="label">Platform</span>
                        <span class="value">🤖 Android</span>
                    </div>
                    ` : ''}
                </div>

                ${g.services?.length ? `
                <div class="node-info-section">
                    <h4>Google Services (${g.services.length})</h4>
                    <div class="node-info-tags">
                        ${g.services.map(s => `<span class="node-info-tag">${esc(s)}</span>`).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }
    // === GOOGLE SERVICES ===
    else if (nodeType === 'services') {
        const services = node.data;
        html = `
            <div class="panel-header">
                <div class="panel-icon services">📱</div>
                <div class="panel-title">Google Services</div>
            </div>
            <div class="panel-list">
                ${services.map(s => `<div class="pl-item service">${esc(s)}</div>`).join('')}
            </div>
        `;
    }
    // === REAL NAME ===
    else if (nodeType === 'name') {
        const names = Array.isArray(node.data) ? node.data : [node.data];
        html = `
            <div class="panel-header">
                <div class="panel-icon name">👤</div>
                <div class="panel-title">Real Name</div>
            </div>
            <div class="panel-list">
                ${names.map(n => `<div class="pl-item name">${esc(n)}</div>`).join('')}
            </div>
        `;
    }
    // === PHONE NUMBER ===
    else if (nodeType === 'phone') {
        const ph = node.data;
        const country = node.country || getCountryFromPhone(ph.phone);
        html = `
            <div class="panel-header">
                <div class="panel-icon phone">📞</div>
                <div class="panel-title">Phone Number</div>
            </div>
            <div class="panel-details">
                <div class="pd-row"><span>Number</span>${country ? getFlag(country) : ''} <strong>${esc(ph.phone)}</strong></div>
                ${ph.source ? `<div class="pd-row"><span>Source</span>${esc(ph.source)}</div>` : ''}
                ${country ? `<div class="pd-row"><span>Country</span>${getFlag(country)} ${country.toUpperCase()}</div>` : ''}
            </div>
        `;
    }
    // === REGISTRAR (WHOIS) ===
    else if (nodeType === 'registrar') {
        const d = node.data;
        const names = d.names || [];
        const records = d.records || [];
        // Get unique domains
        const domains = [...new Set(records.map(r => r.domain))];
        // Get unique countries
        const countries = [...new Set(records.map(r => r.country).filter(c => c && !c.includes('REDACTED')))];
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-service">📋</div>
                    <div class="node-info-title">
                        <h3>WHOIS Registrant</h3>
                        <span class="node-type-badge info">IDENTITY</span>
                    </div>
                </div>

                <div class="node-info-section">
                    <h4><i class="fas fa-user"></i> Registrant Names</h4>
                    ${names.slice(0, 5).map(n => `
                        <div class="node-info-row">
                            <span class="label">👤</span>
                            <span class="value">${esc(n)}</span>
                        </div>
                    `).join('')}
                    ${names.length > 5 ? `<div style="padding:4px 0;color:var(--text-muted);font-size:11px">+${names.length - 5} more names</div>` : ''}
                </div>

                <div class="node-info-section">
                    <h4><i class="fas fa-globe"></i> Registered Domains (${domains.length})</h4>
                    <div class="node-info-tags">
                        ${domains.slice(0, 8).map(d => `<span class="node-info-tag">${esc(d)}</span>`).join('')}
                    </div>
                    ${domains.length > 8 ? `<div style="padding:4px 0;color:var(--text-muted);font-size:11px">+${domains.length - 8} more</div>` : ''}
                </div>

                ${countries.length ? `
                <div class="node-info-section">
                    <h4><i class="fas fa-map-marker-alt"></i> Countries</h4>
                    <div class="node-info-tags">
                        ${countries.slice(0, 5).map(c => `<span class="node-info-tag">${getFlag(c)} ${esc(c)}</span>`).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }
    // === PASSWORDS GROUP ===
    else if (nodeType === 'passwords_group') {
        const passwords = node.data;
        const uniquePwds = [...new Set(passwords.map(pw => typeof pw === 'string' ? pw : pw.password || ''))];
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-password">🔑</div>
                    <div class="node-info-title">
                        <h3>Leaked Credentials</h3>
                        <span class="node-type-badge threat">EXPOSED</span>
                    </div>
                </div>

                <div class="threat-level high">
                    <div class="threat-level-icon">🔐</div>
                    <div class="threat-level-text">
                        <div class="level">Credentials Exposed</div>
                        <div class="desc">${passwords.length} password${passwords.length > 1 ? 's' : ''} found in ${uniquePwds.length} unique</div>
                    </div>
                </div>

                <div class="node-info-section">
                    <h4><i class="fas fa-key"></i> Leaked Passwords</h4>
                    ${passwords.slice(0, 10).map(pw => {
                        const pwd = typeof pw === 'string' ? pw : pw.password || '';
                        const url = typeof pw === 'object' ? (pw.url || '').replace(/^https?:\/\//, '').split('/')[0] : '';
                        return `
                        <div class="node-info-row">
                            <span class="label">${url ? esc(url.slice(0,20)) : 'Password'}</span>
                            <span class="value monospace danger">${esc(pwd)}</span>
                        </div>`;
                    }).join('')}
                    ${passwords.length > 10 ? `<div style="padding:8px 0;color:var(--text-muted);font-size:11px">+${passwords.length - 10} more credentials</div>` : ''}
                </div>
            </div>
        `;
    }
    // === LEAKED SITE ===
    else if (nodeType === 'leaked_site') {
        const d = node.data;
        html = `
            <div class="panel-header">
                <div class="panel-icon leaked">🌐</div>
                <div class="panel-title">Leaked From</div>
            </div>
            <div class="panel-details">
                <div class="pd-row"><span>Site</span><img src="${getFavicon(d.domain)}" style="width:16px;height:16px;vertical-align:middle;margin-right:6px" onerror="this.style.display='none'">${esc(d.domain)}</div>
                <div class="pd-row"><span>Passwords</span><strong>${d.passwords?.length || 0}</strong></div>
            </div>
            ${d.passwords?.length ? `
                <div class="panel-list">
                    ${d.passwords.slice(0, 5).map(pw => {
                        const pwd = typeof pw === 'string' ? pw : pw.password || '';
                        return `<div class="pl-item cred"><code>${esc(pwd)}</code></div>`;
                    }).join('')}
                </div>
            ` : ''}
        `;
    }
    // === LEAKS GROUP ===
    else if (nodeType === 'leaks_group') {
        const dbs = node.data;
        const uniqueDbs = [...new Set(dbs.map(d => d.database || d.source || 'Unknown'))];
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-leak">💧</div>
                    <div class="node-info-title">
                        <h3>Data Breaches</h3>
                        <span class="node-type-badge warning">${dbs.length} LEAKS</span>
                    </div>
                </div>

                <div class="threat-level medium">
                    <div class="threat-level-icon">📊</div>
                    <div class="threat-level-text">
                        <div class="level">Data Exposed</div>
                        <div class="desc">Found in ${uniqueDbs.length} different database${uniqueDbs.length > 1 ? 's' : ''}</div>
                    </div>
                </div>

                <div class="node-info-section">
                    <h4><i class="fas fa-database"></i> Breach Databases</h4>
                    <div class="node-info-tags">
                        ${uniqueDbs.slice(0, 15).map(db => `<span class="node-info-tag warning">${esc(db)}</span>`).join('')}
                    </div>
                    ${uniqueDbs.length > 15 ? `<div style="padding:8px 0;color:var(--text-muted);font-size:11px">+${uniqueDbs.length - 15} more databases</div>` : ''}
                </div>
            </div>
        `;
    }
    // === LEAK DATABASE ===
    else if (nodeType === 'leak_db') {
        const db = node.data;
        const d = db.data?.[0] || db;
        html = `
            <div class="panel-header">
                <div class="panel-icon db">🗄️</div>
                <div class="panel-title">${esc(db.database || db.source || 'Database')}</div>
            </div>
            <div class="panel-details">
                ${d.username ? `<div class="pd-row"><span>Username</span>${esc(d.username)}</div>` : ''}
                ${d.password ? `<div class="pd-row"><span>Password</span><code>${esc(d.password)}</code></div>` : ''}
                ${d.phone ? `<div class="pd-row"><span>Phone</span>${esc(d.phone)}</div>` : ''}
                ${d.name || d.FullName ? `<div class="pd-row"><span>Name</span>${esc(d.name || d.FullName)}</div>` : ''}
                ${d.ip ? `<div class="pd-row"><span>IP</span>${esc(d.ip)}</div>` : ''}
            </div>
        `;
    }
    // === THREATS GROUP ===
    else if (nodeType === 'threats_group') {
        const threats = node.data;
        const malwareList = threats.filter(t => t.type === 'malware');
        const phishingList = threats.filter(t => t.type === 'phishing');
        const threatLevel = malwareList.length > 0 ? 'critical' : phishingList.length > 3 ? 'high' : 'medium';
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-malware">⚠️</div>
                    <div class="node-info-title">
                        <h3>Threat Intelligence</h3>
                        <span class="node-type-badge threat">${threats.length} THREATS</span>
                    </div>
                </div>

                <div class="threat-level ${threatLevel}">
                    <div class="threat-level-icon">🛡️</div>
                    <div class="threat-level-text">
                        <div class="level">${threatLevel} Risk</div>
                        <div class="desc">${malwareList.length} malware, ${phishingList.length} phishing domains</div>
                    </div>
                </div>

                ${malwareList.length ? `
                <div class="node-info-section">
                    <h4><i class="fas fa-skull-crossbones"></i> Malware (${malwareList.length})</h4>
                    ${malwareList.slice(0, 5).map(t => `
                        <div class="node-info-row">
                            <span class="label">☠️</span>
                            <span class="value monospace danger">${esc(t.domain)}</span>
                        </div>
                    `).join('')}
                    ${malwareList.length > 5 ? `<div style="padding:4px 0;color:var(--text-muted);font-size:11px">+${malwareList.length - 5} more</div>` : ''}
                </div>
                ` : ''}

                ${phishingList.length ? `
                <div class="node-info-section">
                    <h4><i class="fas fa-fish"></i> Phishing (${phishingList.length})</h4>
                    ${phishingList.slice(0, 5).map(t => `
                        <div class="node-info-row">
                            <span class="label">🎣</span>
                            <span class="value monospace warning">${esc(t.domain)}</span>
                        </div>
                    `).join('')}
                    ${phishingList.length > 5 ? `<div style="padding:4px 0;color:var(--text-muted);font-size:11px">+${phishingList.length - 5} more</div>` : ''}
                </div>
                ` : ''}
            </div>
        `;
    }
    // === MALWARE DOMAIN ===
    else if (nodeType === 'malware') {
        const d = node.data;
        const card = d.card;
        const totalEngines = (d.harmless || 0) + (d.malicious || 0) + (d.suspicious || 0);
        const detectionRate = totalEngines > 0 ? Math.round((d.malicious / totalEngines) * 100) : 0;
        const threatLevel = detectionRate > 50 ? 'critical' : detectionRate > 25 ? 'high' : 'medium';
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-malware">☠️</div>
                    <div class="node-info-title">
                        <h3>${esc(d.domain)}</h3>
                        <span class="node-type-badge threat">Malware</span>
                    </div>
                </div>

                <div class="threat-level ${threatLevel}">
                    <div class="threat-level-icon">⚠️</div>
                    <div class="threat-level-text">
                        <div class="level">${threatLevel} Risk</div>
                        <div class="desc">${d.malicious || 0} of ${totalEngines} engines detected threats</div>
                    </div>
                </div>

                ${card?.screenshot ? `
                    <div class="node-screenshot-preview">
                        <img src="${esc(card.screenshot)}" onclick="openModal('${esc(card.screenshot)}', '${esc(d.domain)}')" style="cursor:pointer">
                    </div>
                ` : ''}

                <div class="node-info-section">
                    <h4><i class="fas fa-info-circle"></i> Domain Details</h4>
                    <div class="node-info-row">
                        <span class="label">Domain</span>
                        <span class="value monospace">${esc(d.domain)}</span>
                    </div>
                    <div class="node-info-row">
                        <span class="label">Detections</span>
                        <span class="value danger">${d.malicious || 0} / ${totalEngines}</span>
                    </div>
                    ${d.suspicious ? `
                    <div class="node-info-row">
                        <span class="label">Suspicious</span>
                        <span class="value warning">${d.suspicious}</span>
                    </div>
                    ` : ''}
                    ${card?.ip ? `
                    <div class="node-info-row">
                        <span class="label">IP Address</span>
                        <span class="value monospace">${esc(card.ip)}</span>
                    </div>
                    ` : ''}
                    ${card?.country ? `
                    <div class="node-info-row">
                        <span class="label">Country</span>
                        <span class="value">${getFlag(card.country)} ${esc(card.country.toUpperCase())}</span>
                    </div>
                    ` : ''}
                    ${card?.server ? `
                    <div class="node-info-row">
                        <span class="label">Server</span>
                        <span class="value">${esc(card.server)}</span>
                    </div>
                    ` : ''}
                </div>

                <div class="node-info-actions">
                    <a href="https://www.virustotal.com/gui/domain/${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm">${ICONS.virustotal} VirusTotal</a>
                    <a href="https://urlscan.io/search/#${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm btn-secondary">URLScan</a>
                </div>
            </div>
        `;
    }
    // === PHISHING DOMAIN ===
    else if (nodeType === 'phishing') {
        const d = node.data;
        const card = d.card;
        const sourcesCount = d.sources?.length || 1;
        const threatLevel = sourcesCount > 3 ? 'critical' : sourcesCount > 1 ? 'high' : 'medium';
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-phishing">🎣</div>
                    <div class="node-info-title">
                        <h3>${esc(d.domain)}</h3>
                        <span class="node-type-badge threat">Phishing</span>
                    </div>
                </div>

                <div class="threat-level ${threatLevel}">
                    <div class="threat-level-icon">🎣</div>
                    <div class="threat-level-text">
                        <div class="level">${threatLevel} Risk</div>
                        <div class="desc">Listed in ${sourcesCount} blocklist${sourcesCount > 1 ? 's' : ''}</div>
                    </div>
                </div>

                ${card?.screenshot ? `
                    <div class="node-screenshot-preview">
                        <img src="${esc(card.screenshot)}" onclick="openModal('${esc(card.screenshot)}', '${esc(d.domain)}')" style="cursor:pointer">
                    </div>
                ` : ''}

                <div class="node-info-section">
                    <h4><i class="fas fa-shield-alt"></i> Threat Intelligence</h4>
                    <div class="node-info-row">
                        <span class="label">Domain</span>
                        <span class="value monospace">${esc(d.domain)}</span>
                    </div>
                    ${d.sources?.length ? `
                    <div class="node-info-row">
                        <span class="label">Blocklists</span>
                        <span class="value danger">${d.sources.length} sources</span>
                    </div>
                    ` : ''}
                    ${card?.ip ? `
                    <div class="node-info-row">
                        <span class="label">IP Address</span>
                        <span class="value monospace">${esc(card.ip)}</span>
                    </div>
                    ` : ''}
                    ${card?.country ? `
                    <div class="node-info-row">
                        <span class="label">Country</span>
                        <span class="value">${getFlag(card.country)} ${esc(card.country.toUpperCase())}</span>
                    </div>
                    ` : ''}
                    ${card?.server ? `
                    <div class="node-info-row">
                        <span class="label">Server</span>
                        <span class="value">${esc(card.server)}</span>
                    </div>
                    ` : ''}
                    ${card?.title ? `
                    <div class="node-info-row">
                        <span class="label">Title</span>
                        <span class="value">${esc(card.title.slice(0, 40))}</span>
                    </div>
                    ` : ''}
                </div>

                ${d.sources?.length ? `
                <div class="node-info-section">
                    <h4><i class="fas fa-list"></i> Blocklist Sources</h4>
                    <div class="node-info-tags">
                        ${d.sources.map(s => `<span class="node-info-tag danger">${esc(s)}</span>`).join('')}
                    </div>
                </div>
                ` : ''}

                <div class="node-info-actions">
                    <a href="https://urlscan.io/search/#${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm">URLScan</a>
                    <a href="https://web.archive.org/web/*/${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm btn-secondary">Archive</a>
                </div>
            </div>
        `;
    }
    // === IPS GROUP ===
    else if (nodeType === 'ips_group') {
        const ips = node.data;
        html = `
            <div class="panel-header">
                <div class="panel-icon ip">🖥️</div>
                <div class="panel-title">IP Addresses (${ips.length})</div>
            </div>
            <div class="panel-list">
                ${ips.slice(0, 10).map(ip => {
                    const addr = ip.ip || ip;
                    const info = getIPInfo(addr);
                    return `<div class="pl-item ip">${info.country ? getFlag(info.country) : ''} <code>${esc(addr)}</code> ${ip.source ? `<small>${esc(ip.source)}</small>` : ''}</div>`;
                }).join('')}
                ${ips.length > 10 ? `<div class="pl-more">+${ips.length - 10} more</div>` : ''}
            </div>
        `;
    }
    // === DOMAINS GROUP ===
    else if (nodeType === 'domains_group') {
        const domains = node.data || [];
        html = `
            <div class="panel-header">
                <div class="panel-icon domain">🌐</div>
                <div class="panel-title">Domains (${domains.length || profile.total_domains || 0})</div>
            </div>
            <div class="panel-list">
                ${(domains.slice ? domains.slice(0, 12) : []).map(d => `
                    <div class="pl-item domain">
                        <img src="${getFavicon(d)}" style="width:16px;height:16px;vertical-align:middle;margin-right:6px" onerror="this.style.display='none'">
                        ${esc(d.length > 30 ? d.slice(0, 28) + '..' : d)}
                    </div>
                `).join('')}
                ${(domains.length || 0) > 12 ? `<div class="pl-more">+${domains.length - 12} more</div>` : ''}
            </div>
        `;
    }
    // === SCREENSHOTS GROUP ===
    else if (nodeType === 'screenshots_group') {
        const screenshots = node.data || [];
        html = `
            <div class="panel-header">
                <div class="panel-icon screenshot">📷</div>
                <div class="panel-title">Scanned Domains (${screenshots.length})</div>
            </div>
            <div class="panel-screenshots">
                ${screenshots.slice(0, 6).map(d => `
                    <div class="panel-thumb" onclick="openModal('${esc(d.screenshot)}', '${esc(d.domain)}')">
                        <img src="${esc(d.screenshot)}" loading="lazy">
                        <span>${esc(d.domain.slice(0, 20))}</span>
                    </div>
                `).join('')}
            </div>
            ${screenshots.length > 6 ? `<div class="pl-more">+${screenshots.length - 6} more screenshots</div>` : ''}
        `;
    }
    // === DOMAIN (single scanned domain) ===
    else if (nodeType === 'domain') {
        const d = node.data;
        html = `
            <div class="node-info-content">
                <div class="node-info-header">
                    <div class="node-info-icon type-domain">🌐</div>
                    <div class="node-info-title">
                        <h3>${esc(d.domain)}</h3>
                        <span class="node-type-badge info">Scanned Domain</span>
                    </div>
                </div>

                ${d.screenshot ? `
                    <div class="node-screenshot-preview">
                        <img src="${esc(d.screenshot)}" onclick="openModal('${esc(d.screenshot)}', '${esc(d.domain)}')" style="cursor:pointer">
                    </div>
                ` : ''}

                <div class="node-info-section">
                    <h4><i class="fas fa-server"></i> Domain Info</h4>
                    <div class="node-info-row">
                        <span class="label">Domain</span>
                        <span class="value monospace">${esc(d.domain)}</span>
                    </div>
                    ${d.ip ? `
                    <div class="node-info-row">
                        <span class="label">IP Address</span>
                        <span class="value monospace">${esc(d.ip)}</span>
                    </div>
                    ` : ''}
                    ${d.country ? `
                    <div class="node-info-row">
                        <span class="label">Country</span>
                        <span class="value">${getFlag(d.country)} ${esc(d.country.toUpperCase())}</span>
                    </div>
                    ` : ''}
                    ${d.server ? `
                    <div class="node-info-row">
                        <span class="label">Server</span>
                        <span class="value">${esc(d.server)}</span>
                    </div>
                    ` : ''}
                    ${d.title ? `
                    <div class="node-info-row">
                        <span class="label">Page Title</span>
                        <span class="value">${esc(d.title.slice(0, 50))}</span>
                    </div>
                    ` : ''}
                    ${d.urlscan_uuid ? `
                    <div class="node-info-row">
                        <span class="label">Scan ID</span>
                        <span class="value monospace" style="font-size:10px">${esc(d.urlscan_uuid.slice(0, 16))}...</span>
                    </div>
                    ` : ''}
                </div>

                <div class="node-info-actions">
                    <a href="https://urlscan.io/search/#${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm">URLScan</a>
                    <a href="https://web.archive.org/web/*/${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-sm btn-secondary">Archive</a>
                </div>
            </div>
        `;
    }
    // === CONNECTIONS GROUP (shared passwords) ===
    else if (nodeType === 'connections_group') {
        const emails = node.data || [];
        html = `
            <div class="panel-header">
                <div class="panel-icon connection">🔗</div>
                <div class="panel-title">Shared Passwords (${emails.length})</div>
            </div>
            <p style="padding: 12px; color: var(--text-muted); font-size: 12px;">
                These actors share the same password with this actor - likely same person or group.
            </p>
            <div class="panel-list">
                ${emails.slice(0, 10).map(email => {
                    const actor = DATA.emails.find(e => e.email === email);
                    return `<div class="pl-item connection" onclick="openProfile('${esc(email)}')" style="cursor:pointer">
                        ${actor?.google?.photo ? `<img src="${esc(actor.google.photo)}" style="width:20px;height:20px;border-radius:50%">` : '📧'}
                        ${esc(email)}
                        ${actor?.blacklist?.length ? '<span style=\"color:var(--warning)\">⚠️</span>' : ''}
                    </div>`;
                }).join('')}
                ${emails.length > 10 ? `<div class="pl-more">+${emails.length - 10} more</div>` : ''}
            </div>
        `;
    }
    // === CONNECTED EMAIL (single) ===
    else if (nodeType === 'connected_email') {
        const d = node.data || {};
        const name = d.leak_intel?.real_names?.[0] || d.google?.name || '';
        html = `
            <div class="panel-header">
                <div class="panel-avatar">${d.google?.photo ? `<img src="${esc(d.google.photo)}">` : getInitial(node.email)}</div>
                <div class="panel-identity">
                    ${name ? `<div class="panel-name">${esc(name)}</div>` : ''}
                    <div class="panel-email">${esc(node.email)}</div>
                </div>
            </div>
            <p style="padding: 12px; color: var(--accent-pink); font-size: 12px;">
                🔑 Shares password with main actor
            </p>
            ${d.total_domains || d.blacklist?.length || d.passwords?.length ? `
                <div class="panel-stats">
                    ${d.total_domains ? `<div class="ps-item"><span>${d.total_domains}</span>Domains</div>` : ''}
                    ${d.blacklist?.length ? `<div class="ps-item warning"><span>${d.blacklist.length}</span>Threats</div>` : ''}
                    ${d.passwords?.length ? `<div class="ps-item"><span>${d.passwords.length}</span>Creds</div>` : ''}
                </div>
            ` : ''}
            <button class="btn-profile" onclick="openProfile('${esc(node.email)}')">View Profile</button>
        `;
    }
    // === DEFAULT ===
    else {
        html = `
            <div class="panel-header">
                <div class="panel-icon">📄</div>
                <div class="panel-title">${esc(node.label || node.type)}</div>
            </div>
            <div class="panel-details">
                <div class="pd-row"><span>Type</span>${esc(node.type)}</div>
            </div>
        `;
    }

    panel.innerHTML = html;
}

// ==================== FULL PROFILE ====================
function openProfile(email) {
    const p = DATA.emails.find(e => e.email === email);
    if (!p) return;

    const modal = document.getElementById('actor-modal');
    const content = document.getElementById('actor-profile');
    if (!modal || !content) return;

    // Get name from multiple sources
    const name = p.leak_intel?.real_names?.[0] || p.leak_info?.fullname || p.google?.name ||
                 p.contacts?.find(c => c.name && !c.name.includes('REDACTED') && !c.name.includes('???'))?.name || '';
    const country = getActorCountry(p);
    const screenshots = getActorScreenshots(p);
    const vtArr = getVTArray(p);
    const blArr = getBLArray(p);
    const malwareDomains = new Set(vtArr.map(v => v.domain));
    const phishingDomains = new Set(blArr.map(b => b.domain));
    // Get all phones from multiple sources
    const allPhones = dedupePhones([
        ...(p.leak_intel?.phones || []),
        ...(p.leak_info?.phone ? [{ phone: p.leak_info.phone, source: 'Breach Data' }] : [])
    ]);

    content.innerHTML = `
        <!-- Header -->
        <div class="profile-hero">
            <div class="ph-bg ${vtArr.length ? 'malware' : (blArr.length ? 'phishing' : '')}"></div>
            <div class="ph-content">
                <div class="ph-avatar">${p.google?.photo ? `<img src="${esc(p.google.photo)}">` : getInitial(p.email)}</div>
                <div class="ph-info">
                    ${name ? `<h1 class="ph-name">${esc(name)}</h1>` : ''}
                    <div class="ph-email">${esc(p.email)}</div>
                    ${country ? `<div class="ph-location">${getFlag(country)} ${country}</div>` : ''}
                    <div class="ph-badges">
                        ${p.is_primary_target ? '<span class="badge primary">Primary Target</span>' : '<span class="badge related">Related</span>'}
                        ${vtArr.length ? `<span class="badge danger">${vtArr.length} Malware</span>` : ''}
                        ${blArr.length ? `<span class="badge warning">${blArr.length} Phishing</span>` : ''}
                        ${getBrandArray(p).length ? `<span class="badge brand">Brand Impersonation</span>` : ''}
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="profile-stats">
            ${p.total_domains ? `<div class="pstat">${ICONS.domain}<span>${p.total_domains}</span><label>Domains</label></div>` : ''}
            ${(vtArr.length || blArr.length) ? `<div class="pstat danger">${ICONS.malware}<span>${vtArr.length + blArr.length}</span><label>Threats</label></div>` : ''}
            ${p.passwords?.length ? `<div class="pstat danger">${ICONS.key}<span>${p.passwords.length}</span><label>Passwords</label></div>` : ''}
            ${hasLeakData(p) ? `<div class="pstat warning">${ICONS.leak}<span>${getLeakCount(p) || (p.leak_info?.num_results || 0)}</span><label>Leaks</label></div>` : ''}
            ${allPhones.length ? `<div class="pstat">${ICONS.phone}<span>${allPhones.length}</span><label>Phones</label></div>` : ''}
            ${dedupeIPs(p.leak_intel?.ips || []).length ? `<div class="pstat">${ICONS.ip}<span>${dedupeIPs(p.leak_intel.ips).length}</span><label>IPs</label></div>` : ''}
        </div>

        <div class="profile-body">
            <!-- Google Account -->
            ${p.google?.person_id ? `
                <section class="profile-section">
                    <h2>${ICONS.google} Google Account</h2>
                    <div class="google-card">
                        ${p.google.photo ? `<img src="${esc(p.google.photo)}" class="gc-photo">` : ''}
                        <div class="gc-info">
                            <div class="gc-row"><strong>Google ID:</strong> ${esc(p.google.person_id)}</div>
                            ${p.google.name ? `<div class="gc-row"><strong>Name:</strong> ${esc(p.google.name)}</div>` : ''}
                            ${p.google.services?.length ? `<div class="gc-row"><strong>Services:</strong> ${p.google.services.join(', ')}</div>` : ''}
                            ${p.google.uses_android ? `<div class="gc-row"><strong>Platform:</strong> Android User</div>` : ''}
                        </div>
                    </div>
                </section>
            ` : ''}

            <!-- Breach Data (leak_info) -->
            ${p.leak_info ? `
                <section class="profile-section highlight">
                    <h2>${ICONS.leak} Breach Data Intelligence</h2>
                    <div class="breach-data-card">
                        ${p.leak_info.fullname ? `<div class="bd-row highlight"><span class="bd-label">Real Name</span><span class="bd-value">${esc(p.leak_info.fullname)}</span></div>` : ''}
                        ${p.leak_info.nickname ? `<div class="bd-row"><span class="bd-label">Nickname</span><span class="bd-value">${esc(p.leak_info.nickname)}</span></div>` : ''}
                        ${p.leak_info.phone ? `<div class="bd-row highlight"><span class="bd-label">Phone</span><span class="bd-value">${p.leak_info.phone_country ? getFlag(p.leak_info.phone_country.code) : ''} ${esc(p.leak_info.phone)}</span></div>` : ''}
                        ${p.leak_info.num_results ? `<div class="bd-row"><span class="bd-label">Found in</span><span class="bd-value">${p.leak_info.num_results} breach databases</span></div>` : ''}
                    </div>
                </section>
            ` : ''}

            <!-- Intelligence Data -->
            ${(p.leak_intel?.real_names?.length || p.leak_intel?.phones?.length || p.leak_intel?.ips?.length) ? `
                <section class="profile-section highlight">
                    <h2>${ICONS.user} Identity Intelligence</h2>
                    <div class="intel-grid">
                        ${p.leak_intel.real_names?.length ? `
                            <div class="intel-card">
                                <div class="ic-title">Real Names</div>
                                <div class="ic-values">${p.leak_intel.real_names.map(n => `<span class="iv-name">${esc(n)}</span>`).join('')}</div>
                            </div>
                        ` : ''}
                        ${p.leak_intel.phones?.length ? `
                            <div class="intel-card">
                                <div class="ic-title">Phone Numbers</div>
                                <div class="ic-phones">${dedupePhones(p.leak_intel.phones).filter(ph => ph.phone && !ph.phone.includes('REDACTED')).map(ph => `
                                    <div class="ip-row">${getFlagForPhone(ph)} <span>${esc(ph.phone)}</span> <small>${esc(ph.source || '')}</small></div>
                                `).join('') || '<div class="empty-text">No public phones</div>'}</div>
                            </div>
                        ` : ''}
                        ${p.leak_intel.ips?.length ? `
                            <div class="intel-card">
                                <div class="ic-title">IP Addresses</div>
                                <div class="ic-ips" id="profile-ips-${esc(p.email.replace(/[^a-z0-9]/gi, ''))}">${dedupeIPs(p.leak_intel.ips).slice(0, 10).map(ip => renderIPRow(ip)).join('')}</div>
                            </div>
                        ` : ''}
                    </div>
                </section>
            ` : ''}

            <!-- Threats -->
            ${(vtArr.length || blArr.length) ? `
                <section class="profile-section danger">
                    <h2>${ICONS.malware} Threat Detections</h2>
                    <div class="threats-list">
                        ${vtArr.map(vt => `
                            <div class="threat-item malware">
                                <div class="ti-icon">${ICONS.malware}</div>
                                <div class="ti-info">
                                    <div class="ti-domain">${esc(vt.domain)}</div>
                                    <div class="ti-detail">${vt.malicious || 0} malicious / ${vt.suspicious || 0} suspicious detections</div>
                                </div>
                                <a href="https://www.virustotal.com/gui/domain/${encodeURIComponent(vt.domain)}" target="_blank" class="ti-link">${ICONS.external}</a>
                            </div>
                        `).join('')}
                        ${blArr.map(bl => `
                            <div class="threat-item phishing">
                                <div class="ti-icon">${ICONS.phishing}</div>
                                <div class="ti-info">
                                    <div class="ti-domain">${esc(bl.domain)}</div>
                                    <div class="ti-detail">Sources: ${(bl.blacklist_sources || bl.sources || []).join(', ') || 'Blacklist'}</div>
                                </div>
                                <a href="https://urlscan.io/search/#${encodeURIComponent(bl.domain)}" target="_blank" class="ti-link">${ICONS.external}</a>
                            </div>
                        `).join('')}
                    </div>
                </section>
            ` : ''}

            <!-- Brand Impersonation -->
            ${getBrandArray(p).length ? `
                <section class="profile-section warning">
                    <h2>${ICONS.brand} Brand Impersonation</h2>
                    <div class="brand-tags">${getBrandArray(p).map(b => `<span class="brand-tag">${esc(b)}</span>`).join('')}</div>
                </section>
            ` : ''}

            <!-- WHOIS Contacts -->
            ${p.contacts?.length ? `
                <section class="profile-section">
                    <h2>${ICONS.user} WHOIS Contacts</h2>
                    <div class="contacts-grid">
                        ${dedupeContacts(p.contacts).slice(0, 8).map(c => `
                            <div class="contact-card">
                                <div class="cc-name">${esc(c.name || 'Unknown')}${c.count > 1 ? ` <span class="cc-count">×${c.count}</span>` : ''}</div>
                                ${c.company ? `<div class="cc-row">${esc(c.company)}</div>` : ''}
                                ${c.phone && c.phone !== 'REDACTED FOR PRIVACY' ? `<div class="cc-row">${c.phone_country ? getFlag(c.phone_country.code) : ''} ${esc(c.phone)}</div>` : ''}
                                ${c.country ? `<div class="cc-row">${getFlag(c.country)} ${esc(c.country)}</div>` : ''}
                                ${c.address ? `<div class="cc-row small">${esc(c.address)}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </section>
            ` : ''}

            <!-- Leaked Credentials -->
            ${p.passwords?.length ? `
                <section class="profile-section">
                    <h2>${ICONS.key} Leaked Credentials (${p.passwords.length})</h2>
                    <div class="creds-list">
                        ${(() => {
                            const byService = {};
                            p.passwords.forEach(pw => {
                                const pwd = typeof pw === 'string' ? pw : pw.password || '';
                                const url = typeof pw === 'object' ? (pw.url || '').replace(/^www\./, '').split('/')[0] : 'unknown';
                                if (!byService[url]) byService[url] = [];
                                if (!byService[url].includes(pwd)) byService[url].push(pwd);
                            });
                            return Object.entries(byService).slice(0, 20).map(([svc, pwds]) => `
                                <div class="cred-row">
                                    <span class="cr-service">${esc(svc.slice(0, 30))}</span>
                                    <div class="cr-passwords">${pwds.slice(0, 3).map(p => `<code>${esc(p)}</code>`).join('')}${pwds.length > 3 ? `<span class="cr-more">+${pwds.length - 3}</span>` : ''}</div>
                                </div>
                            `).join('');
                        })()}
                    </div>
                </section>
            ` : ''}

            <!-- Leak Databases -->
            ${p.leak_extended?.databases?.length ? `
                <section class="profile-section">
                    <h2>${ICONS.leak} Data Breaches (${p.leak_extended.databases.length})</h2>
                    <div class="leaks-grid">
                        ${p.leak_extended.databases.slice(0, 20).map(db => {
                            const info = parseLeakInfo(db.info || '');
                            const dbName = db.database || db.source || db.name || '';
                            const hasGoodData = info.FirstName || info.LastName || info.Phone || info.Address || info.City || info.CompanyName || info.Password;
                            // Skip empty Unknown records
                            if (!dbName || dbName === 'Unknown') {
                                if (!hasGoodData) return '';
                            }
                            return `
                                <div class="leak-card ${hasGoodData ? 'has-data' : ''}">
                                    <div class="lc-header">${esc(dbName || 'Data Breach')}</div>
                                    ${hasGoodData ? `<div class="lc-data">
                                        ${info.FirstName || info.LastName ? `<div class="ld-row highlight"><span>Name</span>${esc((info.FirstName || '') + ' ' + (info.LastName || '')).trim()}</div>` : ''}
                                        ${info.NickName ? `<div class="ld-row"><span>Nick</span>${esc(info.NickName)}</div>` : ''}
                                        ${info.Phone ? `<div class="ld-row highlight"><span>Phone</span>${esc(info.Phone)}</div>` : ''}
                                        ${info.Address ? `<div class="ld-row highlight"><span>Addr</span>${esc(info.Address)}</div>` : ''}
                                        ${info.City ? `<div class="ld-row"><span>City</span>${esc(info.City)}${info.Country ? ', ' + esc(info.Country) : ''}</div>` : ''}
                                        ${info.CompanyName ? `<div class="ld-row highlight"><span>Company</span>${esc(info.CompanyName)}</div>` : ''}
                                        ${info.Domain ? `<div class="ld-row"><span>Domain</span>${esc(info.Domain)}</div>` : ''}
                                        ${info.IP ? `<div class="ld-row"><span>IP</span>${esc(info.IP)}</div>` : ''}
                                        ${info.Password ? `<div class="ld-row danger"><span>Pass</span><code>${esc(info.Password)}</code></div>` : ''}
                                        ${info['Password(MD5)'] ? `<div class="ld-row"><span>Hash</span><code class="hash">${esc(info['Password(MD5)'].slice(0,16))}...</code></div>` : ''}
                                    </div>` : '<div class="lc-empty">Email found in breach</div>'}
                                </div>
                            `;
                        }).join('')}
                    </div>
                </section>
            ` : ''}

            <!-- Screenshots -->
            ${screenshots.length ? `
                <section class="profile-section">
                    <h2>${ICONS.screenshot} Site Screenshots (${screenshots.length})</h2>
                    <div class="screenshots-grid">
                        ${screenshots.slice(0, 12).map(d => {
                            const isMal = malwareDomains.has(d.domain);
                            const isPh = phishingDomains.has(d.domain);
                            return `
                                <div class="screenshot-card ${isMal ? 'malware' : ''} ${isPh ? 'phishing' : ''}" onclick="openModal('${esc(d.screenshot)}', '${esc(d.domain)}')">
                                    <img src="${esc(d.screenshot)}" loading="lazy">
                                    <div class="sc-overlay">
                                        ${isMal ? '<span class="sc-badge danger">MAL</span>' : ''}
                                        ${isPh ? '<span class="sc-badge warning">PHISH</span>' : ''}
                                    </div>
                                    <div class="sc-domain">${esc(d.domain)}</div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </section>
            ` : ''}

            <!-- Domain Registrars -->
            ${p.registrars?.length ? `
                <section class="profile-section">
                    <h2>🏢 Domain Registrars (${p.registrars.length})</h2>
                    <div class="registrars-list">
                        ${p.registrars.slice(0, 10).map(r => `<span class="registrar-tag">${esc(r)}</span>`).join('')}
                    </div>
                </section>
            ` : ''}

            <!-- All Domains -->
            ${p.domains?.length ? `
                <section class="profile-section">
                    <h2>${ICONS.domain} All Domains (${p.total_domains || p.domains.length})</h2>
                    <div class="domains-list">
                        ${p.domains.slice(0, 50).map(d => {
                            const isMal = malwareDomains.has(d);
                            const isPh = phishingDomains.has(d);
                            return `<span class="domain-tag ${isMal ? 'malware' : ''} ${isPh ? 'phishing' : ''}">${esc(d)}</span>`;
                        }).join('')}
                        ${p.domains.length > 50 ? `<span class="domains-more">+${p.domains.length - 50} more</span>` : ''}
                    </div>
                </section>
            ` : ''}
        </div>
    `;

    modal.classList.add('active');

    // Load IP address info
    if (p.leak_intel?.ips?.length) {
        const uniqueIPs = dedupeIPs(p.leak_intel.ips).slice(0, 10);
        const ipsToLoad = uniqueIPs.map(ip => ip.ip).filter(ip => !ipCache.has(ip));

        if (ipsToLoad.length) {
            lookupIPsBatch(ipsToLoad).then(() => {
                // Update IP display after loading
                const containerId = `profile-ips-${p.email.replace(/[^a-z0-9]/gi, '')}`;
                const container = document.getElementById(containerId);
                if (container) {
                    container.innerHTML = uniqueIPs.map(ip => renderIPRow(ip)).join('');
                }
            });
        }
    }
}
window.openProfile = openProfile;

function closeActorModal() {
    document.getElementById('actor-modal')?.classList.remove('active');
}
window.closeActorModal = closeActorModal;

// ==================== MODAL ====================
function openModal(src, title) {
    if (!src) return;
    const modal = document.getElementById('modal');
    const img = document.getElementById('modal-image');
    const info = document.getElementById('modal-info');
    if (modal && img) {
        img.src = src;
        if (info) info.textContent = title || '';
        modal.classList.add('active');
    }
}
window.openModal = openModal;

function closeModal() {
    document.getElementById('modal')?.classList.remove('active');
}
window.closeModal = closeModal;

// ==================== PAGINATION ====================
function renderPagination() {
    const total = Math.ceil(filtered.length / perPage);
    const c = document.getElementById('pagination');
    if (!c || total <= 1) { if (c) c.innerHTML = ''; return; }

    c.innerHTML = `
        <button ${page === 1 ? 'disabled' : ''} onclick="changePage(${page - 1})">Previous</button>
        <span>Page ${page} of ${total}</span>
        <button ${page === total ? 'disabled' : ''} onclick="changePage(${page + 1})">Next</button>
    `;
}

function changePage(p) {
    page = p;
    renderActors();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}
window.changePage = changePage;

// ==================== UTILITIES ====================
// Sources that 100% indicate country (strictly local services)
// NOT including international ones
const GEO_SOURCES = {
    // Russia - strictly Russian services
    'alfabank': 'ru', 'alfaBank': 'ru', 'sberbank': 'ru', 
    'tinkoff': 'ru',  'vtb': 'ru',  'gazprombank': 'ru',
    'rosbank': 'ru', 'otkritie': 'ru', 'sovcombank': 'ru', 'pochta.ru': 'ru',
    'cdek': 'ru',  'boxberry': 'ru', 'dpd.ru': 'ru', 'pek': 'ru',
    'wildberries': 'ru', 'ozon': 'ru', 'dns-shop': 'ru', 'mvideo': 'ru',
    'eldorado': 'ru', 'citilink': 'ru', 'svyaznoy': 'ru', 'metro-cc.ru': 'ru', 'lenta': 'ru',
    'perekrestok': 'ru', 'magnit': 'ru', 'pyaterochka': 'ru', 'dixy': 'ru',
    'yandex': 'ru',  'mail.ru': 'ru', 'rambler': 'ru',
    'gosuslugi': 'ru',  'nalog.ru': 'ru', 'pfr.ru': 'ru', 'mos.ru': 'ru',
    'avito': 'ru', 'youla': 'ru', 'drom.ru': 'ru', 'auto.ru': 'ru',
    'hh.ru': 'ru', 'superjob.ru': 'ru', 'rabota.ru': 'ru',
    'fonbet.ru': 'ru', 'ligastavok': 'ru',
    'adengi': 'ru', 'oneclickmoney': 'ru', 'moneyman.ru': 'ru', 'vivus.ru': 'ru', 'zaimer': 'ru',
    'mts': 'ru',  'megafon': 'ru',  'beeline': 'ru', 
    'tele2': 'ru',  'yota': 'ru',  'rostelecom': 'ru',
    'vk.com': 'ru', 'vkontakte': 'ru',  'ok.ru': 'ru', 
    'pikabu': 'ru', 'habr': 'ru', 'vc.ru': 'ru', 'dtf': 'ru',
    'kinopoisk': 'ru', 'ivi': 'ru', 'okko': 'ru', 'amediateka': 'ru',
    'sportmaster': 'ru', 'decathlon.ru': 'ru', 'rendez-vous': 'ru',
    // Ukraine - strictly Ukrainian services
    'privatbank': 'ua',  'privat24': 'ua', 'monobank': 'ua', 'oschadbank': 'ua',
    'nova poshta': 'ua', 'novaposhta': 'ua',  'ukrposhta': 'ua', 'meest': 'ua',
    'rozetka': 'ua', 'epicentr': 'ua', 'comfy': 'ua', 'foxtrot': 'ua', 'allo.ua': 'ua',
    'silpo': 'ua', 'atb': 'ua', 'fozzy': 'ua', 'novus': 'ua', 'metro.ua': 'ua',
    'olx.ua': 'ua', 'work.ua': 'ua', 'rabota.ua': 'ua', 'dou.ua': 'ua', 'jobs.ua': 'ua',
    'kyivstar': 'ua',  'vodafone.ua': 'ua', 'lifecell': 'ua',
    'yavshoke': 'ua', 'yavshoke.ua': 'ua', // Ukrainian service
    'prom.ua': 'ua', 'hotline.ua': 'ua', 'ria.ua': 'ua', 'auto.ria': 'ua',
    'ukr.net': 'ua', 'i.ua': 'ua', 'meta.ua': 'ua', 'bigmir': 'ua',
    'diia': 'ua',  'action.gov.ua': 'ua',
    'volia': 'ua', 'triolan': 'ua', 'datagroup': 'ua', // Ukrainian ISPs
    // Belarus
    'belarusbank': 'by', 'priorbank': 'by', 'alfa.by': 'by',
    'euroopt': 'by', 'e-dostavka': 'by', '21vek': 'by', 'onliner': 'by',
    // Kazakhstan
    'kaspi': 'kz', 'halyk': 'kz', 'forte': 'kz', 'jusan': 'kz',
    'kolesa.kz': 'kz', 'krisha.kz': 'kz', 'olx.kz': 'kz',
    // USA
    'uber': 'us', 'lyft': 'us', 'doordash': 'us', 'instacart': 'us', 'grubhub': 'us',
    'venmo': 'us', 'cashapp': 'us', 'zelle': 'us', 'paypal': 'us',
    'chase': 'us', 'wellsfargo': 'us', 'bankofamerica': 'us', 'citi': 'us',
    'amazon.com': 'us', 'walmart': 'us', 'target': 'us', 'bestbuy': 'us',
    'linkedin': 'us', 'facebook': 'us', 'instagram': 'us', 'twitter': 'us',
    // Europe
    'revolut': 'gb', 'n26': 'de', 'klarna': 'se', 'ing': 'nl',
};

// Services that indicate Android
const ANDROID_INDICATORS = ['Photos', 'Maps', 'Meet', 'Drive', 'Play', 'Chrome', 'Gmail', 'Youtube'];

function getActorCountry(p) {
    const geoVotes = {};

    // Weighted voting function
    function vote(country, weight = 1) {
        if (country) {
            const c = country.toLowerCase().trim();
            // Normalize country names
            const normalized = {
                'ukraine': 'ua',  'ua': 'ua',
                'russia': 'ru',  'russian federation': 'ru', 'ru': 'ru',
                'belarus': 'by',  'by': 'by',
                'kazakhstan': 'kz',  'kz': 'kz',
                'united states': 'us', 'usa': 'us', 'us': 'us',
            }[c] || c;
            if (normalized && normalized.length === 2) {
                geoVotes[normalized] = (geoVotes[normalized] || 0) + weight;
            }
        }
    }

    // 1. WHOIS contacts - weight 5
    if (p.contacts?.length) {
        p.contacts.forEach(c => {
            if (c.country) vote(c.country, 5);
        });
    }

    // 2. Phone numbers - weight 4
    const phones = dedupePhones(p.leak_intel?.phones || []);
    phones.forEach(ph => {
        const phoneCountry = getCountryFromPhone(ph.phone);
        if (phoneCountry) vote(phoneCountry, 4);
    });

    // 3. Leak sources with .ua/.ru - weight 3
    const allSources = [];
    if (p.leak_extended?.databases) {
        p.leak_extended.databases.forEach(db => {
            if (db.database) allSources.push(db.database);
            if (db.source) allSources.push(db.source);
        });
    }
    if (p.leak_intel?.phones) {
        p.leak_intel.phones.forEach(ph => ph.source && allSources.push(ph.source));
    }
    if (p.leak_intel?.ips) {
        p.leak_intel.ips.forEach(ip => ip.source && allSources.push(ip.source));
    }

    // Check sources for country domains
    allSources.forEach(src => {
        const srcLower = src.toLowerCase();
        if (srcLower.includes('.ua') || srcLower.includes('_ua')) vote('ua', 3);
        else if (srcLower.includes('.ru') || srcLower.includes('_ru')) vote('ru', 3);
        else if (srcLower.includes('.by') || srcLower.includes('_by')) vote('by', 3);
        else if (srcLower.includes('.kz') || srcLower.includes('_kz')) vote('kz', 3);
    });

    // 4. Known local services - weight 2
    for (const src of allSources) {
        const srcLower = src.toLowerCase().replace(/[\s_\-]/g, '');
        for (const [key, country] of Object.entries(GEO_SOURCES)) {
            if (srcLower.includes(key.toLowerCase().replace(/[\s_\-]/g, ''))) {
                vote(country, 2);
            }
        }
    }

    // 5. IP providers from cache - weight 2
    if (p.leak_intel?.ips?.length) {
        p.leak_intel.ips.forEach(ip => {
            const ipInfo = ipCache.get(ip.ip);
            if (ipInfo?.country) vote(ipInfo.country, 2);
            // Ukrainian ISPs
            if (ip.source) {
                const src = ip.source.toLowerCase();
                if (src.includes('volia') || src.includes('kharkov') || src.includes('kharkiv') ||
                    src.includes('kyiv') || src.includes('kiev') || src.includes('triolan') ||
                    src.includes('ukr') || src.includes('datagroup')) {
                    vote('ua', 3);
                }
            }
        });
    }

    // 6. Google geolocation - weight 1
    if (p.user_geo?.countries?.[0]) vote(p.user_geo.countries[0], 1);

    // 7. Domain hosting - weight 1
    if (p.domain_cards?.[0]?.country) vote(p.domain_cards[0].country, 1);

    // Select country with max weight
    if (Object.keys(geoVotes).length) {
        const sorted = Object.entries(geoVotes).sort((a, b) => b[1] - a[1]);
        return sorted[0][0];
    }

    return '';
}

// Check if actor has Android
function hasAndroid(p) {
    if (p.google?.uses_android) return true;
    if (p.google?.android_services?.length) return true;
    if (p.google?.services?.some(s => ANDROID_INDICATORS.includes(s))) return true;
    return false;
}

// Get actor services list for display
function getActorServices(p) {
    const services = [];
    if (p.google?.services?.length) {
        services.push(...p.google.services);
    }
    return [...new Set(services)];
}

// Get phishing sources from blacklist
function getPhishingSources(blacklist) {
    if (!blacklist?.length) return { icon: ICONS.phishing, text: 'Unknown' };

    const sources = new Set();
    blacklist.forEach(b => {
        if (b.sources) b.sources.forEach(s => sources.add(s));
    });

    const srcList = [...sources];

    // Select icon by priority
    if (srcList.includes('MetaMask')) {
        return { icon: ICONS.metamask, text: srcList.join(', ') };
    }
    if (srcList.includes('SEAL')) {
        return { icon: ICONS.seal, text: srcList.join(', ') };
    }

    return { icon: ICONS.phishing, text: srcList.join(', ') || 'Blacklist' };
}

// Get domain registrar
function getRegistrar(domainCard) {
    if (!domainCard?.whois) return null;
    const w = domainCard.whois;
    return w.registrar || w.Registrar || null;
}

// IP info cache
const ipCache = new Map();

// Check IP via ip-api.com (free, 45 req/min)
async function lookupIP(ip) {
    if (!ip) return null;
    if (ipCache.has(ip)) return ipCache.get(ip);

    try {
        const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,isp,org,mobile,proxy,hosting`);
        const data = await res.json();

        if (data.status === 'success') {
            const result = {
                ip: ip,
                country: data.countryCode?.toLowerCase(),
                countryName: data.country,
                isp: data.isp,
                org: data.org,
                isMobile: data.mobile,
                isProxy: data.proxy || data.hosting,
                isHosting: data.hosting,
                loaded: true
            };
            ipCache.set(ip, result);
            return result;
        }
    } catch (e) {
        console.warn('IP lookup failed:', ip, e);
    }

    const fallback = { ip, loaded: false };
    ipCache.set(ip, fallback);
    return fallback;
}

// Batch lookup for multiple IPs
async function lookupIPsBatch(ips) {
    const toFetch = ips.filter(ip => !ipCache.has(ip)).slice(0, 100);
    if (!toFetch.length) return;

    try {
        const res = await fetch('http://ip-api.com/batch?fields=status,query,country,countryCode,isp,org,mobile,proxy,hosting', {
            method: 'POST',
            body: JSON.stringify(toFetch.map(ip => ({ query: ip })))
        });
        const results = await res.json();

        results.forEach(data => {
            if (data.status === 'success') {
                ipCache.set(data.query, {
                    ip: data.query,
                    country: data.countryCode?.toLowerCase(),
                    countryName: data.country,
                    isp: data.isp,
                    org: data.org,
                    isMobile: data.mobile,
                    isProxy: data.proxy || data.hosting,
                    isHosting: data.hosting,
                    loaded: true
                });
            }
        });
    } catch (e) {
        console.warn('Batch IP lookup failed:', e);
    }
}

// Get IP info from cache or return placeholder
function getIPInfo(ip) {
    return ipCache.get(ip) || { ip, loaded: false };
}

// Render IP with info
function renderIPRow(ipObj, showSource = true) {
    const ip = ipObj.ip || ipObj;
    const source = ipObj.source || '';
    const info = getIPInfo(ip);

    let tags = '';
    let ispText = '';
    let flagHtml = '';

    if (info.loaded) {
        // Country flag
        if (info.country) {
            flagHtml = `<span class="fi fi-${info.country}"></span>`;
        }

        // IP type
        if (info.isProxy || info.isHosting) {
            tags = '<span class="ip-tag proxy">Proxy/VPN</span>';
        } else if (info.isMobile) {
            tags = '<span class="ip-tag mobile">Mobile</span>';
        } else {
            tags = '<span class="ip-tag residential">Residential</span>';
        }

        // ISP/Operator
        if (info.isp) {
            ispText = `<span class="ip-isp">${esc(info.isp)}</span>`;
        }
    } else {
        tags = '<span class="ip-tag loading">...</span>';
    }

    return `<div class="ip-row" data-ip="${esc(ip)}">
        ${flagHtml}
        ${tags}
        <code>${esc(ip)}</code>
        ${ispText}
        ${showSource && source ? `<small class="ip-source">${esc(source)}</small>` : ''}
    </div>`;
}

function getInitial(email) {
    return (email || 'U')[0].toUpperCase();
}

// Emoji flag by country code
function getCountryEmoji(code) {
    if (!code || code.length !== 2) return '';
    const offset = 127397;
    return String.fromCodePoint(...code.toUpperCase().split('').map(c => c.charCodeAt(0) + offset));
}

function getFlag(code) {
    if (!code) return '';
    const map = {
        'nigeria': 'ng', 'united states': 'us', 'usa': 'us', 'united kingdom': 'gb', 'uk': 'gb',
        'germany': 'de', 'france': 'fr', 'spain': 'es', 'italy': 'it', 'netherlands': 'nl',
        'russia': 'ru', 'russian federation': 'ru', 'china': 'cn', 'japan': 'jp', 'india': 'in', 'brazil': 'br',
        'canada': 'ca', 'australia': 'au', 'south africa': 'za', 'ghana': 'gh', 'kenya': 'ke',
        'singapore': 'sg', 'hong kong': 'hk', 'malaysia': 'my', 'indonesia': 'id', 'philippines': 'ph',
        'turkey': 'tr', 'poland': 'pl', 'ukraine': 'ua', 'romania': 'ro', 'czech': 'cz', 'czech republic': 'cz',
        'sweden': 'se', 'norway': 'no', 'denmark': 'dk', 'finland': 'fi', 'ireland': 'ie',
        'switzerland': 'ch', 'austria': 'at', 'belgium': 'be', 'portugal': 'pt', 'greece': 'gr',
        'mexico': 'mx', 'argentina': 'ar', 'colombia': 'co', 'chile': 'cl', 'peru': 'pe',
        'egypt': 'eg', 'morocco': 'ma', 'uae': 'ae', 'united arab emirates': 'ae', 'saudi arabia': 'sa',
        'israel': 'il', 'pakistan': 'pk', 'bangladesh': 'bd', 'vietnam': 'vn', 'thailand': 'th',
        'korea': 'kr', 'south korea': 'kr', 'taiwan': 'tw', 'new zealand': 'nz',
        'kazakhstan': 'kz', 'belarus': 'by', 'uzbekistan': 'uz', 'georgia': 'ge', 'armenia': 'am',
        'azerbaijan': 'az', 'moldova': 'md', 'latvia': 'lv', 'lithuania': 'lt', 'estonia': 'ee',
    };
    let c = code.toLowerCase().trim();
    c = map[c] || (c.length === 2 ? c : '');
    if (!c) return '';
    return `<span class="fi fi-${c}"></span>`;
}

// Determine country by phone prefix
function getCountryFromPhone(phone) {
    if (!phone) return null;
    const num = String(phone).replace(/\D/g, '');
    if (!num || num.length < 10) return null;

    // Check specific long prefixes first
    // Russia: 7 (mobile starts with 79, 78)
    // Kazakhstan: 77
    // USA/Canada: 1

    // Russian numbers: 7 + 9xx (11 digits)
    if (num.startsWith('7') && num.length === 11) {
        const secondDigit = num[1];
        // 79, 78, 74, 73, 72 - Russia
        // 77 - Kazakhstan
        if (secondDigit === '7') return 'kz';
        return 'ru';
    }

    // If starts with 8 and 11 digits - Russia (8 = 7)
    if (num.startsWith('8') && num.length === 11) {
        return 'ru';
    }

    // Ukraine: 380 (12 digits)
    if (num.startsWith('380') && num.length === 12) return 'ua';

    // Belarus: 375 (12 digits)
    if (num.startsWith('375') && num.length === 12) return 'by';

    // USA/Canada: 1 (11 digits)
    if (num.startsWith('1') && num.length === 11) return 'us';

    // Other countries by prefix
    const prefixes = [
        // 3-digit
        ['998', 'uz'], ['995', 'ge'], ['994', 'az'], ['374', 'am'], ['373', 'md'],
        ['371', 'lv'], ['370', 'lt'], ['372', 'ee'], ['234', 'ng'], ['233', 'gh'],
        ['254', 'ke'], ['212', 'ma'], ['971', 'ae'], ['966', 'sa'], ['972', 'il'],
        ['880', 'bd'], ['351', 'pt'], ['358', 'fi'], ['353', 'ie'], ['420', 'cz'],
        ['421', 'sk'], ['386', 'si'], ['385', 'hr'], ['381', 'rs'], ['359', 'bg'],
        // 2-digit
        ['44', 'gb'], ['49', 'de'], ['33', 'fr'], ['39', 'it'], ['34', 'es'],
        ['31', 'nl'], ['48', 'pl'], ['40', 'ro'], ['90', 'tr'], ['86', 'cn'],
        ['81', 'jp'], ['82', 'kr'], ['91', 'in'], ['55', 'br'], ['52', 'mx'],
        ['27', 'za'], ['20', 'eg'], ['92', 'pk'], ['84', 'vn'], ['66', 'th'],
        ['62', 'id'], ['60', 'my'], ['63', 'ph'], ['65', 'sg'], ['61', 'au'],
        ['64', 'nz'], ['41', 'ch'], ['43', 'at'], ['32', 'be'], ['30', 'gr'],
        ['46', 'se'], ['47', 'no'], ['45', 'dk'], ['36', 'hu'],
    ];

    for (const [prefix, country] of prefixes) {
        if (num.startsWith(prefix)) return country;
    }

    return null;
}

// Get flag by phone number
function getFlagForPhone(phoneObj) {
    // First try from data
    if (phoneObj?.country?.code) {
        return getFlag(phoneObj.country.code);
    }
    // Otherwise determine by number
    const phone = typeof phoneObj === 'string' ? phoneObj : phoneObj?.phone;
    const countryCode = getCountryFromPhone(phone);
    if (countryCode) {
        return `<span class="fi fi-${countryCode}"></span>`;
    }
    return '';
}

// Dedupe phones
function dedupePhones(phones) {
    if (!phones || !phones.length) return [];
    const seen = new Set();
    return phones.filter(ph => {
        const num = String(ph.phone || ph).replace(/\D/g, '');
        if (seen.has(num)) return false;
        seen.add(num);
        return true;
    });
}

// Dedupe IPs
function dedupeIPs(ips) {
    if (!ips || !ips.length) return [];
    const seen = new Set();
    return ips.filter(ip => {
        const addr = ip.ip || ip;
        if (seen.has(addr)) return false;
        seen.add(addr);
        return true;
    });
}

// Dedupe WHOIS Contacts by name+phone+address
function dedupeContacts(contacts) {
    if (!contacts || !contacts.length) return [];
    const seen = new Map();
    
    contacts.forEach(c => {
        const name = (c.name || '').toLowerCase().trim();
        const phone = (c.phone || '').replace(/\D/g, '');
        const address = (c.address || '').toLowerCase().trim();
        const key = `${name}|${phone}|${address}`;
        
        if (!seen.has(key)) {
            seen.set(key, { ...c, count: 1 });
        } else {
            const existing = seen.get(key);
            existing.count++;
            if (!existing.company && c.company) existing.company = c.company;
            if (!existing.country && c.country) existing.country = c.country;
        }
    });
    
    return [...seen.values()];
}

function getFavicon(domain) {
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
}

function fmt(n) { return (n || 0).toLocaleString(); }
function setText(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; }
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

// Parse leak info string "Key: Value; Key2: Value2" into object
function parseLeakInfo(infoStr) {
    const result = {};
    if (!infoStr) return result;
    // Split by semicolon, then parse each key:value
    const parts = infoStr.split(';');
    for (const part of parts) {
        const idx = part.indexOf(':');
        if (idx > 0) {
            const key = part.slice(0, idx).trim();
            const value = part.slice(idx + 1).trim();
            if (key && value) result[key] = value;
        }
    }
    return result;
}

// ==================== THREAT FILTERS ====================
let allThreats = [];

function populateRegistrarFilter() {
    const select = document.getElementById('threat-registrar-filter');
    if (!select || !window.threatRegistrars) return;

    select.innerHTML = '<option value="all">All Registrars</option>';
    window.threatRegistrars.forEach(r => {
        select.innerHTML += `<option value="${esc(r)}">${esc(r.slice(0, 40))}</option>`;
    });
}

function filterThreats() {
    const container = document.getElementById('threats-container');
    const statsContainer = document.getElementById('threats-stats');
    if (!container) return;

    const typeFilter = document.getElementById('threat-type-filter')?.value || 'all';
    const registrarFilter = document.getElementById('threat-registrar-filter')?.value || 'all';
    const sortBy = document.getElementById('threat-sort')?.value || 'severity';

    // Filter
    let threats = [...allThreats];

    if (typeFilter !== 'all') {
        threats = threats.filter(t => t.type === typeFilter);
    }

    if (registrarFilter !== 'all') {
        threats = threats.filter(t => t.registrar === registrarFilter);
    }

    // Sort
    if (sortBy === 'severity') {
        threats.sort((a, b) => b.severity - a.severity);
    } else if (sortBy === 'date') {
        threats.sort((a, b) => {
            const dateA = a.created ? new Date(a.created) : new Date(0);
            const dateB = b.created ? new Date(b.created) : new Date(0);
            return dateB - dateA;
        });
    } else if (sortBy === 'registrar') {
        threats.sort((a, b) => (a.registrar || 'zzz').localeCompare(b.registrar || 'zzz'));
    }

    // Update stats
    if (statsContainer) {
        const malwareCount = threats.filter(t => t.type === 'malware').length;
        const phishingCount = threats.filter(t => t.type === 'phishing').length;
        const registrarsCount = new Set(threats.filter(t => t.registrar).map(t => t.registrar)).size;

        statsContainer.innerHTML = `
            <div class="ts-item danger"><span>${malwareCount}</span>Malware</div>
            <div class="ts-item warning"><span>${phishingCount}</span>Phishing</div>
            <div class="ts-item"><span>${registrarsCount}</span>Registrars</div>
            <div class="ts-item"><span>${threats.length}</span>Total</div>
        `;
    }

    // Render
    if (!threats.length) {
        container.innerHTML = '<div class="empty-state"><h3>No threats match filters</h3></div>';
        return;
    }

    container.innerHTML = threats.map((t, idx) => {
        const actorName = t.actor.leak_intel?.real_names?.[0] || '';
        const sourceIcon = t.type === 'malware' ? ICONS.virustotal : (t.sources?.includes('MetaMask') ? ICONS.metamask : (t.sources?.includes('SEAL') ? ICONS.seal : ICONS.phishing));
        const sourceText = t.type === 'malware' ? 'VirusTotal' : (t.sources?.slice(0,2).join(', ') || 'Blacklist');

        return `
            <div class="domain-threat ${t.type}" style="animation-delay: ${idx * 0.05}s" onclick="openProfile('${esc(t.actor.email)}')">
                <div class="dt-visual ${!t.screenshot ? 'no-screenshot' : ''}" onclick="event.stopPropagation(); ${t.screenshot ? `openModal('${esc(t.screenshot)}', '${esc(t.domain)}')` : ''}">
                    ${t.screenshot ?
                        `<img src="${esc(t.screenshot)}" loading="lazy" onerror="this.parentElement.classList.add('no-screenshot'); this.nextElementSibling.style.display='flex'; this.remove();">
                         <div class="dt-no-img" style="display:none"><span>No Preview</span></div>` :
                        `<div class="dt-no-img"><span>No Preview</span></div>`}
                    <div class="dt-badges">
                        <span class="dt-type ${t.type}">${t.type.toUpperCase()}</span>
                        <span class="dt-source">${sourceIcon} ${sourceText}</span>
                    </div>
                    ${t.type === 'malware' && t.detections ? `<span class="dt-detections">${t.detections}/${t.total || 70}</span>` : ''}
                    <div class="dt-overlay"><span>View Screenshot</span></div>
                </div>
                <div class="dt-info">
                    <div class="dt-domain">
                        <img src="${getFavicon(t.domain)}" onerror="this.style.display='none'">
                        <span>${esc(t.domain)}</span>
                    </div>
                    ${t.country || t.ip ? `<div class="dt-location">${t.country ? getFlag(t.country) : ''} ${t.ip || ''}</div>` : ''}
                    ${t.registrar ? `<div class="dt-registrar">${ICONS.domain} ${esc(t.registrar.slice(0, 35))}</div>` : ''}
                    ${t.created ? `<div class="dt-created">${ICONS.link} ${esc(formatDate(t.created))}</div>` : ''}
                    <div class="dt-actor">
                        ${t.actor.google?.photo ? `<img src="${esc(t.actor.google.photo)}" onerror="this.remove()">` : `<span class="dt-actor-initial">${getInitial(t.actor.email)}</span>`}
                        <span>${actorName ? esc(actorName) + ' · ' : ''}${esc(t.actor.email)}</span>
                    </div>
                    <div class="dt-actions" onclick="event.stopPropagation()">
                        <a href="https://www.virustotal.com/gui/domain/${encodeURIComponent(t.domain)}" target="_blank" class="btn-sm">${ICONS.virustotal} VT</a>
                        <a href="https://urlscan.io/search/#${encodeURIComponent(t.domain)}" target="_blank" class="btn-sm">${ICONS.screenshot} Scan</a>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}
window.filterThreats = filterThreats;

function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
        const d = new Date(dateStr);
        if (isNaN(d.getTime())) return dateStr;
        return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
        return dateStr;
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        closeModal();
        closeActorModal();
    }
});