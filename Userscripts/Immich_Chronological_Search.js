// ==UserScript==
// @name         Immich Chronological Timeline Search
// @namespace    http://tampermonkey.net/
// @version      5.0
// @description  Renders a true Google Photos chronological date-grouped timeline on Immich search pages
// @match        http://YOUR_IMMICH_IP_OR_DOMAIN:PORT/*
// @match        https://photos.example.com/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==

/*
 * ============================================================================
 * SETUP INSTRUCTIONS FOR SELF-HOSTED INSTANCES:
 * ============================================================================
 * Update the @match line above with your Immich URL, keeping the trailing /*
 *
 * Examples:
 *   Local IP + Port:  // @match http://192.168.1.50:2283/*
 *   Reverse Proxy:    // @match https://immich.yourdomain.com/*
 *
 * PRO TIP (Survives Script Updates):
 * Instead of editing the code above, open this script in Tampermonkey, click
 * the "Settings" tab at the top, scroll to "Includes/Excludes" -> "User matches",
 * and add your URL there (e.g., http://192.168.1.50:2283/*).
 * ============================================================================
 */

(function() {
    'use strict';

    const TOP_K_CUTOFF = 150; // Keep top 150 ML matches before sorting by date
    let lastSearchUrl = '';

    // Extract timestamp from filename (YYYYMMDD_HHMMSS / YYYY-MM-DD) or EXIF
    function getBestTimestamp(asset) {
        const name = asset.originalFileName || asset.originalPath || '';
        const regex = /(20\d{2}|19\d{2})[-_]?([01]\d)[-_]?([0-3]\d)(?:[-_T]?([0-2]\d)[-_:]?([0-5]\d)[-_:]?([0-5]\d))?/;
        const match = name.match(regex);
        if (match) {
            const t = new Date(
                parseInt(match[1], 10),
                parseInt(match[2], 10) - 1,
                parseInt(match[3], 10),
                parseInt(match[4] || '0', 10),
                parseInt(match[5] || '0', 10),
                parseInt(match[6] || '0', 10)
            ).getTime();
            if (!isNaN(t)) return t;
        }
        const dateStr = asset.localDateTime || asset.fileCreatedAt || asset.createdAt || asset.updatedAt;
        return dateStr ? new Date(dateStr).getTime() : 0;
    }

    function formatDateHeader(timestamp) {
        if (!timestamp) return 'Unknown Date';
        const d = new Date(timestamp);
        return d.toLocaleDateString('en-US', {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    async function fetchSearchResults(queryObj) {
        // Try Smart Search endpoint first if query text exists, else Metadata endpoint
        const endpoints = ['/api/search/smart', '/api/search/metadata'];
        const payload = { ...queryObj, size: TOP_K_CUTOFF, page: 1 };

        for (const ep of endpoints) {
            try {
                const res = await fetch(ep, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    const data = await res.json();
                    const items = data?.assets?.items || data?.items || (Array.isArray(data) ? data : []);
                    if (items.length > 0) return items;
                }
            } catch (e) {
                console.warn('[Immich Timeline] Endpoint failed:', ep, e);
            }
        }
        return [];
    }

    function renderTimeline(items) {
        let container = document.getElementById('immich-chrono-timeline');
        if (!container) {
            container = document.createElement('div');
            container.id = 'immich-chrono-timeline';
            container.style.cssText = `
                position: fixed;
                top: 72px;
                left: 250px;
                right: 0;
                bottom: 0;
                background: #000000;
                color: #ffffff;
                overflow-y: auto;
                z-index: 999;
                padding: 24px 32px 80px 32px;
                font-family: system-ui, -apple-system, sans-serif;
            `;
            document.body.appendChild(container);
        }

        // Slice top K matches and sort newest to oldest
        const sorted = items.slice(0, TOP_K_CUTOFF).map(item => ({
            ...item,
            _ts: getBestTimestamp(item)
        })).sort((a, b) => b._ts - a._ts);

        // Group by Day (Google Photos style)
        const groups = new Map();
        for (const item of sorted) {
            const header = formatDateHeader(item._ts);
            if (!groups.has(header)) groups.set(header, []);
            groups.get(header).push(item);
        }

        let html = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:1px solid #333; padding-bottom:12px;">
                <div>
                    <span style="font-size:18px; font-weight:700; color:#4dabf7;">📅 Chronological Search Timeline</span>
                    <span style="font-size:13px; color:#aaa; margin-left:12px;">Top ${sorted.length} matches grouped by capture/filename date</span>
                </div>
                <button id="immich-chrono-toggle" style="background:#222; color:#fff; border:1px solid #555; padding:6px 14px; border-radius:6px; cursor:pointer; font-size:13px;">
                    Switch to Default Unsorted Grid
                </button>
            </div>
        `;

        for (const [dateHeader, assets] of groups.entries()) {
            html += `
                <div style="margin-bottom: 28px;">
                    <h3 style="font-size: 15px; font-weight: 600; color: #e9ecef; margin: 0 0 12px 0; letter-spacing: 0.3px;">
                        ${dateHeader} <span style="color:#666; font-weight:400; font-size:13px;">(${assets.length})</span>
                    </h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 10px;">
            `;

            for (const asset of assets) {
                const thumbUrl = `/api/assets/${asset.id}/thumbnail?size=thumbnail`;
                const fullUrl = `/api/assets/${asset.id}/original`;
                const fileName = asset.originalFileName || asset.id;
                const timeStr = new Date(asset._ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                html += `
                    <a href="${fullUrl}" target="_blank" title="${fileName}" style="position:relative; display:block; aspect-ratio:1/1; background:#141414; border-radius:6px; overflow:hidden; text-decoration:none; border:1px solid #262626;">
                        <img src="${thumbUrl}" loading="lazy" style="width:100%; height:100%; object-fit:cover; display:block;" />
                        <div style="position:absolute; bottom:0; left:0; right:0; background:linear-gradient(transparent, rgba(0,0,0,0.85)); padding:18px 8px 6px 8px; font-size:11px; color:#ddd; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                            <div style="font-weight:600; color:#fff;">${fileName}</div>
                            <div style="font-size:10px; color:#aaa;">${timeStr}</div>
                        </div>
                    </a>
                `;
            }

            html += `</div></div>`;
        }

        container.innerHTML = html;
        container.style.display = 'block';

        document.getElementById('immich-chrono-toggle').onclick = () => {
            container.style.display = 'none';
        };
    }

    async function checkRoute() {
        const currentUrl = window.location.href;
        if (!window.location.pathname.startsWith('/search')) {
            const existing = document.getElementById('immich-chrono-timeline');
            if (existing) existing.style.display = 'none';
            lastSearchUrl = '';
            return;
        }

        if (currentUrl === lastSearchUrl) return;
        lastSearchUrl = currentUrl;

        const params = new URLSearchParams(window.location.search);
        const rawQuery = params.get('query');
        if (!rawQuery) return;

        let queryObj = {};
        try {
            queryObj = JSON.parse(rawQuery);
        } catch (e) {
            queryObj = { query: rawQuery };
        }

        const items = await fetchSearchResults(queryObj);
        if (items.length > 0) {
            renderTimeline(items);
        }
    }

    // Poll URL changes every 600ms to catch both SSR refreshes and Svelte client routing
    setInterval(checkRoute, 600);
    checkRoute();
})();