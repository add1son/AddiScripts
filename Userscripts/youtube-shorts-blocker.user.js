// ==UserScript==
// @name         YouTube Shorts & Distraction Blocker
// @namespace    https://github.com/add1son/
// @version      1.0.0
// @description  Removes YouTube Shorts, navigation links, and shelves across desktop and mobile. Includes optional focus/minimalist toggles.
// @author       Add1son
// @match        https://www.youtube.com/*
// @match        https://m.youtube.com/*
// @run-at       document-start
// @grant        GM_addStyle
// ==/UserScript==

(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // Configuration / Focus Toggles (Set to true to activate minimalist mode)
    // -------------------------------------------------------------------------
    const CONFIG = {
        hideHomeFeed: false,   // Blank out the homepage feed (search-only mode)
        hideWatchSidebar: false, // Hide recommendations sidebar on watch page
        hideComments: false,   // Hide comments entirely
        hideEndScreen: false   // Hide end-screen video tiles
    };

    // -------------------------------------------------------------------------
    // Static CSS Injection
    // -------------------------------------------------------------------------
    let cssRules = `
        /* Hide Shorts Shelves & Carousels */
        ytd-reel-shelf-renderer,
        ytm-reel-shelf-renderer,
        ytd-rich-section-renderer:has(ytd-rich-grid-slim-media[is-short]),
        ytd-rich-section-renderer:has(ytd-reel-shelf-renderer) {
            display: none !important;
        }

        /* Hide Sidebar / Pivot Bar Shorts Tabs */
        ytd-guide-entry-renderer:has(a[href^="/shorts"]),
        ytd-mini-guide-entry-renderer:has(a[href^="/shorts"]),
        ytm-pivot-bar-item-renderer:has(.pivot-shorts, a[href^="/shorts"]) {
            display: none !important;
        }

        /* Hide Standalone Shorts Containers via CSS :has */
        ytd-rich-item-renderer:has(a[href*="/shorts/"]),
        ytd-video-renderer:has(a[href*="/shorts/"]),
        ytd-grid-video-renderer:has(a[href*="/shorts/"]),
        ytd-compact-video-renderer:has(a[href*="/shorts/"]),
        ytm-video-with-context-renderer:has(a[href*="/shorts/"]),
        ytm-compact-video-renderer:has(a[href*="/shorts/"]) {
            display: none !important;
        }
    `;

    if (CONFIG.hideHomeFeed) {
        cssRules += `
            ytd-browse[page-subtype="home"] #primary { display: none !important; }
        `;
    }
    if (CONFIG.hideWatchSidebar) {
        cssRules += `
            #secondary.ytd-watch-flexy { display: none !important; }
        `;
    }
    if (CONFIG.hideComments) {
        cssRules += `
            #comments { display: none !important; }
        `;
    }
    if (CONFIG.hideEndScreen) {
        cssRules += `
            .ytp-endscreen-content, .videowall-endscreen { display: none !important; }
        `;
    }

    if (typeof GM_addStyle !== 'undefined') {
        GM_addStyle(cssRules);
    } else {
        const style = document.createElement('style');
        style.type = 'text/css';
        style.textContent = cssRules;
        (document.head || document.documentElement).appendChild(style);
    }

    // -------------------------------------------------------------------------
    // Dynamic DOM Purge (Fallback for browsers/nodes where :has delays)
    // -------------------------------------------------------------------------
    const removeShortsNodes = () => {
        // Purge sidebar & nav links
        document.querySelectorAll('a[href^="/shorts"]').forEach(link => {
            const navParent = link.closest('ytd-guide-entry-renderer, ytd-mini-guide-entry-renderer, ytm-pivot-bar-item-renderer');
            if (navParent) navParent.remove();
        });

        // Purge video cards containing shorts links
        document.querySelectorAll('a[href*="/shorts/"]').forEach(link => {
            const cardParent = link.closest('ytd-rich-item-renderer, ytd-video-renderer, ytd-grid-video-renderer, ytd-compact-video-renderer, ytm-video-with-context-renderer, ytm-compact-video-renderer');
            if (cardParent) cardParent.remove();
        });

        // Purge leftover reel containers
        document.querySelectorAll('ytd-reel-shelf-renderer, ytm-reel-shelf-renderer').forEach(shelf => shelf.remove());
    };

    // Debounce mutations to avoid performance degradation during rapid scrolling
    let debounceTimeout = null;
    const observer = new MutationObserver(() => {
        if (debounceTimeout) clearTimeout(debounceTimeout);
        debounceTimeout = setTimeout(removeShortsNodes, 80);
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    window.addEventListener('DOMContentLoaded', removeShortsNodes);
})();