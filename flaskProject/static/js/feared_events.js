/**
 * @fileoverview Feared events display and filtering module.
 * 
 * This module provides functionality for displaying feared events (both original and propagated)
 * with interactive filtering, sorting capabilites, and dynamic risk-based color coding.
 * Feared events are displayed in a card-based grid layout with comprehensive details including
 * probability, impact, affected assets, and generated risks.
 * 
 * Features:
 *   - Toggle filter to show only original feared events vs. combined feared events
 *   - Dynamic risk-based background colors fetched from backend
 *   - Scroll position persistence across navigation
 *   - Feared event highlighting with smooth scroll behavior
 *   - Page visibility management for performance
 * 
 * Dependencies:
 *   - Backend: /risk_color/<value> endpoint for color mapping (1-50 risk scale)
 *   - Jinja2/Flask template variables: fearedEventParam (passed from template)
 * 
 * @requires none (vanilla JavaScript)
 */

// ===== FILTER & NAVIGATION FUNCTIONS =====

/**
 * Toggle filter to show only original feared events.
 * 
 * When enabled, navigates to the feared_events page with filter_original=true parameter,
 * which causes the backend to filter the list to only original feared events.
 * When disabled, navigates without the filter parameter to show combined list.
 * 
 * Interaction Flow:
 *   1. User clicks toggle checkbox
 *   2. Function reads checkbox state
 *   3. Constructs URL with or without filter_original parameter
 *   4. Full page navigation triggers (could be optimized with AJAX)
 * 
 * Time Complexity: O(1) - simple URL navigation
 * Side Effects: Full page reload
 * 
 * @function toggleOriginalFilter
 * @return {void} Navigates to new page URL
 * 
 * @example
 *   // User clicks toggle - function is invoked
 *   // Checkbox checked -> navigates to: /feared_events?filter_original=true
 *   // Checkbox unchecked -> navigates to: /feared_events
 */
function toggleOriginalFilter() {
    const isChecked = document.getElementById('filterOriginalToggle').checked;
    const baseUrl = "/feared_events";
    
    if (isChecked) {
        window.location.href = baseUrl + "?filter_original=true";
    } else {
        window.location.href = baseUrl;
    }
}

// ===== PAGE INITIALIZATION & STATE MANAGEMENT =====

/**
 * Initialize page state and handle highlight/scroll restoration on page load.
 * 
 * This event handler fires after all DOM elements are loaded and executes:
 *   1. Checks if a specific feared event should be highlighted (via fearedEventParam)
 *   2. If highlighting is needed: adds highlight class, scrolls to element, removes class after 3s
 *   3. Otherwise: Restores scroll position from localStorage to return user to previous view
 *   4. Sets page visibility to visible (was hidden until page ready via CSS)
 * 
 * Scroll Position Persistence:
 *   - On page unload: scroll position saved to localStorage
 *   - On page load: scroll position restored if no specific highlight is requested
 *   - Useful for maintaining user context when navigating back from detail views
 * 
 * Performance: O(1) - one DOM query and classList operation
 * Side Effects: Modifies DOM (adds/removes highlight class), sets window scroll position
 * 
 * @event DOMContentLoaded-like (attached to 'load' event)
 * @return {void}
 * 
 * @example
 *   // If fearedEventParam = "FE_001":
 *   // 1. Find element with id="FE_001"
 *   // 2. Add transform and shadow via .highlight class
 *   // 3. Scroll smoothly to center of viewport
 *   // 4. Remove highlight class after 3 seconds
 */
window.addEventListener('load', () => {
    const fe = typeof fearedEventParam !== 'undefined' ? fearedEventParam : "";
    const scrollPos = localStorage.getItem("scrollPos");
    if (fe) {
        const row = document.getElementById(fe);
        if (row) {
            row.classList.add("highlight");
            row.scrollIntoView({ behavior: "smooth", block: "center" });
            setTimeout(() => {
                row.classList.remove("highlight");
            }, 3000);
        }
    } else if (scrollPos) {
        window.scrollTo(0, parseInt(scrollPos, 10));
        localStorage.removeItem("scrollPos"); 
    }
    document.body.style.visibility = "visible";
});

/**
 * Save current scroll position to localStorage before page unload.
 * 
 * This allows the page to restore the user's view when they navigate away and return.
 * For example, when clicking on a feared event to view details then using browser back button.
 * 
 * Timing: Fires on beforeunload event (user navigating away)
 * Storage: Uses browser's localStorage (persistent across session)
 * Performance: O(1) - simple localStorage write
 * 
 * @event beforeunload
 * @return {void} Saves to localStorage, no page interruption
 * 
 * @example
 *   // Before user navigates to another page:
 *   // Save current scroll position (e.g., 450px down page)
 *   // When they return: restored to 450px position
 */
window.addEventListener("beforeunload", () => {
    localStorage.setItem("scrollPos", window.scrollY);
});

// ===== STYLING & COLOR MAPPING =====

/**
 * Get color based on probability value (1-5 scale).
 * 
 * Color Mapping:
 *   1: #00AA00 (Green - Low probability)
 *   2: #55DD00 (Light Green)
 *   3: #FFDD00 (Yellow - Medium probability)
 *   4: #FF9900 (Orange - High probability)
 *   5: #DD0000 (Red - Very high probability)
 * 
 * @param {number} value - Probability value (1-5)
 * @return {string} Hex color code
 */
function getProbabilityColor(value) {
    const probabilityColors = {
        1: '#00AA00',
        2: '#55DD00',
        3: '#FFDD00',
        4: '#FF9900',
        5: '#DD0000'
    };
    return probabilityColors[value] || '#CCCCCC';
}

/**
 * Get color based on impact value (1-10 scale).
 * 
 * Color Mapping:
 *   1-2: #00AA00 (Green - Low impact)
 *   3-4: #55DD00 (Light Green)
 *   5-6: #FFDD00 (Yellow - Medium impact)
 *   7-8: #FF9900 (Orange - High impact)
 *   9-10: #DD0000 (Red - Very high impact)
 * 
 * @param {number} value - Impact value (1-10)
 * @return {string} Hex color code
 */
function getImpactColor(value) {
    if (value <= 2) return '#00AA00';
    if (value <= 4) return '#55DD00';
    if (value <= 6) return '#FFDD00';
    if (value <= 8) return '#FF9900';
    if (value <= 10) return '#DD0000';
    return '#CCCCCC';
}

/**
 * Apply semantic risk-based background colors to probability and impact elements.
 * 
 * Distinguishes between probability (1-5 scale) and impact (1-10 scale) elements
 * using CSS classes and applies appropriate color gradients:
 *   - Green (low severity) → Yellow (medium) → Orange (high) → Red (critical)
 * 
 * Elements targeted by class:
 *   .probability: Applies probability color mapping (1-5)
 *   .impact: Applies impact color mapping (1-10)
 * 
 * Color Application:
 *   - Local computation (no backend fetch needed)
 *   - Immediate application on page load
 *   - Consistent with risk assessment methodology
 * 
 * Performance:
 *   - Time: O(n) where n = number of elements
 *   - Synchronous (faster than async fetches)
 */

// Apply colors to probability elements (1-5 scale)
document.querySelectorAll('.probability').forEach(element => {
    const value = parseInt(element.textContent.trim(), 10);
    if (!isNaN(value) && value >= 1 && value <= 5) {
        element.style.backgroundColor = getProbabilityColor(value);
    } else {
        element.style.backgroundColor = '#CCCCCC';
    }
});

// Apply colors to impact elements (1-10 scale)
document.querySelectorAll('.impact').forEach(element => {
    const value = parseInt(element.textContent.trim(), 10);
    if (!isNaN(value) && value >= 1 && value <= 10) {
        element.style.backgroundColor = getImpactColor(value);
    } else {
        element.style.backgroundColor = '#CCCCCC';
    }
});
