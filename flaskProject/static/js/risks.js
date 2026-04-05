/**
 * @fileoverview Risks display, filtering, and system indicators module.
 * 
 * This module provides functionality for displaying system risk indicators and potential risks
 * with dynamic risk-based color coding fetched from the backend. It supports filtering between
 * all risks (original + propagated) and original-only risks, with automatic color mapping based
 * on numeric risk values (1-50 scale).
 * 
 * Features:
 *   - Display system-level risk indicators (Risk Level and Propagated Risk Level)
 *   - Toggle filter to show only original risks vs. combined risks
 *   - Dynamic risk-based background colors fetched from backend
 *   - Scroll position persistence across navigation
 *   - Risk row highlighting with smooth scroll behavior
 *   - Page visibility management during color fetching
 * 
 * Dependencies:
 *   - Backend: /risk_color/<value> endpoint for color mapping (1-50 risk scale)
 *   - Jinja2/Flask template variables: systemData, riskParam (passed from template)
 * 
 * @requires none (vanilla JavaScript)
 */

// ===== COLOR FETCHING FUNCTIONS =====

/**
 * Fetch risk color from backend based on numeric risk value.
 * 
 * Makes async request to /risk_color/<value> endpoint to get hex color code
 * corresponding to the risk value. Uses backend's centralized color mapping
 * to ensure consistency across the application.
 * 
 * Time Complexity: O(1) - single endpoint call
 * Space Complexity: O(1) - returns single hex color string
 * 
 * @async
 * @function getRiskColor
 * @param {number} riskValue - Risk value (1-50 scale, any out-of-range returns gray)
 * @return {Promise<string>} Hex color code (e.g., "#FF5500") or "#CCCCCC" on error
 * 
 * @example
 *   const color = await getRiskColor(15);
 *   // Returns "#FF5500" (high risk orange)
 */
async function getRiskColor(riskValue) {
    try {
        const response = await fetch(`/risk_color/${riskValue}`);
        if (response.ok) {
            return await response.text();
        }
    } catch (error) {
        console.error('Error fetching risk color:', error);
    }
    return "#CCCCCC";
}

// ===== INDICATOR & DISPLAY FUNCTIONS =====

/**
 * Update system risk level indicators with values and colors.
 * 
 * Populates the two main indicators (Risk Level and Propagated Risk Level) with
 * the system's current risk values and applies color-coded backgrounds based on
 * fetched colors from the backend.
 * 
 * Time Complexity: O(1) - two color fetches (can be awaited in parallel)
 * Side Effects: Updates DOM elements, sets page visibility when complete
 * 
 * @async
 * @function updateIndicators
 * @return {Promise<void>}
 * 
 * @example
 *   await updateIndicators();
 *   // Risk Level indicator: "15" with orange background
 *   // Propagated Risk Level indicator: "22" with red background
 */
async function updateIndicators() {
    const system = window.systemData;
    
    if (system) {
        const riskLevelEl = document.getElementById('RLIndicator');
        const propagatedRiskLevelEl = document.getElementById('PRLIndicator');
        
        if (riskLevelEl) {
            riskLevelEl.textContent = system.risk_level || 'N/A';
            const color = await getRiskColor(system.risk_level);
            riskLevelEl.style.backgroundColor = color;
        }
        
        if (propagatedRiskLevelEl) {
            propagatedRiskLevelEl.textContent = system.propagated_risk_level || 'N/A';
            const color = await getRiskColor(system.propagated_risk_level);
            propagatedRiskLevelEl.style.backgroundColor = color;
        }
    }
    
    document.body.style.visibility = "visible";
}

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
 * Colorize risk level cells and probability/impact cells in the table.
 * 
 * Applies semantic colors to table cells based on their type:
 *   - .probability: Uses probability color mapping (1-5 scale)
 *   - .impact: Uses impact color mapping (1-10 scale)
 *   - .level (risk_level): Fetches color from backend (1-50 scale)
 * 
 * This provides visual risk assessment at a glance for each risk row with
 * appropriate color gradients for each metric type.
 * 
 * Time Complexity: O(n) where n is number of risk cells + async fetches for risk levels
 * Space Complexity: O(1) - modifies elements in-place
 * 
 * @async
 * @function colorizeRiskLevels
 * @return {Promise<void>}
 * 
 * @example
 *   await colorizeRiskLevels();
 *   // Probability cells: colored 1-5 scale (green to red)
 *   // Impact cells: colored 1-10 scale (green to red)
 *   // Risk level cells: fetched from backend (1-50 scale)
 */
async function colorizeRiskLevels() {
    // Apply probability colors (1-5 scale)
    document.querySelectorAll('.probability').forEach(element => {
        const value = parseInt(element.textContent.trim(), 10);
        if (!isNaN(value) && value >= 1 && value <= 5) {
            element.style.backgroundColor = getProbabilityColor(value);
        } else {
            element.style.backgroundColor = '#CCCCCC';
        }
    });

    // Apply impact colors (1-10 scale)
    document.querySelectorAll('.impact').forEach(element => {
        const value = parseInt(element.textContent.trim(), 10);
        if (!isNaN(value) && value >= 1 && value <= 10) {
            element.style.backgroundColor = getImpactColor(value);
        } else {
            element.style.backgroundColor = '#CCCCCC';
        }
    });

    // Apply risk level colors (1-50 scale, fetched from backend)
    const levelElements = document.querySelectorAll('.level:not(.probability):not(.impact)');
    for (const element of levelElements) {
        const risk_level = element.textContent.trim();
        const color = await getRiskColor(risk_level);
        element.style.backgroundColor = color;
    }
}

// ===== SCROLL & HIGHLIGHT FUNCTIONS =====

/**
 * Handle scroll restoration and risk row highlighting.
 * 
 * Manages two scenarios:
 * 1. If a specific risk is passed (from feared_events', navigate to this risk),
 *    highlights it with visual effect and smooth scroll
 * 2. Otherwise, restores previous scroll position from localStorage
 * 
 * Time Complexity: O(1) for scroll, O(n) for DOM search (if highlighting specific risk)
 * Side Effects: Modifies scroll position, adds/removes highlight class
 * 
 * @function handleScrollAndHighlight
 * @return {void}
 * 
 * @example
 *   // Scenario 1: User navigated from feared_events and selected a risk
 *   window.riskParam = "PR_Original_001"
 *   // Result: Row with ID "PR_Original_001" highlighted and scrolled into view
 *   
 *   // Scenario 2: User returned to risks page
 *   // Result: Previously saved scroll position is restored
 */
function handleScrollAndHighlight() {
    const risk = window.riskParam;
    const scrollPos = localStorage.getItem("scrollPos");
    if (risk) {
        const row = document.getElementById(risk);
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
}

// ===== FILTER & NAVIGATION FUNCTIONS =====

/**
 * Toggle filter to show only original risks.
 * 
 * When enabled, navigates to the risks page with filter_original=true parameter,
 * which causes the backend to filter the list to only original risks.
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
 *   // Checkbox checked -> navigates to: /risks?filter_original=true
 *   // Checkbox unchecked -> navigates to: /risks
 */
function toggleOriginalFilter() {
    const params = new URLSearchParams(window.location.search);
    const filterCheckbox = document.getElementById('filterOriginalToggle');
    if (filterCheckbox.checked) {
        params.set('filter_original', 'true');
    } else {
        params.delete('filter_original');
    }
    window.location.search = params.toString();
}

// ===== INITIALIZATION & EVENT LISTENERS =====

/**
 * Initialize all page functionality on load.
 * 
 * Execution Order (important for visual presentation):
 *   1. updateIndicators() - Display system risk values and colors
 *   2. handleScrollAndHighlight() - Restore scroll or highlight specific risk
 *   3. colorizeRiskLevels() - Colorize all table cells
 * 
 * The final step (colorizeRiskLevels) completes before making the page visible
 * to avoid unstyled content flash (FOUC).
 * 
 * addEventListener('beforeunload') saves scroll position for restoration on return.
 */
window.addEventListener('load', updateIndicators);
window.addEventListener('load', handleScrollAndHighlight);
window.addEventListener('load', colorizeRiskLevels);

/**
 * Save current scroll position to localStorage before leaving page.
 * 
 * This allows users to return to approximately the same scroll position
 * when navigating back (from feared_events page, etc.).
 * 
 * Side Effects: Writes to localStorage["scrollPos"]
 */
window.addEventListener("beforeunload", () => {
    localStorage.setItem("scrollPos", window.scrollY);
});
