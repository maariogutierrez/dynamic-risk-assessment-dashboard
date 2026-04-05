/**
 * @fileoverview Assets display and styling module.
 * 
 * This module provides functionality for displaying system assets in a table format.
 * Assets are displayed with their ID, type, description, importance, and risk level information.
 * 
 * Features:
 *   - Display assets in a sortable table
 *   - Sort by Asset ID, Type, Description, Importance, and Risk Levels
 *   - Dynamic risk-based color coding fetched from backend
 *   - Dynamic row highlighting on hover
 *   - Asset highlighting with smooth scroll behavior
 *   - Scroll position persistence across navigation
 *   - Page visibility management
 * 
 * Dependencies:
 *   - Backend: /risk_color/<value> endpoint for color mapping (1-50 risk scale)
 *   - Jinja2/Flask template: assets data passed from template (window.assetParam)
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

// ===== LEVEL COLORING FUNCTIONS =====

/**
 * Colorize all risk level cells in the table.
 * 
 * Iterates through all .level elements in the table (Risk Level, Propagated Risk Level,
 * and Relative Risk Level columns) and applies background colors based on their numeric values.
 * This provides visual risk assessment at a glance for each asset row.
 * 
 * Time Complexity: O(n) where n is number of risk cells
 * Space Complexity: O(1) - modifies elements in-place
 * 
 * @async
 * @function colorizeRiskLevels
 * @return {Promise<void>}
 * 
 * @example
 *   await colorizeRiskLevels();
 *   // All table cells with class .level now have appropriate background colors
 */
async function colorizeRiskLevels() {
    const elements = document.querySelectorAll('.level');
    for (const element of elements) {
        const risk_level = element.textContent.trim();
        const color = await getRiskColor(risk_level);
        element.style.backgroundColor = color;
    }
}

// ===== SCROLL & HIGHLIGHT FUNCTIONS =====

/**
 * Handle scroll restoration and asset row highlighting.
 * 
 * Manages two scenarios:
 * 1. If a specific asset is passed (from risks page), navigate to this asset,
 *    highlights it with visual effect and smooth scroll
 * 2. Otherwise, restores previous scroll position from localStorage
 * 
 * Time Complexity: O(1) for scroll, O(n) for DOM search (if highlighting specific asset)
 * Side Effects: Modifies scroll position, adds/removes highlight class
 * 
 * @function handleScrollAndHighlight
 * @return {void}
 * 
 * @example
 *   // Scenario 1: User navigated from risks and selected an asset
 *   window.assetParam = "Activo_1"
 *   // Result: Row with ID "Activo_1" highlighted and scrolled into view
 *   
 *   // Scenario 2: User returned to assets page
 *   // Result: Previously saved scroll position is restored
 */
function handleScrollAndHighlight() {
    const asset = window.assetParam ? window.assetParam.trim() : "";
    const scrollPos = localStorage.getItem("scrollPos");
    
    if (asset && asset.length > 0) {
        const row = document.getElementById(asset);
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

// ===== PAGE INITIALIZATION =====

/**
 * Initialize page visibility when DOM is loaded.
 * Shows the page once all resources are loaded and styles are applied.
 * 
 * @function initializePage
 * @return {void}
 */
function initializePage() {
    document.body.style.visibility = "visible";
}

// ===== INITIALIZATION & EVENT LISTENERS =====

/**
 * Initialize all page functionality on load.
 * 
 * Execution Order (important for visual presentation):
 *   1. colorizeRiskLevels() - Colorize all risk level cells
 *   2. handleScrollAndHighlight() - Restore scroll or highlight specific asset
 *   3. initializePage() - Show page after styling is complete
 * 
 * This order prevents unstyled content flash (FOUC) before colors are applied.
 */
window.addEventListener('load', async () => {
    await colorizeRiskLevels();
    handleScrollAndHighlight();
    initializePage();
});

// Fallback if DOMContentLoaded doesn't fire
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', async () => {
        await colorizeRiskLevels();
        handleScrollAndHighlight();
        initializePage();
    });
}

/**
 * Save current scroll position to localStorage before leaving page.
 * 
 * This allows users to return to approximately the same scroll position
 * when navigating back (from risks page, etc.).
 * 
 * Side Effects: Writes to localStorage["scrollPos"]
 */
window.addEventListener("beforeunload", () => {
    localStorage.setItem("scrollPos", window.scrollY);
});

