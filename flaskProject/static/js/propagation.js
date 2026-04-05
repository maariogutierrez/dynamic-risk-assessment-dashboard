/**
 * @fileoverview Propagation visualization module for threat propagation analysis.
 * 
 * This module renders an interactive network graph using vis.js to visualize how
 * threats propagate through a system's assets, generating feared events and cascading
 * risks. It provides interactive node selection, filtering by group, and detailed
 * information panels.
 * 
 * Dependencies:
 *   - vis-network: Network visualization library (expected in global scope)
 *   - Backend data: Variables must be injected before this script loads:
 *       * threatsData: Array of threat objects with propagation metadata
 *       * fearedEventsData: Array of feared event objects
 *       * assetsData: Array of asset objects with risk levels
 *       * relationshipsData: Array of relationship objects defining asset criticality
 *       * threatOriginal: Original threat that triggered the propagation analysis
 *       * fearedEventOriginal: Original feared event(s) being analyzed
 * 
 * @requires vis-network/standalone/umd/vis-network.min.js
 */

// ===== DATA INITIALIZATION & LOOKUP MAPS =====

/**
 * Decodes HTML entities in a string using a textarea element.
 * This approach is safe, efficient, and handles all HTML5 named entities.
 * 
 * Performance: O(1) - minimal DOM manipulation.
 * 
 * @param {string} html - HTML-encoded string (e.g., "&quot;", "&#39;")
 * @return {string} Decoded string with entities converted to their character equivalents
 * 
 * @example
 *   decodeHtml("&lt;Asset&gt;") // Returns: "<Asset>"
 */
function decodeHtml(html) {
    var txt = document.createElement("textarea");
    txt.innerHTML = html;
    return txt.value;
}

/**
 * Global lookup maps for O(1) access to entity data by ID.
 * These are populated at script initialization and substantially improve
 * performance when looking up detailed information during node selection.
 * 
 * @type {Object.<string, Object>}
 */
var assetMap = {};      // Key: asset_id, Value: asset object
var threatMap = {};     // Key: threat_id, Value: threat object
var fearedEventMap = {}; // Key: feared_event_id, Value: feared event object

/**
 * Initialize all lookup maps from the backend data.
 * This O(n) preprocessing step enables O(1) lookups during interactive operations.
 */
assetsData.forEach(function(asset) {
    assetMap[asset.asset_id] = asset;
});

threatsData.forEach(function(threat) {
    threatMap[threat.threat_id] = threat;
});

fearedEventsData.forEach(function(fe) {
    fearedEventMap[decodeHtml(fe.feared_event_id)] = fe;
});



// ===== UTILITY FUNCTIONS =====

/**
 * Normalizes a value into a filtered array, handling null/undefined cases.
 * 
 * This function ensures consistent array handling across the codebase by:
 * - Converting single values to arrays
 * - Filtering out falsy values (null, undefined, '')
 * - Returning empty array for absent data
 * 
 * Time: O(n) where n is array length
 * 
 * @param {*} value - Any value that might be a single item or array
 * @return {Array} Array of non-falsy values, or empty array
 */
function normalizeToArray(value) {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (value === null || value === undefined || value === '') return [];
    return [value];
}

/**
 * Returns a display string for a value, or dash '-' if the value is empty/null.
 * Used consistently in the UI for unified empty state representation.
 * 
 * @param {*} value - Value to display
 * @return {string} String representation or '-' if empty
 */
function valueOrDash(value) {
    if (value === null || value === undefined || value === '') return '-';
    return String(value);
}

/**
 * Converts a value or array of values into a comma-separated string, or '-' if empty.
 * Used for displaying multiple related items in table cells.
 * 
 * Performance: O(n) where n is array size
 * 
 * @param {*} value - Single value or array
 * @return {string} Comma-separated list or '-'
 */
function listOrDash(value) {
    var arr = normalizeToArray(value);
    return arr.length ? arr.join(', ') : '-';
}

/**
 * Converts snake_case identifier strings to Title Case for UI display.
 * Examples: 'supporting_asset' -> 'Supporting Asset'
 * 
 * Performance: O(n) where n is string length
 * 
 * @param {string} group - Identifier string with underscores
 * @return {string} Title-cased version suitable for display
 */
function titleCaseGroup(group) {
    if (!group) return '-';
    return group
        .replace(/_/g, ' ')
        .replace(/\b\w/g, function(char) { return char.toUpperCase(); });
}

/**
 * Sets a risk badge element with appropriate styling based on risk value.
 * Asynchronously fetches the risk color from the backend to ensure consistency
 * with server-side risk calculations.
 * 
 * Performance: One async fetch per badge. Batching multiple badges should use
 * Promise.all() to minimize request overhead.
 * 
 * @param {HTMLElement} cell - The TD element to populate with the badge
 * @param {number|Array|null} value - Risk value (1-50) or array containing risk value
 * @throws {Error} If cell is null or fetch fails (errors are logged to console)
 * 
 * @example
 *   const cell = document.getElementById('riskCell');
 *   setRiskBadge(cell, 25);  // Fetches color and creates badge
 */
function setRiskBadge(cell, value) {
    if (!cell) return;
    if (value === null || value === undefined || value === '') {
        cell.textContent = '-';
        return;
    }

    var badge = document.createElement('span');
    badge.className = 'risk-badge';
    badge.textContent = String(value);

    // Extract numeric value from single integer or array[0]
    var riskValue = Array.isArray(value) ? parseInt(value[0]) : parseInt(value);

    // Valid risk levels range from 1-50; fetch color from backend
    if (!isNaN(riskValue) && riskValue >= 1 && riskValue <= 50) {
        getRiskColor(riskValue).then(color => {
            badge.style.backgroundColor = color;
            badge.style.color = '#ffffff';
            cell.replaceChildren(badge);
        });
    } else {
        // Fallback neutral color for invalid/missing risk values
        badge.style.backgroundColor = '#4a4a55';
        cell.replaceChildren(badge);
    }
}

/**
 * Fetches the UI color for a given risk value from the backend.
 * Backend maintains authoritative risk-to-color mapping for consistency
 * across all views and exports.
 * 
 * Network request: One HTTP GET per unique risk value
 * Consider caching repeated values to reduce requests.
 * 
 * @param {number} riskValue - Risk level (1-50)
 * @return {Promise<string>} Promise resolving to hex or rgb color string
 * 
 * @example
 *   getRiskColor(35).then(color => console.log(color)); // "#FF6B6B"
 */
function getRiskColor(riskValue) {
    return fetch('/risk_color/' + riskValue)
        .then(response => response.text())
        .then(color => {
            return color;
        });
}



// ===== NETWORK GRAPH CONSTRUCTION =====

/**
 * Constructs nodes for the vis.js network visualization.
 * 
 * Node organization (hierarchical levels):
 *   Level 0: Threats (root cause - threats that started the propagation)
 *   Level 1: Feared Events (intermediate - outcomes of threats affecting assets)
 *   Level 2: Assets (targets - systems/resources threatened)
 * 
 * Each node receives:
 *   - Unique ID matching the entity ID
 *   - Label with type and ID for display
 *   - Group classification for styling and filtering
 *   - Shape (dot for normal, hexagon for original/root entities)
 *   - Level for hierarchical layout positioning
 * 
 * Performance: O(n) where n = threats + feared events + assets
 * Memory: O(n) for node array storage
 */
var nodesArray = [];

/**
 * Add threat nodes (Level 0: root causes).
 * Displayed using threat.svg icon; original threat is marked with a border.
 */
threatsData.forEach(function(threat) {
    nodesArray.push({
        id: threat.threat_id,
        label: threat.threat_id,
        group: "threats",
        shape: "image",
        image: '../images/threat.png',
        size: 20,
        level: 0
    });
});

/**
 * Add feared event nodes (Level 1: propagated outcomes).
 * These are the consequences of threats affecting assets.
 */
fearedEventsData.forEach(function(fe) {
    nodesArray.push({
        id: decodeHtml(fe.feared_event_id),
        label: fe.feared_event_id,
        group: "feared_events",
        shape: "image",
        image: '../images/feared_event.png',
        size: 20,
        level: 1
    });
});

/**
 * Add asset nodes (Level 2: threatened systems).
 * Display primary system components that can be affected by threats.
 */
assetsData.forEach(function(asset) {
    nodesArray.push({
        id: asset.asset_id,
        label: asset.asset_id,
        group: "assets",
        shape: "image",
        image: '../images/asset.png',
        size: 20,
        level: 2
    });
});

// Create vis.js DataSet for reactive node management
var nodes = new vis.DataSet(nodesArray);

/**
 * Mark the original threat with a border to visually distinguish it as the
 * root cause entity in the propagation chain.
 */
if (threatOriginal && threatOriginal.threat_id) {
    nodes.update({ 
        id: threatOriginal.threat_id, 
        borderWidth: 4,
        borderWidthSelected: 6,
        color: { border: '#FFD700', highlight: { border: '#FFD700' } }
    });
}

/**
 * Mark original feared event(s) with borders. This handles both single
 * feared event and array cases (multiple analysis scenarios).
 */
if (fearedEventOriginal) {
    if (Array.isArray(fearedEventOriginal)) {
        fearedEventOriginal.forEach(function(item) {
            nodes.update({ 
                id: item.feared_event_id, 
                borderWidth: 4,
                borderWidthSelected: 6,
                color: { border: '#FFD700', highlight: { border: '#FFD700' } }
            });
        });
    } else if (fearedEventOriginal.feared_event_id) {
        nodes.update({ 
            id: fearedEventOriginal.feared_event_id, 
            borderWidth: 4,
            borderWidthSelected: 6,
            color: { border: '#FFD700', highlight: { border: '#FFD700' } }
        });
    }
}

/**
 * Constructs edges (directed connections) representing propagation paths
 * and asset relationships.
 * 
 * Edge types:
 *   1. Threat -> Feared Event (threat.generates)
 *   2. Threat -> Asset (threat.affects)
 *   3. Feared Event -> Asset (fe.affects)
 *   4. Asset -> Asset (relationships: criticality-weighted)
 * 
 * All edges are directed (arrows pointing toward the target/consequence).
 * 
 * Edge colors:
 *   - Yellow (#FFD700): Edges originating from original threats or feared events
 *   - Blue (#3498db): All other propagation edges
 * 
 * Performance: O(n*m) worst case where n = propagation items, 
 *   m = average edges per item
 */

/**
 * Determines if a node ID represents an original threat or feared event.
 * Used to color edges from source nodes appropriately.
 * 
 * @param {string} nodeId - The node ID to check
 * @return {boolean} True if the node is an original threat or feared event
 */
function isOriginalThreatOrEvent(nodeId) {
    // Check if it's the original threat
    if (threatOriginal && threatOriginal.threat_id === nodeId) {
        return true;
    }
    
    // Check if it's in the original feared events
    if (fearedEventOriginal) {
        if (Array.isArray(fearedEventOriginal)) {
            return fearedEventOriginal.some(function(item) {
                return item.feared_event_id === nodeId;
            });
        } else if (fearedEventOriginal.feared_event_id === nodeId) {
            return true;
        }
    }
    
    return false;
}

var edgesArray = [];

/**
 * Build threat propagation edges.
 * - generates: Threat creates a feared event
 * - affects: Threat immediately impacts an asset
 */
threatsData.forEach(function(threat) {
    var edgeColor = isOriginalThreatOrEvent(threat.threat_id) ? '#FFD700' : '#3498db';
    
    if (threat.generates) {
        normalizeToArray(threat.generates).forEach(function(targetId) {
            edgesArray.push({
                from: threat.threat_id,
                to: decodeHtml(targetId),
                arrows: "to",
                color: edgeColor
            });
        });
    }
    if (threat.affects) {
        normalizeToArray(threat.affects).forEach(function(targetId) {
            edgesArray.push({
                from: threat.threat_id,
                to: decodeHtml(targetId),
                arrows: "to",
                color: edgeColor
            });
        });
    }
});

/**
 * Build feared event propagation edges.
 * - propagates_to: Feared event cascades to other feared events
 * - affects: Feared event impacts assets
 */
fearedEventsData.forEach(function(fe) {
    var feId = decodeHtml(fe.feared_event_id);
    var edgeColor = isOriginalThreatOrEvent(feId) ? '#FFD700' : '#3498db';
    
    if (fe.propagates_to) {
        normalizeToArray(fe.propagates_to).forEach(function(targetId) {
            edgesArray.push({
                from: feId,
                to: targetId,
                arrows: "to",
                color: edgeColor
            });
        });
    }
    if (fe.affects) {
        normalizeToArray(fe.affects).forEach(function(targetId) {
            edgesArray.push({
                from: feId,
                to: decodeHtml(targetId),
                arrows: "to",
                color: edgeColor
            });
        });
    }
});

/**
 * Build asset relationship edges.
 * All relationship edges are colored blue.
 */
relationshipsData.forEach(function(relationship) {
    edgesArray.push({
        from: relationship.from,
        to: relationship.to,
        arrows: 'to',
        color: '#3498db'
    });
});

// Create vis.js DataSet for reactive edge management
var edges = new vis.DataSet(edgesArray);

/**
 * Initialize the vis.js network visualization with hierarchical layout.
 * 
 * Configuration:
 *   - Layout: Hierarchical (directed top-down from threats to assets)
 *   - Physics: Enabled during stabilization, disabled for position control
 *   - Styling: Color-coded by entity group for visual differentiation
 */
var container = document.getElementById("network");
var data = { nodes: nodes, edges: edges };

/**
 * Vis.js network options configure layout and styling.
 * 
 * Hierarchical layout ensures:
 *   - Threats at top (causes)
 *   - Feared events in middle (intermediate effects)
 *   - Assets at bottom (final targets)
 *   - Visual flow from left to right within rows to minimize edge crossings
 * 
 * Node spacing (150px) and level separation (150px) prevent label overlap
 * and make the propagation structure obvious at a glance.
 */
var options = {
    layout: {
        hierarchical: {
            enabled: true,
            direction: "UD",              // Up-Down (top = threats, bottom = assets)
            sortMethod: "directed",       // Respect edge direction for positioning
            levelSeparation: 150,         // Vertical gap between hierarchy levels
            nodeSpacing: 150              // Horizontal gap between nodes at same level
        }
    },
    // Common font styling for all node labels
    nodes: {
        font: {
            color: '#ffffff',
            align: 'center',
            vadjust: 5                   // Offset to position label below the node
        }
    }
};

/**
 * Create the network instance.
 * This internally triggers physics simulation during 'stabilized' event.
 */
var network = new vis.Network(container, data, options);

// ===== ADAPTIVE GRAPH POSITIONING =====

/**
 * Preprocesses target relationships for each entity.
 * Used to align parents with children during position adjustment phase.
 * 
 * Maps each entity ID to the IDs of its "targets" (entities it affects/generates).
 * This enables parent nodes to center themselves above their children for
 * clearer visual propagation flow.
 * 
 * Performance: O(n) where n = total entities
 * Memory: O(m) where m = total relationships
 */
var positionTargets = {};

threatsData.forEach(function(threat) {
    if (threat.affects) {
        positionTargets[threat.threat_id] = normalizeToArray(threat.affects);
    } else if (threat.generates) {
        positionTargets[threat.threat_id] = normalizeToArray(threat.generates).map(decodeHtml);
    }
});

fearedEventsData.forEach(function(fe) {
    if (fe.affects) {
        positionTargets[decodeHtml(fe.feared_event_id)] = normalizeToArray(fe.affects);
    }
});

/**
 * Event handler called once network physics simulation stabilizes.
 * 
 * Adjusts node positions to create a cleaner, more readable graph by:
 *   1. Preserving asset positions (immutable anchors)
 *   2. Aligning feared events above their target assets
 *   3. Aligning threats above their target feared events/assets
 *   4. Spreading overlapping nodes to maintain visibility
 *   5. Resolving remaining collisions through iterative adjustment
 * 
 * This post-processing step runs once at initialization and dramatically
 * improves graph readability without excessive physics time.
 * 
 * Time Complexity: O(n² log n) worst case due to collision detection,
 *   but typically much faster for typical graph sizes.
 * 
 * Tuning parameters:
 *   - SPREAD_THRESHOLD: Distance before nodes are considered "overlapping" (150px)
 *   - MIN_DISTANCE: Minimum separation after spreading (150px)
 *   - maxIterations: Collision resolution iterations (10)
 */
network.once('stabilized', function() {
    var positions = network.getPositions();
    var newX = {};

    // ===== PHASE 1: Anchor asset positions =====
    // Assets stay fixed; they represent the real system topology
    nodes.forEach(function(node) {
        if (node.group === 'assets') newX[node.id] = positions[node.id].x;
    });

    // ===== PHASE 2: Center feared events above their target assets =====
    // If FE affects multiple assets, position between them (average X position)
    nodes.forEach(function(node) {
        if (node.group === 'feared_events') {
            var targets = positionTargets[node.id];
            if (targets) {
                var sumX = 0, count = 0;
                targets.forEach(function(tId) {
                    if (newX[tId] !== undefined) { sumX += newX[tId]; count++; }
                });
                if (count > 0) { newX[node.id] = sumX / count; return; }
            }
            newX[node.id] = positions[node.id].x;
        }
    });

    // ===== PHASE 3: Center threats above their targets =====
    // If threat affects multiple assets/FEs, position between them
    nodes.forEach(function(node) {
        if (node.group === 'threats') {
            var targets = positionTargets[node.id];
            if (targets) {
                var sumX = 0, count = 0;
                targets.forEach(function(tId) {
                    if (newX[tId] !== undefined) { sumX += newX[tId]; count++; }
                });
                if (count > 0) { newX[node.id] = sumX / count; return; }
            }
            newX[node.id] = positions[node.id].x;
        }
    });

    // ===== PHASE 4: Spread overlapping nodes =====
    // Prevent label occlusion by enforcing minimum spacing within each level
    var SPREAD_THRESHOLD = 150;    // Distance threshold for clustering
    var MIN_DISTANCE = 150;         // Minimum pixel separation

    [0, 1].forEach(function(level) {
        var levelNodes = [];
        
        // Collect all nodes at this level with positions
        nodes.forEach(function(node) {
            if (node.level === level && newX[node.id] !== undefined) {
                levelNodes.push({ id: node.id, x: newX[node.id] });
            }
        });
        
        // Sort left-to-right for sweep algorithm
        levelNodes.sort(function(a, b) { return a.x - b.x; });

        // ===== Sub-phase 4a: Group clustered nodes =====
        // Group nodes that are within SPREAD_THRESHOLD (consider them "together")
        var groups = [];
        levelNodes.forEach(function(n) {
            if (groups.length === 0) {
                groups.push([n]);
            } else {
                var last = groups[groups.length - 1];
                var avgX = last.reduce(function(s, e) { return s + e.x; }, 0) / last.length;
                if (Math.abs(n.x - avgX) < SPREAD_THRESHOLD) {
                    last.push(n);
                } else {
                    groups.push([n]);
                }
            }
        });

        // ===== Sub-phase 4b: Spread nodes within each group =====
        // Redistribute nodes in each group with MIN_DISTANCE between all
        groups.forEach(function(group) {
            if (group.length > 1) {
                var centerX = group.reduce(function(s, e) { return s + e.x; }, 0) / group.length;
                var totalWidth = (group.length - 1) * MIN_DISTANCE;
                var startX = centerX - totalWidth / 2;
                group.forEach(function(n, i) {
                    newX[n.id] = startX + i * MIN_DISTANCE;
                });
            }
        });

        // ===== Sub-phase 4c: Resolve inter-group collisions =====
        // Iteratively push apart any nodes still too close
        var maxIterations = 10;
        for (var iter = 0; iter < maxIterations; iter++) {
            var hasCollision = false;
            for (var i = 0; i < levelNodes.length - 1; i++) {
                for (var j = i + 1; j < levelNodes.length; j++) {
                    var node1 = levelNodes[i];
                    var node2 = levelNodes[j];
                    var distance = Math.abs(newX[node2.id] - newX[node1.id]);
                    
                    if (distance < MIN_DISTANCE) {
                        hasCollision = true;
                        var diff = MIN_DISTANCE - distance;
                        // Push nodes apart equally in opposite directions
                        newX[node2.id] += diff / 2;
                        newX[node1.id] -= diff / 2;
                    }
                }
            }
            // Exit early if no collisions found
            if (!hasCollision) break;
        }
    });

    // ===== PHASE 5: Apply new positions =====
    // Disable physics to lock nodes in place, then move all nodes
    network.setOptions({ physics: { enabled: false } });
    nodes.forEach(function(node) {
        if (newX[node.id] !== undefined && positions[node.id]) {
            network.moveNode(node.id, newX[node.id], positions[node.id].y);
        }
    });
});

// ===== INTERACTIVE DETAILS PANEL =====

/**
 * Detail panel DOM element references.
 * These are cached for performance – the details panel is heavily updated
 * on every node selection (potentially hundreds of times during exploration).
 * 
 * @type {HTMLElement}
 */
var detailHint = document.getElementById('detailHint');
var detailType = document.getElementById('detailType');
var detailId = document.getElementById('detailId');
var detailDescription = document.getElementById('detailDescription');
var detailImportance = document.getElementById('detailImportance');
var detailAffects = document.getElementById('detailAffects');
var detailGenerates = document.getElementById('detailGenerates');
var detailPropagatesTo = document.getElementById('detailPropagatesTo');
var detailRiskLevel = document.getElementById('detailRiskLevel');
var detailPropagatedRiskLevel = document.getElementById('detailPropagatedRiskLevel');
var detailRelativeRiskLevel = document.getElementById('detailRelativeRiskLevel');

/**
 * Resets all detail panel cells to their default empty state.
 * Called when no node is selected or selection is invalid.
 */
function resetDetails() {
    detailHint.textContent = 'Click a node in the propagation graph to inspect it.';
    detailType.textContent = '-';
    detailId.textContent = '-';
    detailDescription.textContent = '-';
    detailImportance.textContent = '-';
    detailAffects.textContent = '-';
    detailGenerates.textContent = '-';
    detailPropagatesTo.textContent = '-';
    detailRiskLevel.textContent = '-';
    detailPropagatedRiskLevel.textContent = '-';
    detailRelativeRiskLevel.textContent = '-';
}

/**
 * Populates detail panel with data from a selected node.
 * 
 * The detail object schema varies by entity type:
 *   - Assets: Shows risk levels and inherited propagated risk
 *   - Threats: Shows affected entities and generated feared events
 *   - Feared Events: Shows affected assets and propagation destinations
 * 
 * @param {Object} details - Detail object with the following schema:
 *   {
 *     hint: string,                    // Status message (e.g., "Asset selected")
 *     type: string,                    // Entity type with subtype (e.g., "Asset (CPU)")
 *     id: string,                      // Entity ID
 *     description: string,             // Human-readable description
 *     affects: string,                 // Comma-separated or single: "-"
 *     generates: string,               // Comma-separated or single: "-"
 *     propagatesTo: string,            // Comma-separated or single: "-"
 *     riskLevel: number|null,          // Direct risk (1-50) or null
 *     propagatedRiskLevel: number|null // Risk from propagation or null
 *   }
 */
function updateDetails(details) {
    detailHint.textContent = details.hint || 'Selected node';
    detailType.textContent = valueOrDash(details.type);
    detailId.textContent = valueOrDash(details.id);
    detailDescription.textContent = valueOrDash(details.description);
    detailImportance.textContent = valueOrDash(details.importance);
    detailAffects.textContent = valueOrDash(details.affects);
    detailGenerates.textContent = valueOrDash(details.generates);
    detailPropagatesTo.textContent = valueOrDash(details.propagatesTo);
    setRiskBadge(detailRiskLevel, details.riskLevel);
    setRiskBadge(detailPropagatedRiskLevel, details.propagatedRiskLevel);
    setRiskBadge(detailRelativeRiskLevel, details.relativeRiskLevel);
}

/**
 * Handles node selection and updates the detail panel accordingly.
 * 
 * Behavior:
 *   1. Updates visual highlighting (resizes node from 20px to 40px)
 *   2. Tracks previously highlighted node to restore normal size
 *   3. Original/root nodes retain their size (not shrunk on deselect)
 *   4. Fetches full data from lookup maps and renders details
 *   5. Animates camera to focus on selected node
 * 
 * Error handling: Invalid node IDs are caught and user is informed.
 * 
 * @param {string} id - The node ID to highlight and inspect
 * 
 * @throws {Error} Indirectly if network.fit() or data lookup fails
 *                (errors logged to console, UI shows message)
 */
function highlightNode(id) {
    var node = nodes.get(id);
    var details;

    if (node) {
        // Restore previous node to normal size
        if (currentHighlightedNode !== null) {
            nodes.update([{ id: currentHighlightedNode, size: 20 }]);
        }

        // Highlight new selection
        currentHighlightedNode = id;
        nodes.update([{ id: id, size: 40 }]);

        var nodeType = node.group;
        var description = '';
        var affects = '';
        var generates = '';
        var propagatesTo = '';
        var prl = null;  // propagated risk level
        var rl = null;   // risk level

        // ===== Asset details =====
        if (nodeType === 'assets') {
            var assetInfo = assetMap[id];
            var importance = null;
            if (assetInfo) {
                description = assetInfo.description ? assetInfo.description : null;
                type = assetInfo.type ? assetInfo.type : null;
                importance = assetInfo.importance ? assetInfo.importance : null;
                prl = assetInfo.propagated_risk_level ? assetInfo.propagated_risk_level : null;
                rl = assetInfo.risk_level ? assetInfo.risk_level : null;
                rrl = assetInfo.relative_risk_level ? assetInfo.relative_risk_level : null;
            }
            details = {
                hint: 'Asset selected',
                type: titleCaseGroup(nodeType) + (type ? ' (' + type + ')' : ''),
                id: id,
                description: description,
                importance: importance,
                affects: '-',
                generates: '-',
                propagatesTo: '-',
                riskLevel: rl,
                propagatedRiskLevel: prl,
                relativeRiskLevel: rrl
            };
        } 
        // ===== Threat details =====
        else if (nodeType === 'threats') {
            var threatInfo = threatMap[id];
            if (threatInfo) {
                description = threatInfo.type ? threatInfo.type : '';
                affects = listOrDash(threatInfo.affects);
                generates = threatInfo.generates ? threatInfo.generates.join(", ") : '';
            }
            details = {
                hint: 'Threat selected',
                type: titleCaseGroup(nodeType),
                id: id,
                description: description,
                affects: affects,
                generates: generates,
                propagatesTo: '-',
                riskLevel: null,
                propagatedRiskLevel: null,
                relativeRiskLevel: null
            };
        } 
        // ===== Feared event details =====
        else if (nodeType === 'feared_events') {
            var feInfo = fearedEventMap[id];
            if (feInfo) {
                description = feInfo.description ? feInfo.description : '';
                affects = listOrDash(feInfo.affects);
                propagatesTo = feInfo.propagates_to ? feInfo.propagates_to.join(", ") : '';
            }
            details = {
                hint: 'Feared event selected',
                type: 'Feared Events',
                id: id,
                description: description,
                affects: affects,
                generates: '-',
                propagatesTo: propagatesTo,
                riskLevel: null,
                propagatedRiskLevel: null,
                relativeRiskLevel: null
            };
        }
        
        // Smoothly pan/zoom to focus on selected node
        network.fit({ nodes: [id], animation: true });
    } else {
        resetDetails();
        detailHint.textContent = `Node with ID "${id}" not found.`;
        return;
    }

    updateDetails(details);
}

/**
 * Tracks the currently highlighted/selected node ID.
 * Used to restore normal size when switching selections.
 * 
 * @type {string|null}
 */
var currentHighlightedNode = null;

// ===== EVENT LISTENERS & INITIALIZATION =====

/**
 * Click handler for node selection.
 * Uses a small delay to distinguish clicks from pan/drag operations
 * (vis.js emits click after drag completes).
 * 
 * The 200ms debounce is tuned to:
 *   - Ignore accidental clicks during panning
 *   - Feel responsive to intentional node selection
 * 
 * Performance: O(1) for most clicks; O(n) if node lookup fails
 */
network.on('click', function(event) {
    setTimeout(function() {
        var nodeId = event.nodes[0];
        if (nodeId) {
            highlightNode(nodeId);
        }
    }, 200);
});

/**
 * Initialize details panel to empty state.
 * Show hint text prompting user to select a node.
 */
resetDetails();

/**
 * Fade in the entire page after initialization completes.
 * Page starts with visibility: hidden in CSS to prevent
 * rendering during complex DOM construction.
 * 
 * 100ms delay ensures all rendering is complete before
 * making content visible (improved perceived performance).
 */
setTimeout(function() {
    document.body.style.visibility = "visible";
}, 100);