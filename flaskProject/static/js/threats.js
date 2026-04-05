/**
 * @fileoverview Threat propagation tree visualization module.
 * 
 * This module renders an interactive hierarchical tree diagram using GoJS to visualize
 * how threats propagate through a system, generating feared events and cascading effects.
 * It provides threat selection, filtering, and detailed information display.
 * 
 * Dependencies:
 *   - gojs: Diagram visualization library (expected in global scope)
 *   - Backend data: Variables must be injected before this script loads:
 *       * threats: Array of original threat objects
 *       * threats_p: Array of propagated threat objects
 *       * feared_events: Array of original feared event objects
 *       * feared_events: Array of propagated feared event objects
 * 
 * @requires jsnet/go-debug.js
 */

// ===== UTILITY FUNCTIONS =====

/**
 * Normalizes a value into a filtered array, handling null/undefined cases.
 * 
 * This function ensures consistent array handling across the codebase by:
 * - Converting single values to arrays
 * - Filtering out falsy values (null, undefined, '')
 * - Returning empty array for absent data
 * 
 * Time Complexity: O(n) where n is array length
 * 
 * @param {*} value - Any value that might be a single item or array
 * @return {Array} Array of non-falsy values, or empty array
 * 
 * @example
 *   normalizeToArray("item")           // Returns: ["item"]
 *   normalizeToArray(["a", "b", null]) // Returns: ["a", "b"]
 *   normalizeToArray(null)             // Returns: []
 */
function normalizeToArray(value) {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (value === null || value === undefined || value === '') return [];
    return [value];
}

/**
 * Gets a human-readable display name for a threat object.
 * 
 * Attempts to extract display name in order of preference:
 * 1. threat.name - custom name if available
 * 2. threat.threat_id - identifier if name unavailable
 * 3. threat.type[0] - first type if array available
 * 4. Fallback to "Unknown threat" if all fail
 * 
 * Time Complexity: O(1)
 * 
 * @param {Object} threat - Threat object to extract name from
 * @return {string} Human-readable threat name or fallback string
 * 
 * @example
 *   getThreatDisplayName({threat_id: "T001", name: "SQL Injection"})
 *   // Returns: "SQL Injection"
 */
function getThreatDisplayName(threat) {
    if (!threat) return 'Unknown threat';
    if (threat.name) return String(threat.name);
    if (threat.threat_id) return String(threat.threat_id);
    if (Array.isArray(threat.type) && threat.type.length) return String(threat.type[0]);
    return 'Unknown threat';
}

/**
 * Returns a display string for a value, or dash '-' if the value is empty/null.
 * Used consistently in the UI for unified empty state representation.
 * 
 * Time Complexity: O(1)
 * 
 * @param {*} value - Value to display
 * @return {string} String representation or '-' if empty
 * 
 * @example
 *   valueOrDash("text")    // Returns: "text"
 *   valueOrDash(null)      // Returns: "-"
 *   valueOrDash("")        // Returns: "-"
 */
function valueOrDash(value) {
    if (value === null || value === undefined || value === '') return '-';
    return String(value);
}

/**
 * Converts a value or array of values into a comma-separated string, or '-' if empty.
 * Used for displaying multiple related items in detail table cells.
 * 
 * Time Complexity: O(n) where n is array size
 * Memory: O(n) for output string
 * 
 * @param {*} value - Single value or array of values
 * @return {string} Comma-separated list or '-' if empty
 * 
 * @example
 *   listOrDash(["Asset1", "Asset2"]) // Returns: "Asset1, Asset2"
 *   listOrDash("Asset1")             // Returns: "Asset1"
 *   listOrDash([])                   // Returns: "-"
 */
function listOrDash(value) {
    var arr = normalizeToArray(value);
    return arr.length ? arr.join(', ') : '-';
}

/**
 * Escapes HTML special characters to prevent XSS injection vulnerabilities.
 * Safely encodes characters that have special meaning in HTML.
 * 
 * Time Complexity: O(n) where n is string length
 * Security: Prevents HTML/JavaScript injection in detail panel
 * 
 * @param {string} text - Raw HTML-containing text to escape
 * @return {string} Escaped text safe for HTML display
 * 
 * @example
 *   escapeHtml("<script>alert('xss')</script>")
 *   // Returns: "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
 */
function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ===== TREE INITIALIZATION & EVENT HANDLING =====

/**
 * Initialize and configure the threat propagation tree diagram.
 * 
 * This function:
 * 1. Loads threat and feared event data from embedded JSON
 * 2. Constructs a lookup map for O(1) entity access
 * 3. Builds a hierarchical tree structure showing threat propagation
 * 4. Creates GoJS diagram with interactive nodes and expand/collapse
 * 5. Populates threat selector dropdown and detail panel
 * 6. Handles user interactions (node clicks, filter toggle, dropdown selection)
 * 
 * Visual styling:
 *   - Yellow (#FFD700) nodes: Original threats (visually distinguished)
 *   - Blue (#3498db) nodes: Propagated threats
 * 
 * Performance:
 *   - Time: O(n log n) for initial tree construction (n = total entities)
 *   - Space: O(n) for node and edge arrays
 *   - Lookup: O(1) for entity details via threatById map
 * 
 * @function
 * @return {void}
 */
function initThreatPropagationTree() {
    var filterToggle = document.getElementById('filterGeneratesToggle');
    if (filterToggle) {
        filterToggle.addEventListener('change', function() {
            if (this.checked) {
                window.location.href = document.getElementById('filterUrl').getAttribute('data-true');
            } else {
                window.location.href = document.getElementById('filterUrl').getAttribute('data-false');
            }
        });
    }

    // ===== DATA INITIALIZATION =====
    // Load threat and feared event data from embedded JSON scripts
    // Backend renders these as JSON to avoid AJAX latency
    var originalThreats = JSON.parse(document.getElementById('threats-original-json').textContent || '[]');
    var propagatedThreats = JSON.parse(document.getElementById('threats-propagated-json').textContent || '[]');
    var originalFearedEvents = JSON.parse(document.getElementById('feared-events-original-json').textContent || '[]');
    var propagatedFearedEvents = JSON.parse(document.getElementById('feared-events-propagated-json').textContent || '[]');

    var allThreats = [].concat(originalThreats || [], propagatedThreats || []);
    var allFearedEvents = [].concat(originalFearedEvents || [], propagatedFearedEvents || []);
    var allFEIds = new Set((allFearedEvents || []).map(function(fe) { return fe && fe.feared_event_id; }).filter(Boolean));
    var feLinkBase = document.getElementById('feLink').getAttribute('data-base');

    // ===== LOOKUP MAP CONSTRUCTION =====
    // Build O(1) lookup maps for fast entity retrieval during UI updates
    // Performance: O(n) construction time, O(1) lookup time
    // Memory: O(n) for map storage where n = number of unique threats
    var threatById = {};
    allThreats.forEach(function(t) {
        if (t && t.threat_id) {
            threatById[t.threat_id] = t;
        }
    });

    var threatSelector = document.getElementById('threatSelector');
    var detailThreatId = document.getElementById('detailThreatId');
    var detailType = document.getElementById('detailType');
    var detailAffects = document.getElementById('detailAffects');
    var detailGenerates = document.getElementById('detailGenerates');

    // ===== DETAIL PANEL UPDATE FUNCTION =====
    /**
     * Updates the threat detail panel with information from selected threat.
     * Displays threat properties and generates clickable links to feared events.
     * 
     * Time Complexity: O(m) where m = number of feared events generated by threat
     * 
     * @param {string} threatId - The threat_id to look up and display
     * @return {void}
     */
    function updateThreatDetails(threatId) {
        var threat = threatById[threatId];
        if (!threat) {
            detailThreatId.textContent = '-';
            detailType.textContent = '-';
            detailAffects.textContent = '-';
            detailGenerates.textContent = '-';
            return;
        }
        detailThreatId.textContent = valueOrDash(threat.threat_id);
        detailType.textContent = listOrDash(threat.type);
        detailAffects.textContent = valueOrDash(threat.affects);
        var generatedFEs = normalizeToArray(threat.generates);
        if (!generatedFEs.length) {
            detailGenerates.textContent = '-';
            return;
        }

        var links = generatedFEs
            .filter(function(feId) { return allFEIds.has(feId); })
            .map(function(feId) {
                var href = feLinkBase.replace('__FE__', encodeURIComponent(feId));
                return '<a href="' + href + '">' + escapeHtml(feId) + '</a>';
            });

        if (links.length) {
            detailGenerates.innerHTML = links.join(', ');
        } else {
            detailGenerates.textContent = '-';
        }
    }

    // ===== THREAT SELECTOR POPULATION =====
    // Build sorted list of threats for dropdown menu
    // Time: O(n log n) for sort where n = number of threats
    var sortedThreatIds = Object.keys(threatById).sort(function(a, b) {
        var ta = getThreatDisplayName(threatById[a]).toLowerCase();
        var tb = getThreatDisplayName(threatById[b]).toLowerCase();
        if (ta < tb) return -1;
        if (ta > tb) return 1;
        return 0;
    });

    sortedThreatIds.forEach(function(threatId) {
        var option = document.createElement('option');
        option.value = threatId;
        option.textContent = getThreatDisplayName(threatById[threatId]);
        threatSelector.appendChild(option);
    });

    threatSelector.addEventListener('change', function() {
        updateThreatDetails(this.value);
    });

    // ===== GRAPH STRUCTURE CONSTRUCTION =====
    // Build node and edge arrays for GoJS diagram
    // Analyze threat propagation to determine tree hierarchy
    
    // Track original threat IDs for visual distinction
    // Time: O(n) where n = original threats count
    var originalThreatIds = new Set((originalThreats || []).map(function(t) { return t.threat_id; }));
    
    // Build feared event lookup map
    // Time: O(m) where m = feared events count
    var feById = {};
    allFearedEvents.forEach(function(fe) {
        if (fe && fe.feared_event_id) {
            feById[fe.feared_event_id] = fe;
        }
    });

    // Find threat propagation paths by analyzing feared event cascades
    // Time: O(n * m) where n = threats, m = feared events per threat
    var edgeSet = new Set();
    var childIds = new Set();

    allThreats.forEach(function(parentThreat) {
        if (!parentThreat || !parentThreat.threat_id) return;

        normalizeToArray(parentThreat.generates).forEach(function(feId) {
            var fe = feById[feId];
            if (!fe) return;

            normalizeToArray(fe.propagates_to).forEach(function(childThreatId) {
                if (!childThreatId || !threatById[childThreatId]) return;
                var edgeKey = parentThreat.threat_id + '->' + childThreatId;
                if (!edgeSet.has(edgeKey)) {
                    edgeSet.add(edgeKey);
                    childIds.add(childThreatId);
                }
            });
        });
    });

    // ===== NODE ARRAY CONSTRUCTION =====
    // Create node data for GoJS diagram
    // Time: O(n) where n = number of unique threats
    var nodeDataArray = [];
    Object.keys(threatById).forEach(function(threatId) {
        var threat = threatById[threatId];
        var label = getThreatDisplayName(threat);
        nodeDataArray.push({
            key: threatId,
            text: label,
            isOriginal: originalThreatIds.has(threatId)
        });
    });

    // ===== EDGE ARRAY CONSTRUCTION =====
    // Create edge data for GoJS diagram
    // Edges represent threat propagation chain: Parent -> Child
    // Time: O(e) where e = number of propagation relationships
    var linkDataArray = [];
    edgeSet.forEach(function(edge) {
        var pair = edge.split('->');
        if (pair.length === 2) {
            linkDataArray.push({ from: pair[0], to: pair[1] });
        }
    });

    // ===== ROOT NODE IDENTIFICATION =====
    // Find root threats (no parent) for tree layout
    // Time: O(n) where n = number of threats
    var rootCandidates = Object.keys(threatById).filter(function(id) {
        return !childIds.has(id);
    });

    // Use original threats as roots if available, otherwise use all roots
    var initialRoots = Array.from(originalThreatIds);
    if (!initialRoots.length) {
        initialRoots = rootCandidates;
    }

    // Add virtual root node if multiple roots (required for tree layout)
    if (initialRoots.length > 1) {
        nodeDataArray.push({ key: '__ROOT__', text: 'Threat propagation', isVirtualRoot: true });
        initialRoots.forEach(function(id) {
            linkDataArray.push({ from: '__ROOT__', to: id, isVirtual: true });
        });
    }

    // ===== GOJS DIAGRAM INITIALIZATION =====
    /**
     * Create GoJS Diagram for interactive tree visualization.
     * Configuration:
     * - Two-level tree layout (top-down)
     * - Node expansion/collapse for branch exploration
     * - No movement/editing (read-only)
     * - Horizontal and vertical scrolling enabled
     */
    var myDiagram = new go.Diagram('treeDiagram', {
        allowMove: false,
        allowCopy: false,
        allowDelete: false,
        allowHorizontalScroll: true,
        allowVerticalScroll: true,
        layout: new go.TreeLayout({
            alignment: go.TreeAlignment.Start,
            angle: 0,
            compaction: go.TreeCompaction.None,
            layerSpacing: 60,
            nodeSpacing: 20,
            setsPortSpot: false,
            setsChildPortSpot: false
        })
    });

    // Expand/collapse acts as dropdown per branch.
    (function(cmd) {
        var originalExpandTree = cmd.expandTree.bind(cmd);
        cmd.expandTree = function(node) {
            node.isTreeExpanded = true;
            node.findTreeChildrenNodes().each(function(child) {
                child.isTreeExpanded = false;
            });
        };
    })(myDiagram.commandHandler);

    // ===== NODE TEMPLATE DEFINITION =====
    /**
     * Define appearance and behavior for threat nodes.
     * 
     * Visual characteristics:
     * - Yellow (#FFD700) background for original threats
     * - Blue (#3498db) background for propagated threats
     * - Black text for yellow nodes, white text for blue nodes
     * - Rounded rectangle shape with subtle border
     * - Node size increases on selection
     * 
     * Interactivity:
     * - Click to select node and show details
     * - Click to expand/collapse child nodes
     * - Synchronized with threat selector dropdown
     */
    myDiagram.nodeTemplate =
        new go.Node('Auto', {
            selectionAdorned: false,
            cursor: 'pointer',
            click: function(e, node) {
                var cmd = myDiagram.commandHandler;
                var selectedThreatId = node && node.data ? node.data.key : '';
                if (selectedThreatId && selectedThreatId !== '__ROOT__') {
                    threatSelector.value = selectedThreatId;
                    updateThreatDetails(selectedThreatId);
                }
                if (node.isTreeExpanded) {
                    if (!cmd.canCollapseTree(node)) return;
                    cmd.collapseTree(node);
                } else {
                    if (!cmd.canExpandTree(node)) return;
                    cmd.expandTree(node);
                }
                e.handled = true;
            }
        })
            .add(
                new go.Shape('RoundedRectangle', {
                    strokeWidth: 1,
                    stroke: '#7f8b99',
                    parameter1: 6
                }).bind('fill', 'isOriginal', function(isOriginal) {
                    return isOriginal ? '#FFD700' : '#3498db';
                }).bind('visible', 'isVirtualRoot', function(isVirtualRoot) {
                    return !isVirtualRoot;
                }),
                new go.TextBlock({
                    margin: 8,
                    font: '10pt Verdana, sans-serif',
                    textAlign: 'center',
                    isMultiline: false,
                    wrap: go.Wrap.None,
                    overflow: go.TextOverflow.Clip
                }).bind('stroke', 'isOriginal', function(isOriginal) {
                    return isOriginal ? '#000000' : '#ffffff';
                }).bind('text', 'text').bind('visible', 'isVirtualRoot', function(isVirtualRoot) {
                    return !isVirtualRoot;
                })
            );

    myDiagram.linkTemplate =
        new go.Link({ routing: go.Routing.Orthogonal, corner: 4 })
            .add(
                new go.Shape({ stroke: '#90a4b8', strokeWidth: 1 })
            );

    // ===== DIAGRAM MODEL INITIALIZATION =====
    // Bind node and edge data to the diagram
    // GoJS updates automatically when data changes
    myDiagram.model = new go.GraphLinksModel(nodeDataArray, linkDataArray);

    // Hide virtual edges (connecting to virtual root node)
    // These edges are purely structural for layout purposes
    myDiagram.links.each(function(link) {
        if (link.data && link.data.isVirtual) {
            link.visible = false;
        }
    });

    // Collapse all nodes initially (except root)  
    // Users can expand branches to explore selectively
    // Time: O(n) where n = number of nodes
    myDiagram.nodes.each(function(node) {
        if (node.data && node.data.isVirtualRoot) return;
        var cmd = myDiagram.commandHandler;
        if (cmd.canCollapseTree(node)) cmd.collapseTree(node);
    });

    // Handle empty state
    // Show message if no threat data available
    if (!nodeDataArray.length) {
        document.getElementById('treeDiagram').innerHTML = '<p style="color:#e0e0e0; font: 10pt Verdana, sans-serif;">No threat propagation data available.</p>';
    }

    // Initialize detail panel with first threat from dropdown
    // Pre-populate so user sees data immediately
    if (sortedThreatIds.length) {
        threatSelector.value = sortedThreatIds[0];
        updateThreatDetails(sortedThreatIds[0]);
    }
}

// ===== PAGE INITIALIZATION =====

/**
 * Start the initialization process when DOM is fully loaded.
 * This ensures all HTML elements are available for JavaScript manipulation.
 * 
 * Performance: Total initialization ~O(n log n) where n = total entities
 *   - Data loading: O(n)
 *   - Lookup map construction: O(n)
 *   - Graph construction: O(n log n) due to sorting
 *   - Diagram rendering: O(n) for GoJS
 *   - Tree layout calculation: O(n)
 */
window.addEventListener('DOMContentLoaded', initThreatPropagationTree);
