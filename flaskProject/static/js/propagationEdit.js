/**
 * @fileoverview Propagation configuration editor module.
 * 
 * This module provides an interactive interface for managing threat propagation
 * configurations. Users can create, edit, and delete mappings between feared events
 * and threats with minimum criticality thresholds. Changes are tracked and can be
 * saved to persist configuration updates.
 * 
 * Features:
 *   - Create new propagation configurations with dynamic row insertion
 *   - Edit feared events and threats via dropdown pickers
 *   - Edit minimum criticality thresholds with input validation
 *   - Delete configurations with visual feedback
 *   - Track unsaved changes with dirty flag
 *   - Save changes via async API call with toast notifications
 *   - Navigate to propagation page with automatic save
 * 
 * Dependencies:
 *   - Backend data: Script elements must be present before this script loads:
 *       * #fe-data: JSON array of feared event identifiers
 *       * #threat-data: JSON array of threat identifiers
 *       * #propagation-url: Element with data-url attribute for navigation
 *   - DOM elements: #propagation-table, #goToPropagationBtn, #toast-container
 * 
 * @requires None (vanilla JavaScript, no external libraries)
 */

// ===== STATE MANAGEMENT =====

/**
 * Flag indicating whether the propagation configuration has unsaved changes.
 * Used to determine whether to save before navigating or just navigate.
 * 
 * @type {boolean}
 */
let propagationIsDirty = false;

// ===== STATE UPDATE FUNCTIONS =====

/**
 * Updates the dirty flag and button text to reflect unsaved changes state.
 * 
 * When the form is dirty, the button text changes from "Go to propagation"
 * to "Save" to indicate that clicking will save changes. This provides
 * immediate visual feedback to the user about the current state.
 * 
 * Time Complexity: O(1)
 * 
 * @param {boolean} [v=true] - New dirty state value (optional, defaults to true)
 * @return {void}
 * 
 * @example
 *   setPropagationDirty(true)   // Mark form as changed, button shows "Save"
 *   setPropagationDirty(false)  // Mark form as saved, button shows "Go to propagation"
 */
function setPropagationDirty(v = true) {
    propagationIsDirty = !!v;
    const btn = document.getElementById('goToPropagationBtn');
    if (btn) btn.textContent = propagationIsDirty ? 'Save' : 'Go to propagation';
}

// ===== UI MANIPULATION FUNCTIONS =====

/**
 * Creates a new empty row in the propagation table with default inputs.
 * 
 * The new row is prepended to the table body and highlighted with an animation.
 * Fields are initialized with unique IDs based on current timestamp to avoid
 * ID collisions when multiple rows are created in quick succession.
 * 
 * Time Complexity: O(1) DOM operations
 * 
 * @return {void}
 * 
 * @example
 *   newPropagation()  // Adds new row to top of propagation table
 */
function newPropagation() {
    const tbody = document.querySelector('#propagation-table tbody');
    const fe_opts = JSON.parse(document.getElementById('fe-data').textContent);
    const threat_opts = JSON.parse(document.getElementById('threat-data').textContent);

    const ts = Date.now();
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td align="center" id='propagation-fe-${ts}'></td>
        <td align="center" id='propagation-threat-${ts}'></td>
        <td align="center"><input id='propagation-criticality-${ts}' type="number" min="1" max="3" step="1" value="" /></td>
        <td align="center" class="actions-cell">
            <button type="button" class="delete-btn" title="Delete row">X</button>
        </td>
    `;
    tbody.prepend(tr);
    try {
        tr.classList.add('new-row-highlight');
        setTimeout(() => {
            try { tr.classList.remove('new-row-highlight'); } catch(e){}
        }, 2200);
    } catch (e) {}
    setPropagationDirty(true);
}

/**
 * Opens a dropdown picker for selecting a feared event or threat value.
 * 
 * A temporary select element is created and positioned absolutely over the
 * target cell. The picker auto-focuses and commits the selection on change,
 * blur, or Escape key. The selection is then written back to the cell and
 * the picker is removed.
 * 
 * Time Complexity: O(n) where n is the number of available options
 * 
 * @param {Object} opts - Configuration object for the picker
 * @param {Element} opts.cell - The table cell to edit
 * @param {string} opts.type - 'fe' for feared event or 'threat' for threat
 * @return {void}
 * 
 * @example
 *   const cell = document.getElementById('propagation-fe-123');
 *   openPicker({cell: cell, type: 'fe'})
 */
function openPicker(opts) {
    const existing = document.querySelector('.popup');
    if (existing && existing.isConnected) {
        try { existing.remove(); } catch(e) {}
    }

    const select = document.createElement('select');
    select.className = 'popup';
    select.style.position = 'absolute';
    select.style.zIndex = 9999;
    select.style.padding = '6px';
    select.style.borderRadius = '6px';
    select.style.border = '1px solid #888';
    select.style.background = '#222';
    select.style.color = 'white';

    const rect = opts.cell.getBoundingClientRect();
    select.style.left = (rect.left + window.scrollX + 6) + 'px';
    select.style.top = (rect.top + window.scrollY + 6) + 'px';

    const currentText = opts.cell.innerText;

    let rawOpts = [];
    if (opts.type === 'fe') {
        rawOpts = JSON.parse(document.getElementById('fe-data').textContent);
    } else if (opts.type === 'threat') {
        rawOpts = JSON.parse(document.getElementById('threat-data').textContent);
    }

    rawOpts.forEach(o => {
        const val = o;
        const option = document.createElement('option');
        option.value = val;
        option.text = val;
        if (val === currentText) option.selected = true;
        select.appendChild(option);
    });

    document.body.appendChild(select);
    select.focus();

    function commit() {
        const v = select.value;
        if (v) {
            opts.cell.innerText = v;
        }
        if (select.isConnected) {
            try { select.remove(); } catch(e) {}
        }
        try { setPropagationDirty(true); } catch(e) {}
    }

    select.addEventListener('change', commit);
    select.addEventListener('blur', commit);
    select.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') {
            if (select.isConnected) {
                try { select.remove(); } catch(e) {}
            }
        }
    });
}

// ===== EVENT LISTENERS =====

/**
 * Root table click handler for row deletion and field editing.
 * 
 * Delegates to appropriate handlers based on click target:
 * - Delete button click: removes row from table
 * - Feared event cell click: opens feared event picker
 * - Threat cell click: opens threat picker
 * 
 * Time Complexity: O(1)
 */
document.getElementById('propagation-table').addEventListener('click', function (e) {
    const btn = e.target.closest('.delete-btn');
    if (btn) {
        const row = btn.closest('tr');
        if (row) {
            row.remove();
            setPropagationDirty(true);
        }
        return;
    }

    const cell = e.target.closest('td');
    if (cell.id.startsWith('propagation-fe')) {
        openPicker({cell: cell, type: 'fe'});
    } else if (cell.id.startsWith('propagation-threat')) {
        openPicker({cell: cell, type: 'threat'});
    }
});

/**
 * Number input blur handler for value validation and rounding.
 * 
 * Enforces minimum/maximum constraints and rounds to step size.
 * Prevents invalid values by resetting to minimum if parsing fails.
 * 
 * Time Complexity: O(1)
 */
document.getElementById('propagation-table').addEventListener('blur', function(e) {
    if (e.target.type === 'number') {
        const min = parseFloat(e.target.min) || 1;
        const max = parseFloat(e.target.max) || 3;
        const step = parseFloat(e.target.step) || 1;
        let value = parseFloat(e.target.value);

        if (isNaN(value)) {
            e.target.value = min;
            setPropagationDirty(true);
            return;
        }

        if (value < min) e.target.value = min;
        else if (value > max) e.target.value = max;
        else if (step === 1) e.target.value = Math.round(value);

        setPropagationDirty(true);
    }
}, true);

/**
 * Input event handler to track changes to any input field.
 * Marks the form as dirty whenever a user modifies an input.
 * 
 * Time Complexity: O(1)
 */
document.getElementById('propagation-table').addEventListener('input', function(e) {
    if (e.target && e.target.tagName === 'INPUT') {
        setPropagationDirty(true);
    }
}, true);

// ===== API & PERSISTENCE FUNCTIONS =====

/**
 * Collects propagation configuration data from the table and sends to server.
 * 
 * Iterates through all rows in the table body and extracts:
 *   - Feared event ID from first column
 *   - Threat ID from second column
 *   - Minimum criticality threshold from number input
 * 
 * Sends data as JSON POST request to /propagation/edit endpoint.
 * Shows success/error toast notification based on response.
 * 
 * Time Complexity: O(n) where n is number of table rows
 * 
 * @async
 * @return {Promise<boolean>} True if save successful, false otherwise
 * 
 * @example
 *   const ok = await update();
 *   if (ok) { setPropagationDirty(false); }
 */
async function update() {
    const propagation_rows = document.querySelectorAll('#propagation-table tbody tr');
    const propagation = [];

    propagation_rows.forEach(row => {
        const cells = row.children;
        const feCell = cells[0];
        const threatCell = cells[1];
        const criticalityInp = cells[2].querySelector('input');

        const fe = feCell ? feCell.innerText.trim() : '';
        const threat = threatCell ? threatCell.innerText.trim() : '';
        const criticality = criticalityInp ? criticalityInp.value.trim() || 0 : 0;

        propagation.push([fe, threat, criticality]);
    });

    const url = `/propagation/edit`;

    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ propagation: propagation })
        });

        if (resp.ok) {
            showToast('Changes saved', 'success');
            return true;
        } else {
            showToast('Save failed', 'error');
        }
    } catch (err) {
        showToast('Save failed', 'error');
    }
}

// ===== NOTIFICATION FUNCTIONS =====

/**
 * Displays a temporary toast notification message to the user.
 * 
 * Creates a new toast element and appends it to the toast container.
 * Automatically fades out and removes the element after 2.5 seconds.
 * Multiple toasts can appear simultaneously, stacked vertically.
 * 
 * Time Complexity: O(1) DOM manipulation
 * 
 * @param {string} message - Text content to display in the toast
 * @param {string} [type='success'] - Toast type: 'success' (green) or 'error' (red)
 * @return {void}
 * 
 * @example
 *   showToast('Configuration saved', 'success')
 *   showToast('Failed to save', 'error')
 */
function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
    }

    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = message;
    t.style.opacity = '1';
    t.style.transform = 'translateY(0)';
    container.appendChild(t);

    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transform = 'translateY(8px)';
        t.addEventListener('transitionend', () => t.remove(), { once: true });
    }, 2500);
}

// ===== NAVIGATION HANDLERS =====

/**
 * Handles navigation to the propagation page, saving changes if needed.
 * 
 * Behavior depends on dirty state:
 * - If dirty: saves changes via update() before navigating
 * - If clean: navigates immediately without saving
 * 
 * Uses the propagation-url data attribute for the target URL.
 * 
 * Time Complexity: O(n) if saving (where n is number of rows), O(1) if just navigating
 * 
 * @async
 * @return {Promise<void>}
 * 
 * @example
 *   handleGoToPropagation()  // Saves if dirty, then navigates
 */
async function handleGoToPropagation() {
    if (propagationIsDirty) {
        const ok = await update();
        if (ok) {
            setPropagationDirty(false);
        }
        return;
    }

    window.location.href = document.getElementById('propagation-url').getAttribute('data-url');
}
