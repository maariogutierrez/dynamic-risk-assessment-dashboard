"""Flask-based web application for threat and risk assessment visualization.

This module provides a web interface for analyzing cybersecurity risks, threat scenarios,
feared events, and asset propagation paths using ontology-based modeling. The application
integrates with Elasticsearch for data persistence and retrieval, and leverages OWL
ontologies for threat modeling and risk assessment calculations.

The application exposes a series of REST endpoints for:
  - Visualizing threat and risk propagation across assets
  - Editing propagation relationships between feared events and threats
  - Sorting and filtering risk assessment data
  - Serving static assets and ontology-derived visualizations

All data is stored and queried from Elasticsearch indices representing:
  - Original ontology entities (threats_o, feared_events_o, potential_risks_o)
  - Propagated/derived entities (threats_p, feared_events_p, potential_risks_p)
  - Assets and their relationships
"""

import argparse
import csv
import logging
import os
import sys

from elasticsearch import Elasticsearch
from flask import (
    Flask,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from logging.handlers import RotatingFileHandler



# Setup logging once at startup.
def setup_logging(
    log_path: str = "logs/app.log",
    max_bytes: int = 10_000_000,
    backup_count: int = 2,
    logging_level=logging.INFO,
) -> None:
    """Configures application-wide logging with rotating file handler.
    
    Sets up a rotating file handler to prevent unbounded log file growth. Suppresses
    verbose logging from Elasticsearch and transport layers to reduce noise. Should be
    called once at application startup before any other logging operations.
    
    Args:
        log_path: Filesystem path where log files will be written. Parent directories
            are created if they don't exist. Defaults to "logs/app.log".
        max_bytes: Maximum size in bytes for each log file before rotation occurs.
            Defaults to 10MB (10_000_000 bytes).
        backup_count: Number of backup log files to retain before oldest is deleted.
            Defaults to 2 (keeping current + 2 backups).
        logging_level: Logging level threshold (e.g., logging.INFO, logging.DEBUG).
            Defaults to logging.INFO.
    """
    """Configures application-wide logging with rotating file handler.
    
    Sets up a rotating file handler to prevent unbounded log file growth. Suppresses
    verbose logging from Elasticsearch and transport layers to reduce noise. Should be
    called once at application startup before any other logging operations.
    
    Args:
        log_path: Filesystem path where log files will be written. Parent directories
            are created if they don't exist. Defaults to "logs/app.log".
        max_bytes: Maximum size in bytes for each log file before rotation occurs.
            Defaults to 10MB (10_000_000 bytes).
        backup_count: Number of backup log files to retain before oldest is deleted.
            Defaults to 2 (keeping current + 2 backups).
        logging_level: Logging level threshold (e.g., logging.INFO, logging.DEBUG).
            Defaults to logging.INFO.
    """
    # Ensure log directory exists before attempting to write logs.
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    # Configure root logger with specified level.
    logger = logging.getLogger()
    logger.setLevel(logging_level)

    # Suppress verbose logging from external dependencies to improve signal-to-noise ratio.
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)

    # Add rotating file handler only once to avoid duplicate log entries.
    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
        )
        logger.addHandler(handler)


setup_logging()
logger = logging.getLogger(__name__)


# Add project root to import path for scripts package.
# This enables the Flask application to import the scripts module containing
# Elasticsearch integration and ontology management utilities.
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import ontology management and Elasticsearch integration modules.
import scripts.import_onto_es as es_manager
import scripts.manager as onto_manager


# Initialize Flask application with a secret key for session management.
app = Flask(__name__)
app.secret_key = "e5233c681def00d5be414b7abfef1d9a"

# Initialize Elasticsearch client and configure cluster settings.
# The id_field_data setting enables efficient sorting and filtering on the _id field.
es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"))
es.cluster.put_settings(body={"persistent": {"indices.id_field_data.enabled": "true"}})

# == Application Startup ==
# Performs initial data load and risk assessment calculation.
# This context manager ensures operations are bound to the Flask application context,
# allowing access to the current app instance within the ontology management functions.
with app.app_context():
    # Reload and parse the OWL ontology from the data directory.
    onto_manager.reload_ontology()
    # Execute risk assessment algorithms on the loaded ontology.
    onto_manager.risk_assessment()
    # Index the ontology entities into Elasticsearch, replacing any existing indices.
    current_app.ontology = es_manager.onto_to_ES(es, reset=True)


# == Route Handlers ==
# The following route handlers manage HTTP requests and render views for the application.

@app.route("/")
def home():
    """Redirect from root to the primary propagation analysis view."""
    return redirect(url_for("propagation"))


@app.route("/images/<path:filename>")
def serve_images(filename):
    """Serve static image files from the application images directory.
    
    Args:
        filename: The image filename (supports subdirectories via path parameter).
        
    Returns:
        File contents from the images directory, or 404 if not found.
    """
    return send_from_directory(os.path.join(current_dir, "images"), filename)


@app.route("/assets")
def assets():
    """Render the assets view with optional sorting and filtering.
    
    Fetches all assets from Elasticsearch and presents them in a tabular format.
    Supports client-requested sorting by multiple fields with ascending/descending order.
    
    Query Parameters:
        sort_field: Field name to sort by (type, description, importance, risk_level,
            propagated_risk_level, relative_risk_level). If not provided, maintains
            natural order from Elasticsearch.
        sort_order: Sort direction as either "asc" (ascending) or "desc" (descending).
            Defaults to "asc".
        asset: Optional asset ID/name for visual highlighting or pre-selection in UI.
        
    Returns:
        Rendered HTML template with assets list and sort toggle state.
    """
    # Fetch all assets from Elasticsearch with a high size limit to ensure complete result set.
    assets_all = [d["_source"] for d in es.search(index="assets", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    
    # Extract sort parameters from request query string.
    sort_field = request.args.get("sort_field")
    sort_order = request.args.get("sort_order", "asc")
    reverse = sort_order == "desc"
    
    # Apply sorting if a valid sortable field is requested.
    # Defaults to 0 for null/missing values to handle sparse data gracefully.
    if sort_field in {"type", "description", "importance", "risk_level", "propagated_risk_level", "relative_risk_level"}:
        assets_all = sorted(
            assets_all,
            key=lambda doc: doc.get(sort_field) if doc.get(sort_field) is not None else 0,
            reverse=reverse,
        )
    
    # Toggle button logic: show opposite sort order for next request.
    next_sort_order = "desc" if sort_order == "asc" else "asc"
    
    return render_template(
        "assets.html",
        assets=assets_all,
        next_sort_order=next_sort_order,
        asset=request.args.get("asset", ""),
    )

@app.route("/propagation/edit", methods=["GET", "POST"])
def propagation_edit():
    """Manage propagation relationships between feared events and threats.
    
    This endpoint provides a form interface for editing the propagation matrix that
    defines how threats propagate to feared events. It supports both viewing and
    persisting changes to the propagation.csv file.
    
    For GET requests:
        Retrieves the current propagation data and available feared events/threats
        to populate the editing interface.
        
    For POST requests:
        Accepts JSON data containing updated propagation relationships, persists
        changes to disk, reloads and reassesses the ontology, and re-indexes all
        entities in Elasticsearch.
        
    Request JSON (POST):
        {
            "propagation": [
                ["feared_event_id", "threat_id", "min_criticality"],
                ...
            ]
        }
        
    Returns:
        GET: Rendered HTML template with propagation form.
        POST: JSON response with status and HTTP 200, or error status.
    """
    # File paths for data persistence (relative to flaskProject directory).
    propagation_path = "../data/propagation.csv"
    fe_path = "../data/fe.csv"
    threat_path = "../data/threat_scenarios.csv"

    if request.method == "POST":
        # Parse JSON payload from request body.
        data = request.get_json(silent=True) or {}
        propagation = data.get("propagation", [])

        # Persist updated propagation relationships to CSV file.
        with open(propagation_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["fe", "threat", "min_criticality"])
            for row in propagation:
                writer.writerow(row)

        # Reload ontology to reflect changes in the propagation matrix.
        onto_manager.reload_ontology()
        # Recalculate risk assessments based on new propagation relationships.
        onto_manager.risk_assessment()
        # Re-index all ontology entities into Elasticsearch (reset=True clears old data).
        es_manager.onto_to_ES(es, reset=True)

        return jsonify({"status": "success"}), 200

    # == GET Request Handler ==
    # Load existing propagation relationships from CSV.
    propagation = []
    with open(propagation_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header row.
        for row in reader:
            propagation.append(row)

    # Load all feared events for the dropdown selection.
    feared_events = []
    with open(fe_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header row.
        for row in reader:
            feared_events.append(row[0])

    # Load all unique threats for the dropdown selection.
    threats = []
    with open(threat_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # Skip header row.
        for row in reader:
            # Avoid duplicate threat IDs by checking membership first.
            if row[0] not in threats:
                threats.append(row[0])

    return render_template(
        "propagationEdit.html",
        propagation=propagation,
        fe=feared_events,
        threat=threats,
    )




@app.route("/propagation")
def propagation():
    """Render threat and feared event propagation visualization.
    
    This endpoint generates propagation chains starting from either an original threat
    or feared event, traversing the propagation graph to show how risks spread through
    the system. Supports filtering to show either all propagation or only direct threats.
    
    The propagation model uses a breadth-first search (BFS) approach to traverse threat
    and feared event relationships, building a complete propagation chain.
    
    Query Parameters:
        threat: ID of an original threat (threats_o) to start propagation from.
        feared_event: ID of an original feared event (feared_events_o) to start from.
        show_few: If "true", omits leaf-node threats with no further propagation.
                  Defaults to "false" (show all nodes).
        
    Returns:
        Rendered HTML template with original/propagated threats/feared events, affected
        assets, and relationship information for visualization.
        
    Note:
        If both threat and feared_event parameters are provided, threat takes precedence.
        This endpoint queries Elasticsearch multiple times (once per node in traversal),
        which may be slow for large propagation chains. Consider implementing batch
        operations or caching for performance improvement.
    """
    # Fetch all original feared events and filter to only those that propagate.
    feared_events_o = [d["_source"] for d in es.search(index="feared_events_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events_o = [doc for doc in feared_events_o if doc.get("propagates_to")]
    # Build a set of feared event IDs that have propagations for quick membership testing.
    fe_o_ids = {fe["feared_event_id"] for fe in feared_events_o}

    # Fetch all original threats and filter to only those that generate feared events
    # that propagate (to reduce visual clutter).
    threats_o_all = [d["_source"] for d in es.search(index="threats_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    threats_o = [
        doc
        for doc in threats_o_all
        if any(
            g in fe_o_ids
            for g in doc["generates"]
        )
        and doc.get("generates")
    ]

    # Initialize result containers for propagated (derived) entities.
    feared_events_p = []
    threats_p = []

    # Extract query parameters to determine which propagation chain to render.
    threat_o_id = request.args.get("threat", "")
    fe_o_id = request.args.get("feared_event", "")
    show_few = request.args.get("show_few", "false")

    # Initialize selected entity containers with empty defaults.
    selected_threat_o = {"threat_id": ""}
    selected_fe_o = {"feared_event_id": ""}

    # == Threat-centric Propagation Path ==
    if threat_o_id:
        # Fetch the selected original threat and its feared events.
        selected_threat_o = es.get(index="threats_o", id=threat_o_id)["_source"]
        fe_os = []
        generated = selected_threat_o.get("generates", [])

        # Load all feared events generated by the selected threat.
        for fe_id in generated:
            if fe_id:
                fe_os.append(es.get(index="feared_events_o", id=fe_id)["_source"])

        # Initialize BFS queue with feared events that have propagations.
        queue = [fe for fe_o in fe_os for fe in fe_o.get("propagates_to", [])]
        propagation_edges = []

        # BFS traversal: expand propagation chain by following threat → feared_event edges.
        while queue:
            threat_id = queue.pop(0)
            threat_p = es.get(index="threats_p", id=threat_id)["_source"]
            generated_p = threat_p.get("generates")

            if generated_p:
                # Threat has generated feared events; continue propagation chain.
                for fe_id in generated_p:
                    fe_p = es.get(index="feared_events_p", id=fe_id)["_source"]
                    propagation_edges.append((threat_p["threat_id"], fe_p["feared_event_id"]))
                    # Add next-level propagations to queue.
                    queue.extend(fe_p.get("propagates_to", []))
            elif show_few == "false":
                # Threat is a leaf node (no further propagation) and show_few is off.
                propagation_edges.append((threat_p["threat_id"], None))

        # Populate result sets with original threat and its direct feared events.
        threats_p = [selected_threat_o]
        feared_events_p = fe_os.copy()
        if len(fe_os) == 1:
            selected_fe_o = fe_os[0]
        else:
            selected_fe_o = fe_os

        # Add all discovered propagated threats and feared events to results.
        for threat_id, fe_id in propagation_edges:
            threat = es.get(index="threats_p", id=threat_id)["_source"]
            threats_p.append(threat)
            if fe_id:
                fe = es.get(index="feared_events_p", id=fe_id)["_source"]
                feared_events_p.append(fe)

    # == Feared Event-centric Propagation Path ==
    elif fe_o_id:
        # Find the original threat that generates the selected feared event.
        all_threats_o = [d["_source"] for d in es.search(index="threats_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]

        for threat in all_threats_o:
            generated = threat.get("generates", [])
            if fe_o_id in generated:
                selected_threat_o = threat
                break

        # Fetch the selected feared event.
        selected_fe_o = es.get(index="feared_events_o", id=fe_o_id)["_source"]

        # Initialize BFS queue with propagations from the selected feared event.
        queue = list(selected_fe_o.get("propagates_to", []))
        propagation_edges = []

        # BFS traversal: expand propagation chain from the feared event.
        while queue:
            threat_id = queue.pop(0)
            threat_p = es.get(index="threats_p", id=threat_id)["_source"]
            generated_p = threat_p.get("generates")

            if generated_p:
                # Normalize generated_p to a list for consistent iteration.
                generated_ids = generated_p if isinstance(generated_p, list) else [generated_p]
                for fe_id in generated_ids:
                    fe_p = es.get(index="feared_events_p", id=fe_id)["_source"]
                    propagation_edges.append((threat_p["threat_id"], fe_p["feared_event_id"]))
                    # Add next-level propagations to queue.
                    queue.extend(fe_p.get("propagates_to", []))
            elif show_few == "false":
                # Leaf node with no further propagation.
                propagation_edges.append((threat_p["threat_id"], None))

        # Populate result sets starting with the original threat and selected feared event.
        threats_p = [selected_threat_o] if selected_threat_o else []
        feared_events_p = [selected_fe_o]

        # Add all discovered propagated threats and feared events to results.
        for threat_id, fe_id in propagation_edges:
            threat = es.get(index="threats_p", id=threat_id)["_source"]
            threats_p.append(threat)
            if fe_id:
                fe = es.get(index="feared_events_p", id=fe_id)["_source"]
                feared_events_p.append(fe)

    # == Asset Impact Analysis ==
    # Fetch all assets from the system.
    assets_all = [d["_source"] for d in es.search(index="assets", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]

    # Determine which assets are affected by the propagated feared events and threats.
    affected_by_fe = {
        asset_id
        for fe in feared_events_p
        for asset_id in (fe.get("affects") if isinstance(fe.get("affects"), list) else [fe.get("affects")] if fe.get("affects") else [])
        if asset_id
    }
    affected_by_threat = {
        asset_id
        for threat in threats_p
        for asset_id in (threat.get("affects") if isinstance(threat.get("affects"), list) else [threat.get("affects")] if threat.get("affects") else [])
        if asset_id
    }

    # Filter assets to only those affected by the propagation chain.
    assets = [
        asset
        for asset in assets_all
        if asset.get("asset_id") in affected_by_fe or asset.get("asset_id") in affected_by_threat
    ]

    # Fetch all asset relationships for visualization.
    relationships = [d["_source"] for d in es.search(index="relationships", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]

    return render_template(
        "propagation.html",
        feared_events_o=feared_events_o,
        threats_o=threats_o,
        feared_events_p=feared_events_p,
        threats_p=threats_p,
        threat_o=selected_threat_o,
        feared_event_o=selected_fe_o,
        assets=assets,
        relationships=relationships,
    )




@app.route("/threats")
def threats():
    """Render comparison view of original vs. propagated threats.
    
    Displays threats in a side-by-side comparison showing the original threat model
    and the derived threats resulting from propagation. Supports filtering to show
    only threats that generate feared events (reducing noise from isolated threats).
    
    Query Parameters:
        filter: If present, filters results to show only threats that generate
                feared events. Omitting this parameter shows all threats.
        
    Returns:
        Rendered HTML template with original and propagated threats/feared events.
    """
    # Fetch all threats from both original and propagated indices.
    threats_original = [d["_source"] for d in es.search(index="threats_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    threats_propagated = [d["_source"] for d in es.search(index="threats_p", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events_original = [d["_source"] for d in es.search(index="feared_events_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events_propagated = [d["_source"] for d in es.search(index="feared_events_p", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]

    # Optional filtering: show only threats that generate feared events.
    if request.args.get("filter"):
        threats_original = [t for t in threats_original if t.get("generates")]
        threats_propagated = [t for t in threats_propagated if t.get("generates")]

    return render_template(
        "threats.html",
        threats=threats_original,
        threats_p=threats_propagated,
        feared_events=feared_events_original,
        feared_events_p=feared_events_propagated,
    )


@app.route("/feared_events")
def feared_events():
    """Render comparison view of original vs. propagated feared events with sorting.
    
    Combines feared events from both original and propagated models, with support for
    sorting by quantitative fields and filtering to show only original events.
    
    Query Parameters:
        sort_field: Field to sort results by ("probability" or "impact").
                   If not provided, maintains natural ordering.
        sort_order: Sort direction ("asc" or "desc"). Defaults to "asc".
        filter_original: If present, shows only feared events from the original
                        model (filtered from the sorted combined list).
        fe: Optional feared event ID for pre-selection or highlighting in UI.
        
    Returns:
        Rendered HTML template with feared events list.
    """
    # Fetch all feared events from both original and propagated indices.
    feared_events_original = [d["_source"] for d in es.search(index="feared_events_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events_propagated = [d["_source"] for d in es.search(index="feared_events_p", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]

    # Extract sort parameters from request.
    sort_field = request.args.get("sort_field")
    sort_order = request.args.get("sort_order", "asc")
    reverse = sort_order == "desc"
    filter_original = request.args.get("filter_original")

    # Combine all feared events for unified sorting.
    all_feared_events = feared_events_original + feared_events_propagated

    # Apply sorting by quantitative fields if requested.
    if sort_field in {"probability", "impact"}:
        all_feared_events = sorted(
            all_feared_events,
            key=lambda doc: doc.get(sort_field) if doc.get(sort_field) is not None else 0,
            reverse=reverse,
        )

    # Apply optional filtering to show only original feared events.
    if filter_original:
        # Get original feared events IDs
        original_ids = {doc["feared_event_id"] for doc in feared_events_original}
        fe_to_display = [doc for doc in all_feared_events if doc["feared_event_id"] in original_ids]
        return render_template(
            "feared_events.html",
            feared_events=fe_to_display,
            feared_event=request.args.get("fe", ""),
        )
    else:
        # Show all feared events combined without distinction
        return render_template(
            "feared_events.html",
            feared_events=all_feared_events,
            feared_event=request.args.get("fe", ""),
        )


@app.route("/risks")
def risks():
    """Render risk assessment view with original vs. propagated risks.
    
    Displays potential risks combining both the original risk model and risks
    derived from threat propagation. Supports multi-field sorting, filtering
    to original risks only, and integrates feared event and system context.
    
    Risk Score Interpretation:
        risk_level: The inherent risk value (probability × impact).
        relative_risk_level: Risk normalized relative to the maximum risk in the system.
    
    Query Parameters:
        sort_field: Field to sort by ("probability", "impact", "risk_level",
                   "relative_risk_level"). If not provided, maintains natural order.
        sort_order: Sort direction ("asc" or "desc"). Defaults to "asc".
        filter_original: If present, filters results to show only original risks
                        (filtered from the sorted combined list).
        risk: Optional risk ID for pre-selection or highlighting in UI.
        
    Returns:
        Rendered HTML template with sorted and filtered risk list.
    """
    # Fetch risks from both original and propagated models.
    potential_risks = [d["_source"] for d in es.search(index="potential_risks_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    potential_propagated_risks = [d["_source"] for d in es.search(index="potential_risks_p", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    # Fetch context data (feared events and system configuration).
    feared_events_original = [d["_source"] for d in es.search(index="feared_events_o", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events_propagated = [d["_source"] for d in es.search(index="feared_events_p", body={"query": {"match_all": {}}, "size": 5000})["hits"]["hits"]]
    feared_events = feared_events_original + feared_events_propagated
    system = next(iter([d["_source"] for d in es.search(index="system", body={"query": {"match_all": {}}, "size": 1})["hits"]["hits"]]), None)

    # Extract sort parameters.
    sort_field = request.args.get("sort_field")
    sort_order = request.args.get("sort_order", "asc")
    reverse = sort_order == "desc"
    filter_original = request.args.get("filter_original")

    # Combine all risks for unified sorting.
    all_potential_risks = potential_risks + potential_propagated_risks

    # Apply sorting by valid sortable fields.
    if sort_field in {"probability", "impact", "risk_level", "relative_risk_level"}:
        all_potential_risks = sorted(
            all_potential_risks,
            key=lambda doc: doc.get(sort_field) if doc.get(sort_field) is not None else 0,
            reverse=reverse,
        )

    # Apply optional filtering to show only original risks.
    if filter_original:
        # Get original risk IDs for filtering.
        original_ids = {doc["potential_risk_id"] for doc in potential_risks}
        risks_to_display = [doc for doc in all_potential_risks if doc["potential_risk_id"] in original_ids]
    else:
        # Show all risks combined without distinction.
        risks_to_display = all_potential_risks

    # For sort toggle button in UI.
    next_sort_order = "desc" if sort_order == "asc" else "asc"

    return render_template(
        "risks.html",
        potential_risks=risks_to_display,
        feared_events=feared_events,
        system=system,
        next_sort_order=next_sort_order,
        risk=request.args.get("risk", ""),
        filter_original=filter_original,
    )




@app.route("/risk_color/<int:risk_value>")
def risk_color(risk_value):
    """Return hex color code for visualizing risk severity.
    
    Maps numerical risk values (1-50) to a color gradient that communicates risk
    severity. Uses a green→yellow→orange→red spectrum aligned with common risk
    assessment frameworks.
    
    Risk Categories and Color Mapping:
        1 (Very Low):           #00AA00 (green)
        2-3 (Low):              #55DD00 (light green)
        4-5 (Low-Medium):       #BBDD00 (yellow-green)
        6-7 (Medium):           #FFDD00 (yellow)
        8-10 (Medium-High):     #FF9900 (orange)
        11-16 (High):           #FF5500 (dark orange)
        17-21 (High-Very High): #FF3333 (red-orange)
        22-28 (Very High):      #DD0000 (red)
        29-36 (V.High-Critical):#BB0000 (dark red)
        37-50 (Critical):       #990000 (very dark red)
    
    Args:
        risk_value: Integer risk score in the range [1, 50].
        
    Returns:
        Hex color code string (e.g., "#FF5500"). Returns "#CCCCCC" (gray) for
        values outside the expected range.
        
    Note:
        This function is typically called via HTTP route to retrieve HTML/CSS
        compatible color values for risk visualizations on dashboards.
    """
    # Mapping of risk values to hex colors. Ranges are contiguous to ensure
    # all values 1-50 are covered without gaps.
    color_map = {
        1: "#00AA00",
        2: "#55DD00", 3: "#55DD00",
        4: "#BBDD00", 5: "#BBDD00",
        6: "#FFDD00", 7: "#FFDD00",
        8: "#FF9900", 9: "#FF9900", 10: "#FF9900",
        11: "#FF5500", 12: "#FF5500", 13: "#FF5500", 14: "#FF5500", 15: "#FF5500", 16: "#FF5500",
        17: "#FF3333", 18: "#FF3333", 19: "#FF3333", 20: "#FF3333", 21: "#FF3333",
        22: "#DD0000", 23: "#DD0000", 24: "#DD0000", 25: "#DD0000", 26: "#DD0000", 27: "#DD0000", 28: "#DD0000",
        29: "#BB0000", 30: "#BB0000", 31: "#BB0000", 32: "#BB0000", 33: "#BB0000", 34: "#BB0000", 35: "#BB0000", 36: "#BB0000",
        37: "#990000", 38: "#990000", 39: "#990000", 40: "#990000", 41: "#990000", 42: "#990000", 43: "#990000", 44: "#990000", 45: "#990000", 46: "#990000", 47: "#990000", 48: "#990000", 49: "#990000", 50: "#990000",
    }
    
    # Default to gray for out-of-range values (defensive programming).
    color = color_map.get(risk_value, "#CCCCCC")
    return color


if __name__ == "__main__":
    """Application entry point.
    
    Parses command-line arguments and starts the Flask development server.
    The -p flag allows customization of the listening port.
    
    Example Usage:
        python app.py              # Runs on default port 5002
        python app.py -p 8000     # Runs on port 8000
        
    Debug Flags:
        debug=True:        Enables auto-reloading on code changes and detailed
                           error messages in browser.
        use_reloader=True: Automatically restarts the server when source files change.
        
    Note:
        This is the development server and should not be used in production.
        Deploy using a WSGI application server (e.g., Gunicorn, uWSGI).
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", type=int, default=5002, help="Port to use")
    args = parser.parse_args()

    app.run(host="0.0.0.0", port=args.p, debug=True, use_reloader=True)
