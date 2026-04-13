"""Ontology management and risk assessment engine for cybersecurity threat modeling.

This module implements a comprehensive threat modeling and dynamic risk assessment system
based on OWL ontologies. It combines asset modeling, threat scenario definition, and
threat propagation analysis to compute both static and propagated risk levels across a
system architecture.

Core Responsibilities:
  1. Ontology Management: Load, parse, and persist OWL ontology files representing
     system architecture, threats, and risks.
  2. Data Ingestion: Import asset catalogs and threat scenarios from CSV files into the ontology.
  3. Risk Propagation: Implement threat propagation algorithms to discover secondary
     risks resulting from cascading failures through system relationships.
  4. Risk Calculation: Compute risk scores using quantitative risk assessment matrices
     (probability × impact framework).

Key Concepts:
  - Original Entities (suffix _o): User-defined base entities (assets, threats, risks)
  - Propagated Entities (suffix _p): Derived entities from threat propagation analysis
  - Relationship Graph: Asset-to-asset connections with criticality ratings
  - Risk Matrix: Quantitative mapping of probability and impact to risk levels

Data Files Expected:
  - dra.owl: Base ontology schema (classes, properties, structure)
  - dra_full.owl: Complete ontology with instances (generated/updated by this module)
  - assets.csv: System assets with importance ratings
  - assets_relationships.csv: Asset-to-asset connections with criticality
  - threat_scenarios.csv: Threat-to-feared-event mappings
  - threat_assets.csv: Threat-to-asset associations
  - fe.csv: Feared event descriptions and impacts
  - matrix.csv: Risk assessment matrix (probability vs. impact)
  - propagation.csv: Propagation rules (feared event → threat connections)
  - system.csv: System-level metadata

Algorithms:
  - Threat Propagation: BFS traversal of asset relationship graph, triggered by feared
    events, following criticality thresholds defined in propagation.csv.
  - Risk Assessment: ITSRM-based methodology calculating risk_level = max(all_risks)
    per asset, with relative_risk_level normalized by asset importance.

Usage:
    # Standalone risk assessment:
    python manager.py -a -p ../data
    
    # Library usage in Flask app:
    from scripts.manager import risk_assessment, reload_ontology
    onto = reload_ontology(path="../data")
    risk_assessment(path="../data")
"""
import statistics, math, argparse
from owlready2 import get_ontology, World, destroy_entity, owl
import pandas as pd 
from collections import defaultdict
import shutil
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import os
import logging
import json

logger = logging.getLogger(__name__)

# == CSV Caching ==
# Cache for CSV files to avoid repeated disk I/O for frequently-accessed data.
# Key: (file_path, kwargs_hash), Value: {mtime_ns, data}
_CSV_CACHE = {}

def _read_cached_csv(path, **kwargs):
    """Read CSV file with caching based on modification time.
    
    Implements a simple file-based cache to avoid redundant CSV parsing. The cache
    is validated by checking the file's modification time (mtime_ns). If the file
    has been modified since the last read, the cache is invalidated and the file
    is re-read.
    
    Args:
        path: Filesystem path to the CSV file to read.
        **kwargs: Additional keyword arguments passed to pd.read_csv() (e.g., dtype,
                 index_col, skiprows). These are included in the cache key to ensure
                 different read configurations don't collide.
                 
    Returns:
        pandas.DataFrame: The parsed CSV data.
        
    Raises:
        FileNotFoundError: If the specified CSV file does not exist.
        pandas.errors.ParserError: If the CSV file is malformed or cannot be parsed.
        
    Performance Notes:
        First read: O(n) where n is file size (disk read + parsing).
        Cached read: O(1) if file unmodified (dictionary lookup).
        Cache invalidation: Automatic when file mtime changes.
    """
    csv_path = Path(path)
    # Build cache key from absolute path and sorted kwargs to ensure consistency.
    cache_key = (str(csv_path.resolve()), tuple(sorted(kwargs.items())))
    try:
        # Get file modification time in nanoseconds for precision.
        mtime_ns = csv_path.stat().st_mtime_ns
    except FileNotFoundError:
        # File no longer exists; remove from cache if present.
        _CSV_CACHE.pop(cache_key, None)
        raise

    # Check if file is in cache and hasn't been modified.
    cached = _CSV_CACHE.get(cache_key)
    if cached and cached["mtime_ns"] == mtime_ns:
        # Cache hit: return cached data without re-reading.
        return cached["data"]

    # Cache miss or invalidation: read and parse CSV file.
    data = pd.read_csv(csv_path, **kwargs)
    # Store in cache with modification time for future validation.
    _CSV_CACHE[cache_key] = {
        "mtime_ns": mtime_ns,
        "data": data,
    }
    return data

def _load_threat_catalogues(path):
    """Load threat scenarios and feared event definitions from disk.
    
    Convenience wrapper that loads both the threat scenario catalog and feared
    event definitions in a single call. Both files are loaded via the CSV cache
    to avoid redundant I/O.
    
    Args:
        path: Filesystem path to the directory containing the CSV files.
        
    Returns:
        tuple: (scenarios_df, feared_events_df) where:
            - scenarios_df: DataFrame with threat_scenarios.csv contents. Columns:
                type, asset, FE (feared event name), likelihood
            - feared_events_df: DataFrame with fe.csv contents. Columns: name, impact
    """
    return (
        _read_cached_csv(f"{path}/threat_scenarios.csv"),
        _read_cached_csv(f"{path}/fe.csv"),
    )

def load_system(o_s, path="../data"):
    """Load system-level metadata from CSV into the ontology.
    
    Reads the system.csv file and creates a System individual in the ontology
    representing the entire managed system. The system entity acts as a top-level
    container for aggregate risk scores and metadata.
    
    Args:
        o_s: owlready2 ontology object where the System individual will be created.
        path: Filesystem path to the directory containing system.csv. Defaults to "../data".
        
    Returns:
        None. The system individual is added to the ontology as a side effect.
        
    Note:
        Expects exactly one row in system.csv; only the first row (iloc[0]) is used.
        The 'id' column value from the CSV becomes the ontology individual name.
    """
    with o_s:
        # Load system information from CSV file.
        system_data = pd.read_csv(f'{path}/system.csv')
        # Extract metadata from first row.
        sys_info = system_data.iloc[0]
        # Create System individual in ontology using the ID from CSV.
        o_s.System(sys_info['id'])

    logger.info("-" * 100)
    logger.info("System loaded")
    logger.info("-" * 100)    

def load_assets(o_a, path="../data"):
    """Load system assets and their relationships from CSV files into the ontology.
    
    Performs a two-pass load process:
    1. First Pass: Creates Asset individuals from assets.csv, each with properties like
       importance, type, and description.
    2. Second Pass: Creates Relationship individuals representing asset-to-asset
       connections, populated after all assets exist to enable relationship creation.
    
    Asset relationships are directional (source → target) and include a criticality
    rating that determines whether threats can propagate across the relationship
    (checked during threat propagation analysis).
    
    Args:
        o_a: owlready2 ontology object where assets and relationships will be created.
        path: Filesystem path to the directory containing CSV files. Defaults to "../data".
              Expected files: assets.csv, assets_relationships.csv
        
    Returns:
        None. Assets and relationships are added to ontology and persisted to disk.
        
    Data Format (assets.csv):
        Columns: id, importance (int), class (asset type), name (description)
        
    Data Format (assets_relationships.csv):
        Columns: from_asset (str), to_asset (str), criticality (float), bidirectional (bool)
        
    Side Effects:
        - Creates Relationship individuals in the ontology
        - Modifies dra_full.owl on disk (appends new instances)
        - Logs warnings for broken asset references (missing from_asset or to_asset)
    """
    with o_a:
        # == Asset Creation Pass ==
        # Load the asset catalog from CSV and create individuals in the ontology.
        assets = pd.read_csv(f'{path}/assets.csv')
        for _, row in assets.iterrows():
            logger.debug(f"Loading asset {row['id']}")
            # Create asset individual under the base Assets class.
            instance = o_a.Assets(f"{row['id']}")
            # Set asset properties from CSV columns.
            instance.importance = row['importance']
            instance.type = row['class']
            instance.description = row['name']

        # == Relationship Creation Pass ==
        # After all assets exist, create relationship individuals.
        # This two-pass approach ensures references are valid.
        relationships = pd.read_csv(f'{path}/assets_relationships.csv', dtype={"from_asset": str, "to_asset": str})
        for _, row_r in relationships.iterrows():
            bidirectional = row_r['bidirectional']
            # Look up source and target assets by their IRI (Internationalized Resource Identifier).
            from_asset = o_a.search_one(iri=f"*#{row_r['from_asset']}")
            to_asset = o_a.search_one(iri=f"*#{row_r['to_asset']}")
            
            # Defensive programming: skip if either asset doesn't exist.
            if from_asset is None or to_asset is None:
                logger.warning(f"Relationship from {row_r['from_asset']} to {row_r['to_asset']} cannot be created because one of the assets does not exist. Ignoring.")
                continue

            # Create directed relationship from source to target.
            rel = o_a.Relationship(f'rel_{row_r["from_asset"]}_{row_r["to_asset"]}')  
            from_asset.source_of.append(rel)
            to_asset.target_of.append(rel)
            rel.criticality = row_r['criticality']

            # If bidirectional, create reverse relationship as well.
            if bidirectional == True:
                rel2 = o_a.Relationship(f'rel_{row_r["to_asset"]}_{row_r["from_asset"]}')
                to_asset.source_of.append(rel2)
                from_asset.target_of.append(rel2)
                rel2.criticality = row_r['criticality']

    # Persist new individuals to disk.
    o_a.save(f"{path}/dra_full.owl")
    
    logger.info("-" * 100)
    logger.info("New assets loaded")
    logger.info("-" * 100)

def risk_assessment(path="../data"):
    """Perform complete dynamic risk assessment including threat propagation.
    
    This is the primary orchestration function for threat modeling and risk calculation.
    It implements the ITSRM (IT Security Risk Management) methodology with threat
    propagation analysis. The process consists of three main phases:
    
    Phase 1 - Threat Loading & Propagation:
        Loads threat scenarios from CSV and processes threat propagation across asset
        relationships. Creates both original threats and propagated (secondary) threats,
        generating the full threat graph.
        
    Phase 2 - Risk Calculation:
        Computes risk scores for assets using the risk matrix (probability × impact).
        Tracks both original risks and risks from propagated threats.
        
    Phase 3 - System-Level Aggregation:
        Calculates total system risk as the maximum risk across all assets,
        providing a single metric for system-level risk reporting.
    
    Args:
        path: Filesystem path to data directory containing CSVs, OWL files, and
              the risk matrix. Defaults to "../data".
        
    Returns:
        None. Updates are persisted to dra_full.owl.
        
    Performance:
        Runtime typically 10-60 seconds depending on system size (number of assets,
        threats, relationships). Propagation phase usually dominates execution time.
        Large systems (100+ assets) may require optimization of graph traversal.
        
    Side Effects:
        - Modifies dra_full.owl (full propagation of threats and risks computed)
        - Creates temporary copy: dra_full_temp.owl (used during processing)
        - Persists propagation paths to propagation_paths.json
        
    Raises:
        FileNotFoundError: If required CSV files or OWL files don't exist.
    """
    # Reset propagation paths for fresh threat propagation analysis.
    # This ensures that propagation paths from previous runs don't interfere.
    propagation_paths = defaultdict(list)

    w = World()
    logger.info("-" * 100)
    logger.info("Starting recalculation of dynamic risk assessment  --  ITSRM")
    logger.info("-" * 100)
    init_time = time.time()
    
    # == Preparation ==
    # Create working copy of ontology to avoid data corruption during processing.
    shutil.copy(f"{path}/dra_full.owl", f"{path}/dra_full_temp.owl")
    onto = w.get_ontology(f"{path}/dra_full_temp.owl").load() 
    
    # == Phase 1: Threat & Propagation Loading ==
    # Load threats from CSV and execute threat propagation algorithm.
    load_threats(onto, path, propagation_paths=propagation_paths)
    onto.save(f"{path}/dra_full.owl")
    propagate_time = time.time()
    logger.info(f"Propagate time: {propagate_time - init_time} seconds")
    logger.info("-" * 100)

    # == Phase 2: Risk Calculation ==
    # Calculate risk scores for original threats and propagated threats.
    calculate_risk_asset(onto, path)  # Original risks (threat_o → FE_o → risk_o)
    propagated_risk_asset(onto)  # Propagated risks (threat_p → FE_p → risk_p)
    calculate_total_risk(onto, path)  # Aggregate original risk
    calculate_total_propagated_risk(onto, path)  # Aggregate propagated risk
    save_propagation_paths(propagation_paths, path)

    # == Persistence ==
    onto.save(f"{path}/dra_full.owl")
    risk_time = time.time()
    logger.info(f"Calculate risk time: {risk_time - propagate_time} seconds")
    logger.info("-" * 100)
    logger.info("-" * 100)
    logger.info("Dynamic risk assessment ended  --  ITSRM")
    logger.info("-" * 100)

    return onto

def load_threats(o_t, path="../data", propagation_paths=None):
    """Load threat scenarios from CSV into ontology.
    
    Reads threat_assets.csv and creates Threat_Original individuals for each
    threat-asset association found in the file. Each threat is associated with
    a specific asset and its corresponding feared events.
    
    Args:
        o_t: owlready2 ontology object where Threat individuals will be created.
        path: Filesystem path to data directory. Defaults to "../data".
        propagation_paths: Dictionary tracking threat propagation chains to prevent
                          infinite loops. Created if not provided.
    """
    if propagation_paths is None:
        propagation_paths = defaultdict(list)
    
    with o_t:
        # Load threat-to-asset associations from CSV.
        threats = pd.read_csv(f'{path}/threat_assets.csv', dtype={"asset": str})
        for _, row in threats.iterrows():
            # Create a threat for each row in the threat_assets CSV.
            create_threat(o_t, row["threat"], str(row["asset"]), path=path, propagation_paths=propagation_paths)

def create_threat(o_t, threat, asset, path="../data", propagation_paths=None):
    """Create a threat individual in the ontology and trigger feared event creation.
    
    Creates a Threat_Original individual linked to a specific asset. For each threat,
    this function:
    1. Creates the threat instance as a Threat_Original
    2. Links it to the target asset (via affects property)
    3. Generates feared events triggered by the threat
    4. Initiates threat propagation to discover secondary threats
    
    Args:
        o_t: owlready2 ontology object.
        threat: String name of the threat (e.g., "SQL Injection").
        asset: String ID of the target asset.
        path: Filesystem path to data directory. Defaults to "../data".
        propagation_paths: Dictionary tracking propagation chains (prevents loops).
        
    Returns:
        The created Threat_Original individual, or None if the target asset
        doesn't exist or another error occurs.
        
    Internal Logic:
        - Threat names are sanitized: spaces replaced with underscores for ontology IRIs
        - Threat individuals are uniquely named by appending a counter to prevent
          accidental overwrites if the same threat is created multiple times
        - The threat is marked as Threat_Original (not Threat_Propagated)
    """
    if propagation_paths is None:
        propagation_paths = defaultdict(list)
    
    with o_t:
        # Look up the target asset to ensure it exists before creating threat.
        asset = o_t.search_one(iri=f"*#{asset}")
        if asset:
            logger.debug(f"Creating threat {threat} over asset {asset}")
            # Sanitize threat name for ontology IRI (replace spaces with underscores).
            threat = threat.replace(" ", "_")
            # Count existing threats with similar names to generate unique identifier.
            anteriores = str(len(o_t.search(iri=f"*#{threat}*")))
            # Create threat individual with unique name.
            ind = o_t.Threat_Original(threat + '_' + anteriores)
            ind.is_a.append(o_t.Threat)  # Mark as base threat class.
            ind.affects.append(asset)
            
            # Generate feared events that this threat can trigger.
            create_feared_event(o_t, asset, ind, path, propagation_paths=propagation_paths)
            return ind
        else:
            logger.warning(f"Creating threat {threat} over non existing asset. Ignoring")
            return None
  
def create_feared_event(o_fe, asset, threat, path="../data", propagation_id=None, propagation_paths=None):
    """Create original feared events triggered by a threat on an asset.
    
    Given a threat affecting an asset, looks up the threat scenarios that apply
    (from threat_scenarios.csv) and creates FE_Original individuals for each
    matching scenario. The scenarios are filtered by threat type and asset ID.
    
    For each feared event created, this function also:
    1. Creates associated risks via create_risk()
    2. Initiates threat propagation to secondary assets via propagate()
    
    Args:
        o_fe: owlready2 ontology object.
        asset: Asset individual being threatened.
        threat: Threat individual triggering the feared events.
        path: Filesystem path to data directory. Defaults to "../data".
        propagation_id: Unique identifier for this propagation chain (prevents loops).
                       Automatically generated from the first feared event name if None.
        propagation_paths: Dictionary mapping propagation_id → list of (threat, asset)
                          tuples already visited (prevents infinite loops).
    """
    if propagation_paths is None:
        propagation_paths = defaultdict(list)
    
    with o_fe:
        # Load threat scenario and feared event catalogs.
        scenarios, fe = _load_threat_catalogues(path)
        asset_name = str(asset).split(".")[1]
        threat_name = str(threat).split('.')[1]
        threat_name = threat_name.rsplit("_", 1)[0]  # Remove numeric suffix.
        
        # Generate propagation_id early if not provided.
        if not propagation_id:
            # Use threat name and asset as basis for propagation chain ID.
            propagation_id = f"{threat_name}_{asset_name}"
        
        # Track original threat in the propagation path.
        original_threat_key = list((threat_name, asset_name))
        if original_threat_key not in propagation_paths[propagation_id]:
            propagation_paths[propagation_id].append(original_threat_key)
            logger.debug(f"Tracked original threat {threat_name} on asset {asset_name} in propagation chain {propagation_id}")
        
        # Filter scenarios that apply to this threat type and asset.
        # Scenarios with asset="all" apply globally; otherwise asset-specific.
        data_ts = scenarios[(scenarios["type"] == threat_name.replace("_", " ")) & 
                           ((scenarios["asset"] == asset_name) | scenarios["asset"].str.contains("all", case=False))]
        
        for index, row in data_ts.iterrows():
            # Create unique feared event individual.
            anteriores = str(len(o_fe.search(iri=f"*#{row['FE']}_o_*")))
            ind = o_fe.FE_Original(row["FE"] + '_o_' + anteriores)
            ind.probability = row['likelihood']
            threat.generates.append(ind)
            threat.type = row['type']
            
            # Look up feared event description and impact from fe.csv.
            fe_name = row['FE'].replace("_", " ")
            data_fe = fe[(fe["name"] == fe_name)]
            impact = data_fe['impact'].tolist()
            
            ind.description = fe_name
            ind.impact = impact[0]
            ind.is_a.append(o_fe.Feared_Event)
            ind.affects = [asset]

            # Mark asset as threatened for status tracking.
            asset.threatened = True
            
            # Create original risk for this feared event.
            create_risk(o_fe, ind, path)

            # == Threat Propagation Initiation ==
            create_risk_propagated(o_fe, ind)
            logger.debug("Starting propagation process")
            propagate(o_fe, row['FE'], asset_name, propagation_id, ind, path=path, propagation_paths=propagation_paths) 

def create_propagated_feared_event(o_fe, asset, threat, propagation_id, path="../data", propagation_paths=None):
    """Create propagated feared events triggered by a secondary threat on an asset.
    
    Similar to create_feared_event(), but creates FE_Propagated individuals
    representing feared events that result from threat propagation (secondary effects).
    
    This function is called during threat propagation to instantiate feared events
    on secondary assets that are affected by propagated threats.
    
    Args:
        o_fe: owlready2 ontology object.
        asset: Asset individual being affected by propagated threat.
        threat: Propagated Threat_Propagated individual.
        propagation_id: Identifier for this propagation chain (for loop prevention).
        path: Filesystem path to data directory. Defaults to "../data".
        propagation_paths: Dictionary of visited (threat, asset) pairs per chain.
    """
    with o_fe:
        scenarios, fe = _load_threat_catalogues(path)
        asset_name = str(asset).split(".")[1]
        threat_name = str(threat).split('.')[1]
        threat_name = threat_name.rsplit("_", 1)[0]
        
        # Filter scenarios that apply to this threat type and asset.
        data_ts = scenarios[(scenarios["type"] == threat_name.replace("_", " ")) & 
                           ((scenarios["asset"] == asset_name) | scenarios["asset"].str.contains("all", case=False))]
        
        if data_ts.empty:
            logger.debug(f"Propagation drop - No feared scenario for {threat_name} over {asset_name}")
            
        for index, row in data_ts.iterrows():
            # Create unique propagated feared event individual.
            anteriores = str(len(o_fe.search(iri=f"*#{row['FE']}_p_*")))
            ind = o_fe.FE_Propagated(row["FE"] + '_p_' + anteriores)
            ind.probability = row['likelihood']
            threat.generates.append(ind)
            
            # Look up feared event description and impact.
            fe_name = row['FE'].replace("_", " ")
            data_fe = fe[(fe["name"] == fe_name)]
            impact = data_fe['impact'].tolist()
            
            ind.description = fe_name
            ind.impact = impact[0]
            ind.is_a.append(o_fe.Feared_Event)
            ind.affects = [asset]

            # Create propagated risk for this feared event.
            create_risk_propagated(o_fe, ind)
            # Continue propagating through the asset relationship graph.
            propagate(o_fe, row['FE'], asset_name, propagation_id, ind, path=path, propagation_paths=propagation_paths)


def search_related_assets(o_fe, asset):
    """Find all assets directly connected to a given asset via relationships.
    
    Queries the ontology using SPARQL to find all target assets of relationships
    where the given asset is the source. Uses RDF/ontology semantics to return
    assets that are reachable in one hop.
    
    Args:
        o_fe: owlready2 ontology object.
        asset: String asset ID (e.g., "APP_001").
        
    Returns:
        List of strings: Asset IDs of all assets that this asset connects to.
                        Returns empty list if asset has no outbound relationships.
    """
    query = f"""
        PREFIX : <http://www.semanticweb.org/carmen.szas/ontologies/2024/10/dra#>

        SELECT DISTINCT ?targetAsset
        WHERE {{
        ?rel a :Relationship .
        :{asset} :source_of ?rel .
        ?targetAsset :target_of ?rel  .
        }}
    """

    results = list(o_fe.world.sparql(query))
    return [r[0].name for r in results]

def propagate(o_fe, fe, asset, propagation_id, fe_ind, path="../data", propagation_paths=None):
    """Propagate a feared event through the asset relationship graph (BFS).
    
    Implements the core threat propagation algorithm. Given a feared event and the
    asset it affects, discovers secondary threats by:
    1. Finding all related assets (via asset relationships)
    2. Looking up propagation rules that apply (feared event → threat mappings)
    3. Creating secondary threats on target assets if criticality threshold is met
    4. Recursively propagating further feared events from secondary threats
    
    Algorithm: Breadth-first search (BFS) traversal of the asset relationship graph,
    with pruning based on:
    - Relationship criticality (must exceed min_criticality from propagation rules)
    - Loop detection (already-visited (threat, asset) pairs stored in propagation_paths)
    
    Args:
        o_fe: owlready2 ontology object.
        fe: String feared event ID (e.g., "Data_Breach").
        asset: String source asset ID where feared event originated.
        propagation_id: Unique identifier for this propagation chain (prevents cross-chain loops).
        fe_ind: The feared event individual that triggered this propagation.
        path: Filesystem path to data directory. Defaults to "../data".
        propagation_paths: Dictionary {propagation_id → [(threat, asset), ...]}.
                          Tracks visited nodes; prevents infinite loops in cycles.
                          
    Performance:
        O(n * m * k) where:
        - n = number of related assets
        - m = number of threat scenarios per asset
        - k = depth of propagation chain
        
    Side Effects:
        - Creates Threat_Propagated individuals in the ontology
        - Updates propagation_paths dictionary with newly discovered paths
        - Recursively calls create_propagated_feared_event()
    """
    if propagation_paths is None:
        propagation_paths = defaultdict(list)

    # Load propagation rules (feared_event → threat mappings with criticality thresholds).
    propagation = pd.read_csv(f'{path}/propagation.csv')
    # Filter to rules that apply to this feared event.
    data_propagation = propagation[(propagation["fe"] == fe)]
    # Find all related assets (direct neighbors in relationship graph).
    target_assets = search_related_assets(o_fe, asset)
    
    for threat, min_criticality in zip(data_propagation["threat"], data_propagation["min_criticality"]):
        for target_asset in target_assets:
            logger.debug(f"Propagate threat {threat}: {asset} to {target_asset}")
            
            # Look up the criticality of the relationship between source and target.
            criticality_rel = o_fe.search_one(iri=f"*#rel_{asset}_{target_asset}").criticality
            
            # Prune if relationship criticality is below minimum threshold.
            if criticality_rel < min_criticality: 
                logger.debug("Propagation drop - Criticality of relationship too low")
                continue
            
            # Prevent loops by checking if this (threat, asset) pair already visited.
            connection = list((threat, target_asset))
            if not connection in propagation_paths[propagation_id]:
                # Look up target asset for threat creation.
                target_asset_obj = o_fe.search_one(iri=f"*#{str(target_asset)}")
                # Sanitize threat name for ontology IRI.
                threat_name = threat.replace(" ", "_")
                # Create unique threat individual.
                anteriores = str(len(o_fe.search(iri=f"*#{threat_name}*")))
                ind = o_fe.Threat_Propagated(threat_name + '_' + anteriores)
                ind.is_a.append(o_fe.Threat)
                ind.affects.append(target_asset_obj)
                ind.type = threat
                fe_ind.propagates_to.append(ind)
                # Mark this path as visited.
                propagation_paths[propagation_id].append(connection)
                logger.debug(f"Created threat {ind.name}")
                # Recursively create feared events from secondary threat (continues propagation).
                create_propagated_feared_event(o_fe, target_asset_obj, ind, propagation_id, path=path, propagation_paths=propagation_paths)
            else:
                logger.debug(f"Propagation drop - Duplicated entry {connection}")

def load_propagation_paths(path="../data"):
    """Load threat propagation chain metadata from disk.
    
    Reads the propagation_paths.json file which tracks which (threat, asset) pairs
    have already been discovered during propagation analysis. This prevents infinite
    loops if the asset relationship graph contains cycles.
    
    Args:
        path: Filesystem path to data directory. Defaults to "../data".
              Expected file: propagation_paths.json
        
    Returns:
        defaultdict(list): Maps propagation_id → [(threat, asset), ...]
                          Returns empty dict if file doesn't exist (fresh start).
    """
    file_path = Path(path) / "propagation_paths.json"
    if file_path.exists():
        with open(file_path, 'r') as f:
            return defaultdict(list, json.load(f))
    return defaultdict(list)


def save_propagation_paths(propagation_paths, path="../data"):
    """Persist threat propagation chain metadata to disk.
    
    Saves the propagation paths dictionary as JSON for reproducibility and debugging.
    Can be examined to understand how threats propagated through the system.
    
    Args:
        propagation_paths: defaultdict(list) mapping propagation_id → [(threat, asset), ...]
        path: Filesystem path to data directory. Defaults to "../data".
              Output file: propagation_paths.json
    """
    file_path = Path(path) / "propagation_paths.json"
    with open(file_path, 'w') as f:
        json.dump(dict(propagation_paths), f) 

# Secondary function to create risk for each feared event
def create_risk(o_r, fe, path="../data"):    
    # Probability and impact values are mapped to numbers to calculate risk level according to risk matrix
    risk_matrix = pd.read_csv(path+'/matrix.csv', header=None) # Risk matrix CSV file.

    risk = o_r.PR_Original('Potential_Risk_'+str(fe).split('.')[1])
    risk.is_a.append(o_r.Risk)
    risk.is_a.append(o_r.Potential_Risk) # Risk is a Potential Risk
    probability = fe.probability
    risk.probability = probability
    impact = fe.impact
    risk.impact = impact
    risk_level = risk_matrix.iloc[10-impact, probability-1] # According to the risk matrix, risk level is calculated
    risk.risk_level = int(risk_level)
    asset = fe.affects[0]
    importance = asset.importance
    risk.relative_risk_level = math.ceil(risk.risk_level * importance)
    fe.generates.append(risk) # Feared event is related to risk individual
    logger.debug(f"Risk {str(risk).split('.')[1]} created -- Probability: {probability} | Impact: {impact} | Risk level: {risk_level}")

# Secondary function to create propagated risk for each feared event
def create_risk_propagated(o_r, fe, path="../data"):    
    # Probability and impact values are mapped to numbers to calculate risk level according to risk matrix
    risk_matrix = pd.read_csv(path+'/matrix.csv', header=None) # Risk matrix CSV file. 

    risk = o_r.PR_Propagated('Potential_Propagated_Risk_'+str(fe).split('.')[1])
    risk.is_a.append(o_r.Risk)
    risk.is_a.append(o_r.Potential_Risk) # Risk is a Potential Risk
    probability = fe.probability
    risk.probability = probability
    impact = fe.impact
    risk.impact = impact
    risk_level = risk_matrix.iloc[10-impact, probability-1] # According to the risk matrix, risk level is calculated
    risk.risk_level = int(risk_level)
    asset = fe.affects[0]
    importance = asset.importance
    risk.relative_risk_level = math.ceil(risk.risk_level * importance)
    fe.generates.append(risk) # Feared event is related to risk individual
    logger.debug(f"Risk {str(risk).split('.')[1]} created -- Probability: {probability} | Impact: {impact} | Risk level: {risk_level}")

def calculate_risk_asset(o_r_a, path="../data"):
    """Calculate risk level for each asset based on original feared events.
    
    Aggregates risk scores from all original (non-propagated) feared events that
    affect each asset. For each asset, determines the maximum risk level across
    all threats targeting it. This represents the worst-case risk scenario without
    considering threat propagation.
    
    Algorithm:
    1. Iterate through all FE_Original instances in the ontology
    2. For each feared event, collect associated risks (PR_Original individuals)
    3. Extract risk_level from each risk and store by affected asset
    4. Per asset: assign max(risk_levels) as the asset's risk_level property
    
    Args:
        o_r_a: owlready2 ontology object containing FE_Original and PR_Original
               individuals along with asset information.
        path: Filesystem path to directory containing ontology and data files.
              Defaults to "../data". The dra_full.owl file is updated with
              calculated risk_level properties.
              
    Returns:
        None. Updates are persisted to dra_full.owl on disk as a side effect.
        
    Side Effects:
        - Modifies asset.risk_level property in the ontology
        - Saves dra_full.owl with updated asset risk levels
        
    Performance:
        O(n * m) where n = number of FE_Original instances,
        m = average number of risks per feared event
    """
    with o_r_a:
        # Dictionary to collect all risk levels per asset.
        asset_risk = defaultdict(list)
        # Retrieve all original feared events from the ontology.
        feared_events = o_r_a.FE_Original.instances()
        for f in feared_events: # For each feared event, the risk is calculated and associated to the asset in a dictionary
            if o_r_a.FE_Original in f.is_a:
                asset = f.affects[0]
                risks = f.generates
                for r in risks:
                    if o_r_a.PR_Original in r.is_a:
                        risk_level = r.risk_level
                        asset_risk[asset].append(risk_level)
        for a in asset_risk.keys(): # For each asset in dictionary, the max value of the risks is calculated and associated to the asset in ontology
            a.risk_level = max(asset_risk[a])

    # Persist updated risk levels to ontology file.
    o_r_a.save(f"{path}/dra_full.owl") # Save updates in assets into potential risks ontology

def propagated_risk_asset(o_r_a):
    """Calculate propagated risk level and relative risk for each asset.
    
    Computes risk scores for each asset considering both original and propagated
    feared events (from threat propagation analysis). For each asset, calculates:
    1. propagated_risk_level: Maximum risk from all feared events (original + propagated)
    2. relative_risk_level: Risk normalized by asset importance (risk × importance)
    
    The relative_risk_level provides a weighted risk metric accounting for how
    critical each asset is to the system (asset.importance).
    
    Algorithm:
    1. Iterate through all Feared_Event instances (original AND propagated)
    2. For each feared event, extract its associated risk's risk_level
    3. Per asset: assign max(risk_levels) as propagated_risk_level
    4. Calculate relative_risk_level = ceil(propagated_risk_level × asset.importance)
    
    Args:
        o_r_a: owlready2 ontology object containing Feared_Event and Risk individuals
               with asset and importance information.
               
    Returns:
        None. Updates asset properties in the ontology as a side effect.
        
    Side Effects:
        - Modifies asset.propagated_risk_level property
        - Modifies asset.relative_risk_level property
        - Updates are NOT persisted; caller must save the ontology
        
    Note:
        Unlike calculate_risk_asset(), this function does not save the ontology.
        Caller is responsible for saving dra_full.owl when propagated risks are final.
    """
    with o_r_a:
        # Dictionary to collect all risk levels per asset from feared events.
        asset_risk = defaultdict(list)
        # Retrieve all feared events (both original and propagated).
        feared_events = o_r_a.Feared_Event.instances()
        for f in feared_events: # For each feared event, the risk is calculated and associated to the asset in a dictionary
            asset = f.affects[0]
            risk = f.generates[0]
            risk_level = risk.risk_level
            asset_risk[asset].append(risk_level)
        for a in asset_risk.keys(): # For each asset in dictionary, the max value of the risks is calculated and associated to the asset in ontology
            # Set propagated risk to maximum from all feared events (empty list → 0).
            a.propagated_risk_level = max(asset_risk[a]) if asset_risk[a] else 0
            # Calculate relative risk by multiplying propagated risk by asset importance.
            a.relative_risk_level = math.ceil(a.importance * a.propagated_risk_level)

def calculate_total_risk(o_t_r, path="../data"):
    """Calculate the total system-level risk from all original threats.
    
    Aggregates risk across all assets to produce a single system-level risk metric.
    Uses the ITSRM (IT Security Risk Management) methodology: system risk equals
    the maximum risk_level across all assets/risks in the system (worst-case scenario).
    
    This represents the system's risk exposure without considering threat propagation.
    For system risk including propagated threats, see calculate_total_propagated_risk().
    
    Args:
        o_t_r: owlready2 ontology object containing System individual and
               PR_Original risk instances.
        path: Filesystem path to data directory. Defaults to "../data".
              The dra_full.owl file is updated with system.risk_level.
              
    Returns:
        None. Updates system.risk_level property and persists to disk.
        
    Side Effects:
        - Modifies System.risk_level with maximum of all PR_Original.relative_risk_level
        - Saves dra_full.owl with updated system risk
        - Logs the computed total risk level at INFO level
        
    Logging:
        Outputs dashed separator lines and total risk level to application logger.
        Useful for risk assessment reports and audit trails.
    """
    with o_t_r:
        # Load the system individual (should be unique in ontology).
        system = o_t_r.System.instances()[0]
        # Retrieve all original (non-propagated) risk instances.
        risks = o_t_r.PR_Original.instances()
        # Extract relative risk levels from all risks for aggregation.
        levels = [r.relative_risk_level for r in risks] # Get risk levels for each risk in the ontology
        # Compute system risk as worst-case (maximum) of all assets (empty list → 0).
        system.risk_level = max(levels) if levels else 0 # Calculate max value of risk levels
        
        # Persist system risk calculation to ontology.
        o_t_r.save(f"{path}/dra_full.owl") # save updates in potential risks ontology (system potential risk level)
        logger.info("-" * 100)
        logger.info(f"Total potential risk level for the system: {system.risk_level}")
        logger.info("-" * 100)

def calculate_total_propagated_risk(o_t_r, path="../data"):
    """Calculate the total system-level risk including threat propagation effects.
    
    Aggregates propagated risk across all assets to produce the total system risk
    considering secondary threats from propagation. Uses the ITSRM methodology:
    system.propagated_risk_level = max(all PR_Propagated.relative_risk_level).
    
    This differs from calculate_total_risk() by including risks from propagated
    threats (i.e., secondary threats triggered by cascading failures). Typically
    results in higher risk scores than original risk calculation.
    
    Args:
        o_t_r: owlready2 ontology object containing System individual and
               PR_Propagated risk instances.
        path: Filesystem path to data directory. Defaults to "../data".
              
    Returns:
        None. Updates system.propagated_risk_level property and logs result.
        
    Side Effects:
        - Modifies System.propagated_risk_level with max of all PR_Propagated
          relative_risk_level values
        - Logs the computed total propagated risk level at INFO level
        - Does NOT persist to disk (dra_full.owl); caller must save if needed
        
    Logging:
        Outputs formatted dashed separator lines and propagated risk level.
    """
    # Numeric mapping of risk levels to calculate max
    with o_t_r:
        # Load the system individual from ontology.
        system = o_t_r.System.instances()[0]
        # Retrieve all propagated (secondary threat) risk instances.
        risks = o_t_r.PR_Propagated.instances()
        # Extract relative risk levels from all propagated risks.
        levels = [r.relative_risk_level for r in risks] # Get risk levels for each risk in the ontology
        # Compute system propagated risk as worst-case of all propagated risks.
        system.propagated_risk_level = max(levels) if levels else 0 # Calculate max value of risk levelsk
                
        logger.info("-" * 100)
        logger.info(f"Total potential propagated risk level for the system: {system.propagated_risk_level}")
        logger.info("-" * 100)

def reload_ontology(path="../data"):
    """Reload and reinitialize the base OWL ontology from disk.
    
    Loads the base OWL ontology schema (dra.owl) without any pre-existing instances,
    then populates it with system metadata and asset definitions from CSV files.
    This is typically used when starting a fresh risk assessment session or when
    the full ontology needs to be reset.
    
    The function performs a three-step initialization:
    1. Create a new ontology World and load the base schema from dra.owl
    2. Load system metadata (from system.csv)
    3. Load assets and their relationships (from assets.csv and assets_relationships.csv)
    
    Args:
        path: Filesystem path to data directory. Defaults to "../data".
              Expected files: dra.owl, system.csv, assets.csv, assets_relationships.csv
              
    Returns:
        owlready2 Ontology: The loaded and initialized ontology object, ready for
                          further threat modeling and risk assessment operations.
                          
    Performance:
        O(n + m) where n = number of assets, m = number of relationships.
        Typically completes in <1 second for typical system sizes.
        
    Note:
        This function loads ONLY the base ontology without threats or risks.
        Use risk_assessment() for full dynamic risk analysis with propagation.
    """
    # Create a fresh ontology world context.
    w = World()
    # Load base ontology schema (classes, properties, but no instances).
    onto_original = w.get_ontology(f"{path}/dra.owl").load() 
    # Populate system-level metadata from CSV.
    load_system(onto_original, path=path)
    # Populate assets and their relationships from CSV files.
    load_assets(onto_original, path=path)
    # Return initialized ontology ready for threat/risk modeling.
    return onto_original

def main():
    """Main entry point for command-line risk assessment execution.
    
    Orchestrates the complete threat modeling and risk assessment workflow.
    Parses command-line arguments, initializes the ontology, and executes the
    dynamic risk assessment pipeline. Results are logged with execution time
    metrics for performance monitoring.
    
    Command-Line Arguments:
        -a, --asset       Load assets into the ontology before risk assessment.
                         By default, only system metadata is loaded.
        -p, --path PATH   Filesystem path to data directory containing CSVs and OWL files.
                         Defaults to "../data". Should contain: dra.owl, system.csv,
                         assets.csv, assets_relationships.csv, and threat catalogs.
                        
    Workflow:
        1. Parse command-line arguments (asset flag, data path)
        2. Configure logging if running standalone (INFO level)
        3. Load base ontology schema from dra.owl
        4. Load system metadata from system.csv
        5. Optionally load asset catalog (if -a flag provided)
        6. Execute dynamic risk assessment with threat propagation
        7. Report execution timings for each phase
        
    Performance:
        Total execution time typically 15-90 seconds depending on system complexity.
        Breakdown:
        - System loading: <1 second
        - Asset loading: <5 seconds (if -a flag used)
        - Risk assessment + propagation: 10-60+ seconds
        
    Logging:
        Configured for standalone execution with INFO level logging to console.
        When imported as library, uses parent module's logging configuration.
        Logs include phase-by-phase execution times for optimization analysis.
        
    Exit Behavior:
        Returns after risk_assessment() completes; results persisted to dra_full.owl.
        Can be called from Flask app or executed as command-line utility.
        
    Usage Examples:
        # Standard risk assessment (system only)
        python manager.py
        
        # Reload assets and perform assessment
        python manager.py -a
        
        # Use custom data directory
        python manager.py -p /path/to/data
        
        # Reload assets with custom path
        python manager.py -a -p /path/to/data
    """
    # Track total and phase-by-phase execution time.
    start_time = time.time()
    last_time = start_time
    
    # == Argument Parsing ==
    parser = argparse.ArgumentParser()

    # Flag to control optional asset reloading.
    parser.add_argument(
        '-a',
        action='store_true',
        help='Load/reload assets from CSV before risk assessment',
    )

    # Path to data directory (ontology files, CSVs, matrix).
    parser.add_argument(
        '-p',
        type=str,
        default="../data",
        help='Path to data directory containing OWL files and CSV catalogs.'
    )

    # == Logging Configuration ==
    # Only configure logging if this is the main entry point (not imported as library).
    # CHANGE THIS TO logging.DEBUG if you want verbose output for troubleshooting.
    if not logging.getLogger().handlers:   
        logging.basicConfig(
             level=logging.INFO,
             format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        )

    # Parse arguments and extract configuration.
    args = parser.parse_args()
    bool_assets = args.a
    path = args.p

    # == Phase 1: Ontology & System Loading ==
    # Load base ontology with class structure (no instances yet).
    onto_original = get_ontology(f"{path}/dra.owl").load() 
    
    # Load system-level metadata from CSV (creates System individual).
    load_system(onto_original, path=path) # Load system information from CSV file
    partial_time = time.time()
    logger.info(f"Loading System time: {partial_time - last_time} seconds")
    logger.info("-" * 100)
    last_time = partial_time

    # == Phase 2: Optional Asset Loading ==
    if bool_assets: # if -a is passed, asset catalogue is loaded
        load_assets(onto_original, path=path)
        partial_time = time.time()
        logger.info(f"Loading Assets time: {partial_time - last_time} seconds")
        logger.info("-" * 100)
        last_time = partial_time

    # == Phase 3: Dynamic Risk Assessment ==
    # Execute full risk assessment pipeline with threat propagation (always runs).
    risk_assessment(path=path) # Dynamic risk assessment is always executed
    partial_time = time.time()
    logger.info(f"Risk Assessment Execution time: {partial_time - last_time} seconds")
    logger.info("-" * 100)
    last_time = partial_time

    end_time = time.time()
    logger.info("-" * 100)
    logger.info(f"Total Execution time: {end_time - start_time} seconds")
    logger.info("-" * 100)


if __name__ == "__main__":
    main()
