"""Elasticsearch indexing utilities for OWL ontology data.

This module provides functions to extract risk assessment data from an OWL ontology
and index it into Elasticsearch for efficient querying and visualization. It serves
as the bridge between the ontology layer (owlready2) and the search/analytics layer
(Elasticsearch).

The module handles:
  - Ontology loading and entity extraction (assets, threats, feared events, risks, etc.)
  - Elasticsearch index creation and management (with optional reset/reindexing)
  - Bulk document indexing for performance
  - Relationship mapping (e.g., threat → feared_event → asset chains)

Data Model:
The OWL ontology is organized into original and propagated entity hierarchies:
  - Original (suffix _o): User-defined base entities
  - Propagated (suffix _p): Derived entities resulting from threat propagation calculations

All entities are indexed as separate Elasticsearch indices for independent querying.

Usage:
    # Programmatic usage:
    from elasticsearch import Elasticsearch
    import import_onto_es
    es = Elasticsearch("http://localhost:9200")
    onto = import_onto_es.onto_to_ES(es, reset=True)
    
    # Command-line usage:
    python import_onto_es.py -r -p ../data
    
Command-line Options:
    -r              Reset/clear existing Elasticsearch indices before reindexing.
    -p PATH         Path to data directory containing OWL ontology file. 
                    Defaults to "../data".
"""
from elasticsearch import Elasticsearch
import owlready2
import argparse
from elasticsearch.helpers import bulk
import logging

logger = logging.getLogger(__name__)


def _ensure_index(es, index_name, reset=False) -> None:
    """Create or reset an Elasticsearch index.
    
    Either creates a new index if it doesn't exist, or optionally deletes and
    recreates an existing index. This function is idempotent; multiple calls
    with the same parameters will result in the same final state.
    
    Args:
        es: Elasticsearch client instance connected to the cluster.
        index_name: Name of the Elasticsearch index to ensure/create.
        reset: If True, deletes the index if it exists before creating a new one.
               If False (default), skips creation if the index already exists.
               
    Returns:
        None. The function modifies cluster state via side effects.
        
    Raises:
        elasticsearch.exceptions.ConnectionError: If unable to connect to Elasticsearch.
        elasticsearch.exceptions.AuthorizationException: If lacking permissions for
            index creation/deletion.
    """
    # Check if the index currently exists.
    exists = es.indices.exists(index=index_name)
    if exists and reset:
        # Delete existing index to start fresh (useful for reprocessing/updates).
        es.indices.delete(index=index_name)
        exists = False
    if not exists:
        # Create the index with default settings.
        # TODO: Consider adding custom analyzers and mappings for better search behavior.
        es.indices.create(index=index_name)


def _bulk_index(es, index_name, docs, id_field) -> None:
    """Index a batch of documents into Elasticsearch using bulk API.
    
    Efficiently indexes multiple documents at once using the Elasticsearch bulk
    API, which reduces network round-trips and improves indexing performance
    compared to individual index operations.
    
    Args:
        es: Elasticsearch client instance.
        index_name: Name of the target Elasticsearch index.
        docs: List of document dictionaries to index. Each document should contain
              all fields to be indexed, including the ID field.
        id_field: Name of the field within each document to use as the Elasticsearch
                 _id. This field should be unique across documents to avoid accidental
                 overwrites. Common examples: "asset_id", "threat_id", "risk_id".
                 
    Returns:
        None. Documents are indexed as a side effect.
        
    Raises:
        elasticsearch.exceptions.BulkIndexError: If one or more documents fail to index.
            Note: The bulk API continues processing even if some documents fail.
        KeyError: If the id_field does not exist in one of the documents.
    """
    # Early return if no documents to index (avoid unnecessary API calls).
    if not docs:
        return

    # Build bulk action list from documents. Each action specifies the target
    # index and the document ID to use.
    actions = [
        {
            "_index": index_name,
            "_id": doc[id_field],
            "_source": doc,  # The actual document data.
        }
        for doc in docs
    ]
    # Execute bulk indexing operation via Elasticsearch client.
    bulk(es, actions)

# == Main Ontology Export Function ==

def onto_to_ES(es, onto=None, path="../data/", reset=False):
    """Extract ontology entities and index them into Elasticsearch.
    
    This is the primary function for syncing ontology data with Elasticsearch.
    It loads the OWL ontology, extracts all entity types (assets, threats, feared
    events, risks, etc.), ensures target indices exist, and bulk-indexes all data.
    
    The function creates/resets the following Elasticsearch indices:
        - assets: System assets and their risk metrics
        - threats_o, threats_p: Original and propagated threat scenarios
        - feared_events_o, feared_events_p: Original and propagated feared events
        - potential_risks_o, potential_risks_p: Original and propagated risk scenarios
        - relationships: Asset-to-asset relationships
        - system: System-wide aggregate risk metrics
    
    Args:
        es: Elasticsearch client instance. Should be connected to the target
            Elasticsearch cluster (e.g., http://localhost:9200).
        onto: Pre-loaded owlready2 ontology object. If None (default), the ontology
              is loaded from disk at path/dra_full.owl.
        path: Filesystem path to the directory containing the OWL ontology files.
              Expects to find "dra_full.owl" in this directory. Defaults to "../data/".
        reset: If True, deletes and recreates all Elasticsearch indices. Use this when
               reprocessing the entire ontology or to clear stale data. If False (default),
               preserves existing indices and overwrites only the indexed documents.
               
    Returns:
        The loaded owlready2 ontology object (whether passed in or loaded from disk).
        Useful for chaining operations or further programmatic access.
        
    Raises:
        FileNotFoundError: If the OWL ontology file (dra_full.owl) cannot be found
            at the specified path.
        elasticsearch.exceptions.ConnectionError: If unable to connect to Elasticsearch.
        owlready2.OwlReadyError: If the OWL file is malformed or fails to load.
    """
    logger.info("/// Starting import of ontology data to Elastic Search")

    # == Ontology Loading ==
    # Load the ontology from disk if not already provided. owlready2 uses a lazy-loading
    # approach, so entities are loaded into memory on-demand.
    if not onto:
        w = owlready2.World()
        onto = w.get_ontology(f"{path}/dra_full.owl").load() 

    # == Entity Extraction ==
    # Extract all instances of each entity class from the ontology. The ontology uses
    # inheritance hierarchies (e.g., Threat_Original, Threat_Propagated) to distinguish
    # between original user-defined threats and threats derived from propagation.
    # 
    # Note: Direct class instantiation checks (is_a) are used here rather than simple
    # instance() calls to ensure we get only direct instances of each class (not subclasses).
    assets = onto.Assets.instances()
    threats_o = [t for t in onto.Threat_Original.instances() if onto.Threat_Original in t.is_a]
    threats_p = [t for t in onto.Threat_Propagated.instances() if onto.Threat_Propagated in t.is_a]
    feared_events_o = [fe for fe in onto.FE_Original.instances() if onto.FE_Original in fe.is_a] 
    feared_events_p = [fe for fe in onto.FE_Propagated.instances() if onto.FE_Propagated in fe.is_a] 
    potential_risks_o = [pr for pr in onto.PR_Original.instances() if onto.PR_Original in pr.is_a]
    potential_risks_p = [pr for pr in onto.PR_Propagated.instances() if onto.PR_Propagated in pr.is_a]
    relationships = onto.Relationship.instances()
    systems = onto.System.instances()

    # == Index Preparation ==
    # List of all Elasticsearch indices that will be created/reset. Ensures all target
    # indices are ready before bulk indexing operations begin.
    indexes = [
        "assets",
        "threats_o",
        "threats_p",
        "feared_events_o",
        "feared_events_p",
        "potential_risks_o",
        "potential_risks_p",
        "relationships",
        "system",
    ]
    for index_name in indexes:
        _ensure_index(es, index_name, reset=reset)

    # == Asset Document Building ==
    # Constructs Elasticsearch documents from asset entities. Each asset represents
    # a system component with associated risk metrics and relationships.
    assets_docs = []
    for asset in assets:
        assets_docs.append(
            {
                "asset_id": asset.name,
                "type": asset.type,
                "description": asset.description,
                "importance": asset.importance,  # User-defined criticality of this asset
                "risk_level": asset.risk_level,  # Inherent risk (threat-based)
                "propagated_risk_level": asset.propagated_risk_level,  # Risk including propagation
                "relative_risk_level": asset.relative_risk_level,  # Normalized relative to system max
                "threatened": asset.threatened,  # Boolean: is this asset targeted by threats?
                "source_of": [rel.name for rel in asset.source_of],  # Outbound relationships
                "target_of": [rel.name for rel in asset.target_of],  # Inbound relationships
            }
        )

    # == Original Threat Document Building ==
    # Creates documents for user-defined (original) threats.
    threats_o_docs = []
    for threat in threats_o:
        threats_o_docs.append(
            {
                "threat_id": threat.name,
                "type": threat.type,
                "affects": [asset.name for asset in threat.affects] if threat.affects else None,
                "generates": [fe.name for fe in threat.generates] if threat.generates else None,
            }
        )

    # == Propagated Threat Document Building ==
    # Creates documents for derived threats resulting from threat propagation analysis.
    threats_p_docs = []
    for threat in threats_p:
        threats_p_docs.append(
            {
                "threat_id": threat.name,
                "type": threat.type,
                "affects": [asset.name for asset in threat.affects] if threat.affects else None,
                "generates": [fe.name for fe in threat.generates] if threat.generates else None,
            }
        )

    # == Index Assets and Threats ==
    # Bulk index all asset and threat documents.
    _bulk_index(
        es,
        "assets",
        assets_docs,
        "asset_id",
    )
    logger.debug("Assets uploaded to ES in bulk")

    _bulk_index(
        es,
        "threats_o",
        threats_o_docs,
        "threat_id",
    )
    _bulk_index(
        es,
        "threats_p",
        threats_p_docs,
        "threat_id",
    )
    logger.debug("Threats uploaded to ES in bulk")

    # == Original Feared Event Document Building ==
    # Creates documents for user-defined feared events. These represent undesired
    # outcomes that threats can trigger, and which can propagate to other threats.
    feared_events_o_docs = []
    for fe in feared_events_o:
        feared_events_o_docs.append(
            {
                "feared_event_id": fe.name,
                "description": fe.description,
                "impact": fe.impact,  # Quantitative impact value
                "probability": fe.probability,  # Probability of occurrence
                "affects": [asset.name for asset in fe.affects] if fe.affects else None,
                "generates": [risk.name for risk in fe.generates],  # Risks caused by this FE
                "propagates_to": [
                    threat.name for threat in fe.propagates_to
                ],  # Threats triggered by this FE
            }
        )

    # == Propagated Feared Event Document Building ==
    # Creates documents for derived feared events from the propagation analysis.
    feared_events_p_docs = []
    for fe in feared_events_p:
        feared_events_p_docs.append(
            {
                "feared_event_id": fe.name,
                "description": fe.description,
                "impact": fe.impact,
                "probability": fe.probability,
                "affects": [asset.name for asset in fe.affects] if fe.affects else None,
                "generates": [risk.name for risk in fe.generates],
                "propagates_to": [
                    threat.name for threat in fe.propagates_to
                ],
            }
        )

    # == Index Feared Events ==
    _bulk_index(
        es,
        "feared_events_o",
        feared_events_o_docs,
        "feared_event_id",
    )
    _bulk_index(
        es,
        "feared_events_p",
        feared_events_p_docs,
        "feared_event_id",
    )
    logger.debug("Feared events uploaded to ES in bulk")

    # == Original Potential Risk Document Building ==
    # Creates documents for user-defined potential risks. Risks are the actual outcomes
    # of feared events affecting assets. This section uses reverse ontology searching
    # to find the feared event that generates each risk, then extracts the assets it affects.
    potential_risks_o_docs = []
    for risk in potential_risks_o:
        # Find which feared event (if any) generates this risk via ontology search.
        generated_by = onto.search_one(generates=risk)
        generated_by_affects = []
        if generated_by:
            # Extract the assets affected by the generating feared event.
            generated_by_affects = [asset.name for asset in generated_by.affects]

        potential_risks_o_docs.append(
            {
                "risk_id": risk.name,
                "potential_risk_id": risk.name,
                "impact": risk.impact,  # Quantitative impact metric
                "probability": risk.probability,  # Probability of occurrence
                "risk_level": risk.risk_level,  # Overall risk score (impact × probability)
                "relative_risk_level": risk.relative_risk_level,  # Normalized to system maximum
                "generated_by": generated_by.name if generated_by else None,  # Feared event source
                "affects": generated_by_affects[0] if generated_by_affects else None,  # Primary asset affected
            }
        )

    # == Propagated Potential Risk Document Building ==
    # Creates documents for risks derived from the threat propagation analysis.
    potential_risks_p_docs = []
    for risk in potential_risks_p:
        # Find the feared event that generates this propagated risk.
        generated_by = onto.search_one(generates=risk)
        generated_by_affects = []
        if generated_by:
            generated_by_affects = [asset.name for asset in generated_by.affects]

        potential_risks_p_docs.append(
            {
                "risk_id": risk.name,
                "potential_risk_id": risk.name,
                "impact": risk.impact,
                "probability": risk.probability,
                "risk_level": risk.risk_level,
                "relative_risk_level": risk.relative_risk_level,
                "generated_by": generated_by.name if generated_by else None,
                "affects": generated_by_affects[0] if generated_by_affects else None,
            }
        )

    # == Index Potential Risks ==
    _bulk_index(
        es,
        "potential_risks_o",
        potential_risks_o_docs,
        "risk_id",
    )
    _bulk_index(
        es,
        "potential_risks_p",
        potential_risks_p_docs,
        "risk_id",
    )
    logger.debug("Potential risks uploaded to ES in bulk")

    # == Relationship Document Building ==
    # Creates documents representing connections between assets. Each relationship
    # has directional attributes (source → target) and associated criticality ratings.
    # This section uses reverse ontology searching to find which assets are connected
    # by each relationship instance.
    relationships_docs = []
    for rel in relationships:
        # Find the source asset (the asset that "sources" this relationship).
        source_asset = onto.search_one(source_of=rel)
        # Find the target asset (the asset that is "targeted" by this relationship).
        target_asset = onto.search_one(target_of=rel)
        source_id = source_asset.name if source_asset else None
        target_id = target_asset.name if target_asset else None

        relationships_docs.append(
            {
                "relationship_id": rel.name,
                "source": source_id,
                "target": target_id,
                "from": source_id,  # Duplicate fields for query flexibility
                "to": target_id,
                "criticality": rel.criticality,  # Importance of this relationship for propagation
            }
        )

    _bulk_index(
        es,
        "relationships",
        relationships_docs,
        "relationship_id",
    )
    logger.debug("Relationships uploaded to ES in bulk")

    # == System Aggregate Document Building ==
    # Creates documents representing system-wide aggregate metrics. Typically there is
    # only one system entity in the ontology, containing overall risk scores for the
    # entire system and its propagated state.
    systems_docs = []
    for system in systems:
        systems_docs.append(
            {
                "system_id": system.name,
                "risk_level": system.risk_level,  # Overall system risk (original model)
                "propagated_risk_level": system.propagated_risk_level,  # Including propagation effects
            }
        )

    _bulk_index(
        es,
        "system",
        systems_docs,
        "system_id",
    )
    logger.debug("System uploaded to ES in bulk")

    logger.info("/// Ontology import to Elastic Search completed")
    return onto



# == CLI Entry Point ==

def main():
    """Command-line interface for ontology export to Elasticsearch.
    
    Parses command-line arguments, initializes the Elasticsearch connection,
    and invokes the main onto_to_ES function with the specified parameters.
    
    This allows for easy manual ontology updates outside of the Flask application
    context. Supports both initial indexing and reprocessing (with -r flag).
    
    Command-line Arguments:
        -r: Reset flag. If present, deletes and recreates all Elasticsearch indices.
            Use when reprocessing the entire ontology or clearing stale cached data.
        -p PATH: Path to the data directory containing ontology files (e.g., dra_full.owl).
                Defaults to "../data" (relative to the script directory).
                
    Example Usage:
        python import_onto_es.py              # Index ontology with defaults
        python import_onto_es.py -r           # Reset indices and re-index
        python import_onto_es.py -r -p /path/to/data   # Reset and use custom data path
    """
    parser = argparse.ArgumentParser(
        description="Index OWL ontology entities into Elasticsearch for query and visualization."
    )

    # Configure logging if not already set up by Flask or other modules.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        )

    # Initialize Elasticsearch client connection.
    # The id_field_data setting enables efficient sorting and filtering on the _id field.
    es = Elasticsearch("http://localhost:9200")
    es.cluster.put_settings(body={"persistent": {"indices.id_field_data.enabled": "true"}})

    # Define command-line options.
    parser.add_argument(
        '-r',
        action='store_true',
        help='Reset Elasticsearch indices (deletes and recreates all indices).',
    )

    parser.add_argument(
        '-p',
        type=str,
        default="../data",
        help='Path to the data directory containing OWL ontology files. Defaults to ../data.',
    )

    # Parse provided command-line arguments.
    args = parser.parse_args()
    reset = args.r
    path = args.p
    
    # Invoke the main ontology export function with parsed arguments.
    onto_to_ES(es, reset=reset, path=path)

if __name__ == "__main__":
    """Script entry point. Runs when invoked directly from command line."""
    main()
