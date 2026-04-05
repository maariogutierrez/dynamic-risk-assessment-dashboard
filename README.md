# Dynamic Risk Assessment Dashboard

A Flask-based web application for **dynamic cybersecurity risk assessment**, combining OWL ontology modeling with Elasticsearch-backed storage to visualize, compute, and propagate risk scores across system architectures.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Data Model](#data-model)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Docker (recommended)](#docker-recommended)
  - [Local Development](#local-development)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Risk Assessment Methodology](#risk-assessment-methodology)
- [Contributing](#contributing)

---

## Overview

The Dynamic Risk Assessment Dashboard (DRA Dashboard) enables security teams to model a system's asset landscape, define threat scenarios and feared events, and automatically propagate risk scores through inter-asset relationships. It implements an **ITSRM-based (IT Security Risk Management)** quantitative methodology and surfaces results through an interactive web dashboard.

Key characteristics:

- **Ontology-driven**: The full system model is encoded in an OWL ontology (`dra.owl` / `dra_full.owl`) and managed with [owlready2](https://owlready2.readthedocs.io/).
- **Elasticsearch-backed**: All ontology entities are indexed for fast querying, filtering, and sorting.
- **Dynamic propagation**: A BFS traversal of the asset relationship graph discovers secondary risks triggered by cascading failures.
- **Live editing**: Propagation relationships between feared events and threats can be modified through the UI and immediately re-assessed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Browser                          │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP
┌────────────────────────▼────────────────────────────────┐
│               Flask Application (port 5002)             │
│                                                         │
│  ┌──────────────┐  ┌────────────────┐  ┌────────────┐   │
│  │  app.py      │  │  manager.py    │  │ import_    │   │
│  │  (routes +   │->│  (ontology +   │  │ onto_es.py │   │
│  │   views)     │  │   risk engine) │  │ (indexing) │   │
│  └──────────────┘  └────────────────┘  └──────┬─────┘   │
└───────────────────────────────────────────────┼─────────┘
                                                │
┌───────────────────────────────────────────────▼──────────┐
│                  Elasticsearch (port 9200)               │
│  Indices: assets │ threats_o/p │ feared_events_o/p │ …   │
└──────────────────────────────────────────────────────────┘
```

**Component responsibilities:**

| Component | Responsibility |
|---|---|
| `flaskProject/app.py` | HTTP routing, template rendering, Elasticsearch queries |
| `scripts/manager.py` | OWL ontology load/save, risk propagation BFS, risk score calculation |
| `scripts/import_onto_es.py` | Extract ontology entities and bulk-index them into Elasticsearch |
| `data/` | Source-of-truth CSV files and OWL ontology files |

---

## Features

| Feature | Description |
|---|---|
| **Propagation** | Interactive graph showing how risk propagates across the asset relationship network |
| **Assets** | View all system assets with their type, description, importance rating, and computed risk levels |
| **Threats** | Browse original and propagated threats |
| **Feared Events** | Inspect feared events with impact and likelihood scores |
| **Risks** | Browse original and propagated risks and inspect system risk indicators |
| **Risk Matrix** | Quantitative probability × impact scoring based on a configurable risk matrix |
| **Sortable Tables** | All views support multi-field ascending/descending sorting |
| **Propagation Editor** | Edit the propagation matrix (feared event → threat connections with criticality thresholds) and trigger live re-assessment |

---

## Data Model

The application reads from CSV files in `data/` and persists a computed OWL ontology:

| File | Contents |
|---|---|
| `assets.csv` | System assets with `id`, `class`, `name`, `importance` |
| `assets_relationships.csv` | Asset-to-asset edges with criticality ratings |
| `threat_scenarios.csv` | Threat → feared event → asset mappings with likelihood and CIA dimensions |
| `threat_assets.csv` | Direct threat-to-asset associations |
| `fe.csv` | Feared event descriptions and impact metadata |
| `incidents.csv` | Historical security incident records |
| `matrix.csv` | Risk matrix (rows = likelihood, columns = impact) |
| `propagation.csv` | Propagation rules: feared event → threat with minimum criticality threshold |
| `vulnerabilities.csv` | CVE records with severity, score, and affected asset |
| `system.csv` | System-level metadata |
| `dra.owl` | Base OWL ontology schema (classes, properties) |
| `dra_full.owl` | Full ontology with instances (generated and updated at runtime) |

Elasticsearch indices mirror these entities with two suffixes:
- `_o` — **original** (user-defined base entities)
- `_p` — **propagated** (derived entities from cascading risk analysis)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.11+ |
| Docker | 20.10+ |
| Docker Compose | v2+ |
| Elasticsearch | 8.8.0 (managed via Docker) |

---

## Getting Started

### Docker (recommended)

The easiest way to run the full stack is with Docker Compose. This starts both Elasticsearch and the dashboard in a single command.

```bash
# Clone the repository
git clone https://github.com/maariogutierrez/dynamic-risk-assessment-dashboard.git
cd dynamic-risk-assessment-dashboard

# Start all services
docker compose -f docker/docker-compose.yml up
```

The dashboard will be available at **http://localhost:5002** once Elasticsearch passes its health check (typically ~30 seconds).

To stop all services:

```bash
docker compose -f docker/docker-compose.yml down
```

> **Memory note**: Elasticsearch is configured with `ES_JAVA_OPTS=-Xms4g -Xmx8g` and a container `mem_limit` of 8 GB. Ensure your host has sufficient available memory.

### Local Development

**1. Create and activate a virtual environment**

```bash
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Start Elasticsearch**

A local Elasticsearch instance is required. The quickest way is Docker:

```bash
docker run -d \
  --name es-dev \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  elasticsearch:8.8.0
```

**4. Run the Flask application**

```bash
cd flaskProject
python app.py -p 5002
```

The dashboard is available at **http://localhost:5002**.

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch connection URL used by the Flask app |
| `PYTHONUNBUFFERED` | — | Set to `1` in Docker to flush stdout/stderr immediately |

The application port defaults to `5002` and is passed as a CLI argument (`-p`) to `app.py`.

---

## Usage

### Dashboard Navigation

| URL | View |
|---|---|
| `/` | Redirects to `/propagation` |
| `/assets` | Asset inventory with risk levels |
| `/threats` | Threat scenario list |
| `/feared_events` | Feared event catalog |
| `/risks` | Computed risk assessments |
| `/propagation` | Propagation graph visualization |
| `/propagation/edit` | Edit propagation rules and trigger re-assessment |

### Re-running Risk Assessment Standalone

Use the `manager.py` script directly for batch processing or debugging:

```bash
cd scripts
python manager.py -a -p ../data
```

### Re-indexing the Ontology into Elasticsearch

```bash
cd scripts
python import_onto_es.py -r -p ../data
```

Flags:
- `-r` — reset and recreate all Elasticsearch indices before indexing
- `-p PATH` — path to the data directory (default: `../data`)

---

## Project Structure

```
.
├── data/                        # Source CSV files and OWL ontology
│   ├── dra.owl                  # Base ontology schema
│   ├── dra_full.owl             # Full ontology with computed instances
│   ├── assets.csv
│   ├── assets_relationships.csv
│   ├── threat_scenarios.csv
│   ├── propagation.csv
│   └── ...
├── docker/
│   ├── Dockerfile               # Production image (python:3.11-slim)
│   └── docker-compose.yml       # Full-stack: Elasticsearch + DRA Dashboard
├── flaskProject/
│   ├── app.py                   # Flask application entrypoint and route handlers
│   ├── images/                  # Static UI icons
│   ├── logs/                    # Rotating application log files
│   ├── static/                  # CSS and JS files
│       ├── css/
│         ├── assets.css
│         ├── base.css
│         └── ...
│       ├── js/
  │       ├── assets.js
  │       └── ...
│   └── templates/               # Jinja2 HTML templates
│       ├── base.html
│       ├── assets.html
│       ├── threats.html
│       ├── feared_events.html
│       ├── risks.html
│       ├── propagation.html
│       └── propagationEdit.html
├── scripts/
│   ├── manager.py               # Ontology management and risk assessment engine
│   └── import_onto_es.py        # Elasticsearch indexing utilities
└── requirements.txt
```

---

## Risk Assessment Methodology

The engine implements a quantitative **ITSRM-based** risk assessment:

1. **Risk Score**: Each threat scenario is assigned a `risk_level` computed as:
   ```
   risk_level = matrix[likelihood][impact]
   ```
   where `matrix.csv` maps probability and impact dimensions to a numeric risk score.

2. **Asset Risk Level**: An asset's `risk_level` is the maximum risk across all associated threat scenarios.

3. **Relative Risk**: `relative_risk_level = risk_level / importance`, normalizing risk by the asset's business importance rating.

4. **Propagated Risk**: A BFS traversal of the asset relationship graph propagates risks from source assets to connected assets, subject to the criticality thresholds defined in `propagation.csv`. Propagated entities carry a `_p` suffix in Elasticsearch and the OWL ontology.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Make your changes with clear commit messages.
3. Ensure the application starts cleanly (`docker compose up`) before opening a pull request.
4. Open a pull request describing the motivation and changes.
