#!/usr/bin/env python3
# Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

"""
Unified Security Knowledge Base Query Tool for STRIDE Threat Modeling.

Combines multiple data sources for comprehensive security knowledge queries:
- Layer 1: YAML (curated) - High-quality, human-curated threat data
- Layer 2: SQLite (indexed) - Full CWE/CAPEC/ATT&CK database with relationships
- Layer 3: KEV/NVD (live) - Real-time vulnerability data

Backward compatible with query_kb.py while adding enhanced capabilities.

Usage:
    # Basic queries (compatible with query_kb.py)
    python unified_kb_query.py --stride spoofing
    python unified_kb_query.py --cwe CWE-89
    python unified_kb_query.py --element process

    # Enhanced queries (new features)
    python unified_kb_query.py --cwe CWE-89 --full-chain
    python unified_kb_query.py --cwe CWE-89 --mitigations
    python unified_kb_query.py --capec CAPEC-66 --attack-chain
    python unified_kb_query.py --check-kev CVE-2021-44228

    # Cloud and LLM queries
    python unified_kb_query.py --cloud aws --category compute
    python unified_kb_query.py --llm LLM01
    python unified_kb_query.py --ai-component rag_retrieval

Output: JSON format for integration with threat modeling workflow.
"""

import argparse
import json
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
import logging
import os
import re

# Setup logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import yaml
except ImportError:
    print("Error: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class CWEEntry:
    """Complete CWE entry with all available data."""
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    abstraction: str = ""
    stride_categories: List[str] = None
    related_capec: List[str] = None
    mitigations: List[Dict] = None
    parents: List[str] = None
    children: List[str] = None
    owasp_categories: List[str] = None
    source: str = "unknown"  # yaml, sqlite, or merged

    def __post_init__(self):
        self.stride_categories = self.stride_categories or []
        self.related_capec = self.related_capec or []
        self.mitigations = self.mitigations or []
        self.parents = self.parents or []
        self.children = self.children or []
        self.owasp_categories = self.owasp_categories or []


@dataclass
class CAPECEntry:
    """Complete CAPEC entry with ATT&CK chain."""
    id: str
    name: str
    description: str = ""
    likelihood: str = ""
    severity: str = ""
    stride_categories: List[str] = None
    related_cwe: List[str] = None
    attack_techniques: List[Dict] = None
    mitigations: List[str] = None
    source: str = "unknown"

    def __post_init__(self):
        self.stride_categories = self.stride_categories or []
        self.related_cwe = self.related_cwe or []
        self.attack_techniques = self.attack_techniques or []
        self.mitigations = self.mitigations or []


@dataclass
class KEVEntry:
    """CISA KEV (Known Exploited Vulnerabilities) entry."""
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str
    known_ransomware: str
    notes: str


# =============================================================================
# NVD API Client
# =============================================================================

class NVDClient:
    """
    NVD (National Vulnerability Database) API Client.

    Provides real-time CVE lookup with CVSS scores and CWE mappings.
    Rate-limited to respect NVD API guidelines.
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_DELAY = 6.0  # 5 requests per 30 seconds without API key

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.delay = 0.6 if api_key else self.REQUEST_DELAY
        self.last_request_time = 0

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def _request(self, params: Dict) -> Optional[Dict]:
        """Send API request with rate limiting."""
        self._rate_limit()

        query = "&".join(f"{k}={v}" for k, v in params.items() if v)
        url = f"{self.NVD_API_BASE}?{query}"

        headers = {
            "User-Agent": "STRIDE-ThreatModeling/1.0",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"NVD API HTTP Error {e.code}: {e.reason}")
            return None
        except urllib.error.URLError as e:
            logger.error(f"NVD API Network error: {e.reason}")
            return None
        except (json.JSONDecodeError, OSError, TimeoutError) as e:
            logger.error(f"NVD API Request error: {e}")
            return None

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get details for a specific CVE from NVD."""
        result = self._request({"cveId": cve_id})
        if not result or not result.get("vulnerabilities"):
            return None

        cve = result["vulnerabilities"][0]["cve"]
        return self._parse_cve(cve)

    def search_by_cwe(self, cwe_id: str, limit: int = 10) -> List[Dict]:
        """Search CVEs by CWE type."""
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        result = self._request({
            "cweId": cwe_id,
            "resultsPerPage": min(limit, 100)
        })

        if not result:
            return []

        return [
            self._parse_cve(item["cve"])
            for item in result.get("vulnerabilities", [])
        ]

    def _parse_cve(self, cve: Dict) -> Dict:
        """Parse CVE data into structured format."""
        # Get description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else ""
        )

        # Get CVSS scores
        metrics = cve.get("metrics", {})
        cvss = {}

        for version, key in [("v3.1", "cvssMetricV31"), ("v3.0", "cvssMetricV30"),
                             ("v4.0", "cvssMetricV40"), ("v2.0", "cvssMetricV2")]:
            if key in metrics and metrics[key]:
                data = metrics[key][0].get("cvssData", {})
                cvss[version] = {
                    "score": data.get("baseScore"),
                    "severity": data.get("baseSeverity") or metrics[key][0].get("baseSeverity"),
                    "vector": data.get("vectorString"),
                }

        # Get CWE mappings
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        return {
            "cve_id": cve.get("id"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description[:500] if len(description) > 500 else description,
            "cvss": cvss,
            "cwes": list(set(cwes)),
            "source": "nvd_api",
        }


# =============================================================================
# Semantic Search Engine
# =============================================================================

class SemanticSearcher:
    """
    Semantic search engine for CWE/CAPEC descriptions.

    Uses TF-IDF vectorization with cosine similarity for semantic matching.
    Optionally supports sentence-transformers for higher-quality embeddings.

    Features:
    - Lazy index building (on first search)
    - Multi-source search (CWE + CAPEC)
    - Configurable result limit
    - Fallback to keyword matching if vectorization fails
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._tfidf = None
        self._tfidf_matrix = None
        self._index_data = []  # [(id, type, name, description), ...]
        self._index_built = False
        self._use_transformers = False

        # Try to import sentence-transformers for better embeddings
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer('all-MiniLM-L6-v2')
            self._embeddings = None
            self._use_transformers = True
            logger.info("Using sentence-transformers for semantic search")
        except ImportError:
            self._model = None
            logger.info("Using TF-IDF for semantic search (install sentence-transformers for better results)")

    def _build_index(self):
        """Build search index from SQLite database."""
        if self._index_built:
            return

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
            import numpy as np
            self._np = np
            self._cosine_similarity = cosine_similarity
        except ImportError:
            logger.error("sklearn not available for semantic search")
            return

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Load CWE data
        try:
            cursor.execute("SELECT id, name, description FROM cwe WHERE description IS NOT NULL AND description != ''")
            for row in cursor.fetchall():
                self._index_data.append({
                    "id": row[0],
                    "type": "CWE",
                    "name": row[1] or "",
                    "description": row[2] or "",
                    "text": f"{row[1] or ''} {row[2] or ''}".strip()
                })
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not load CWE data: {e}")

        # Load CAPEC data
        try:
            cursor.execute("SELECT id, name, description FROM capec WHERE description IS NOT NULL AND description != ''")
            for row in cursor.fetchall():
                self._index_data.append({
                    "id": row[0],
                    "type": "CAPEC",
                    "name": row[1] or "",
                    "description": row[2] or "",
                    "text": f"{row[1] or ''} {row[2] or ''}".strip()
                })
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not load CAPEC data: {e}")

        conn.close()

        if not self._index_data:
            logger.error("No data loaded for semantic search index")
            return

        # Build index based on available method
        texts = [item["text"] for item in self._index_data]

        if self._use_transformers and self._model:
            # Use sentence-transformers for high-quality embeddings
            logger.info(f"Building sentence-transformer embeddings for {len(texts)} items...")
            self._embeddings = self._model.encode(texts, show_progress_bar=False)
        else:
            # Use TF-IDF vectorization
            logger.info(f"Building TF-IDF index for {len(texts)} items...")
            self._tfidf = TfidfVectorizer(
                max_features=5000,
                stop_words='english',
                ngram_range=(1, 2),
                sublinear_tf=True
            )
            self._tfidf_matrix = self._tfidf.fit_transform(texts)

        self._index_built = True
        logger.info(f"Semantic search index built: {len(self._index_data)} entries")

    def search(self, query: str, top_k: int = 10, entry_type: Optional[str] = None) -> List[Dict]:
        """
        Search for semantically similar CWE/CAPEC entries.

        Args:
            query: Natural language query
            top_k: Number of results to return
            entry_type: Filter by type ('CWE', 'CAPEC', or None for both)

        Returns:
            List of matching entries with similarity scores
        """
        self._build_index()

        if not self._index_built or not self._index_data:
            return []

        try:
            if self._use_transformers and self._model and self._embeddings is not None:
                # Sentence-transformer search
                query_embedding = self._model.encode([query])[0]
                similarities = self._cosine_similarity(
                    [query_embedding],
                    self._embeddings
                )[0]
            else:
                # TF-IDF search
                query_vec = self._tfidf.transform([query])
                similarities = self._cosine_similarity(query_vec, self._tfidf_matrix)[0]

            # Get top-k indices
            top_indices = self._np.argsort(similarities)[::-1]

            results = []
            for idx in top_indices:
                if len(results) >= top_k:
                    break

                item = self._index_data[idx]
                score = float(similarities[idx])

                # Skip low-relevance results
                if score < 0.05:
                    continue

                # Apply type filter
                if entry_type and item["type"] != entry_type.upper():
                    continue

                results.append({
                    "id": item["id"],
                    "type": item["type"],
                    "name": item["name"],
                    "description": item["description"][:300] + "..." if len(item["description"]) > 300 else item["description"],
                    "similarity_score": round(score, 4),
                })

            return results

        except (ValueError, TypeError, RuntimeError) as e:
            logger.error(f"Semantic search error: {e}")
            return []

    def get_index_stats(self) -> Dict:
        """Get statistics about the search index."""
        self._build_index()

        cwe_count = sum(1 for item in self._index_data if item["type"] == "CWE")
        capec_count = sum(1 for item in self._index_data if item["type"] == "CAPEC")

        return {
            "total_indexed": len(self._index_data),
            "cwe_count": cwe_count,
            "capec_count": capec_count,
            "search_method": "sentence-transformers" if self._use_transformers else "tfidf",
            "index_built": self._index_built,
        }


# =============================================================================
# FTS5 Query Sanitization
# =============================================================================

def _sanitize_fts5_query(query: str) -> str:
    """Sanitize user input for FTS5 MATCH to prevent query manipulation.

    Strips FTS5 special operators and wraps terms in quotes for literal matching.
    """
    # Remove FTS5 operators and special characters
    sanitized = re.sub(r'[*()"\']', '', query)
    # Collapse whitespace
    sanitized = ' '.join(sanitized.split())
    if not sanitized:
        return '""'  # Empty query returns nothing
    # Quote individual terms to force literal matching
    terms = sanitized.split()
    return ' '.join(f'"{term}"' for term in terms if term)


# =============================================================================
# Unified Knowledge Base
# =============================================================================

class UnifiedKnowledgeBase:
    """
    Unified Security Knowledge Base with multi-layer data access.

    Layer 1: YAML (curated) - High-quality threat data, human-curated
    Layer 2: SQLite Core (indexed) - CWE/CAPEC/ATT&CK/STRIDE/OWASP (~8MB)
    Layer 3: SQLite Extension (optional) - CVE index (~300MB)
    Layer 4: KEV/NVD (live) - Real-time vulnerability data

    Database Architecture:
    - security_kb.sqlite (core): Required for basic threat modeling
    - security_kb_extension.sqlite: Optional CVE vulnerability intelligence
    """

    def __init__(self, knowledge_dir: Optional[Path] = None):
        if knowledge_dir is None:
            # v3.0: knowledge/ is directly under project root (not assets/knowledge)
            knowledge_dir = Path(__file__).parent.parent / "knowledge"

        self.knowledge_dir = Path(knowledge_dir)

        # Dual-database architecture (v2.0.1+)
        # - security_kb.sqlite: Core knowledge base (CWE, CAPEC, ATT&CK, STRIDE, etc.)
        # - security_kb_extension.sqlite: CVE vulnerability data (optional, 300MB+)
        self.sqlite_core_path = self.knowledge_dir / "security_kb.sqlite"
        self.sqlite_extension_path = self.knowledge_dir / "security_kb_extension.sqlite"
        self.sqlite_path = self.sqlite_core_path

        self._yaml_cache: Dict[str, dict] = {}
        self._kev_cache: Dict[str, KEVEntry] = {}
        self._kev_loaded = False
        self._extension_available: Optional[bool] = None

        # Embedding support (lazy-loaded)
        self._embedding_model = None
        self._embeddings_available: Optional[bool] = None
        self._np = None  # numpy module

        # Validate paths
        if not self.knowledge_dir.exists():
            logger.warning(f"Knowledge directory not found: {self.knowledge_dir}")

    @property
    def has_extension(self) -> bool:
        """Check if CVE extension database is available."""
        if self._extension_available is None:
            self._extension_available = self.sqlite_extension_path.exists()
        return self._extension_available

    def _get_extension_connection(self) -> Optional[sqlite3.Connection]:
        """Get SQLite connection to extension database (CVE index)."""
        if self.sqlite_extension_path.exists():
            return sqlite3.connect(str(self.sqlite_extension_path))
        return None

    # =========================================================================
    # Embedding & Semantic Search Layer
    # =========================================================================

    @property
    def has_embeddings(self) -> bool:
        """Check if pre-generated embeddings are available in database."""
        if self._embeddings_available is None:
            conn = self._get_sqlite_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT COUNT(*) FROM kb_embeddings WHERE embedding IS NOT NULL"
                    )
                    count = cursor.fetchone()[0]
                    self._embeddings_available = count > 0
                except sqlite3.OperationalError:
                    self._embeddings_available = False
                finally:
                    conn.close()
            else:
                self._embeddings_available = False
        return self._embeddings_available

    def _load_embedding_model(self) -> bool:
        """Lazy-load the embedding model for query encoding."""
        if self._embedding_model is not None:
            return True

        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np
            self._np = np
            self._embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            logger.info("Loaded embedding model: all-MiniLM-L6-v2")
            return True
        except ImportError:
            logger.warning("sentence-transformers not available, falling back to FTS5")
            return False

    def semantic_search(
        self,
        query: str,
        entry_types: Optional[List[str]] = None,
        limit: int = 10,
        min_score: float = 0.3
    ) -> List[Dict]:
        """
        Semantic search across CWE, CAPEC, ATT&CK, STRIDE, OWASP.

        Uses pre-computed embeddings from kb_embeddings table.
        Falls back to FTS5 if embeddings or model not available.

        Args:
            query: Natural language search query
            entry_types: Filter by types ('cwe', 'capec', 'attack', 'stride', 'owasp')
            limit: Maximum results to return
            min_score: Minimum similarity score (0-1)

        Returns:
            List of matching entries with similarity scores
        """
        # Try vector search first
        if self.has_embeddings and self._load_embedding_model():
            results = self._vector_search(query, entry_types, limit, min_score)
            if results:
                return results

        # Fallback to FTS5
        logger.info("Using FTS5 fallback for search")
        return self._fts_unified_search(query, entry_types, limit)

    def _vector_search(
        self,
        query: str,
        entry_types: Optional[List[str]],
        limit: int,
        min_score: float
    ) -> List[Dict]:
        """Vector similarity search using pre-stored embeddings."""
        conn = self._get_sqlite_connection()
        if not conn or not self._embedding_model:
            return []

        try:
            cursor = conn.cursor()

            # Encode query
            query_embedding = self._embedding_model.encode(query)

            # Build type filter
            type_filter = ""
            params = []
            if entry_types:
                placeholders = ",".join("?" for _ in entry_types)
                type_filter = f"WHERE entry_type IN ({placeholders})"
                params = [t.lower() for t in entry_types]

            # Load embeddings from database
            cursor.execute(f"""
                SELECT id, entry_type, embedding
                FROM kb_embeddings
                {type_filter}
            """, params)

            results = []
            for row in cursor.fetchall():
                entry_id, entry_type, embedding_bytes = row
                # Convert bytes to numpy array
                stored_embedding = self._np.frombuffer(embedding_bytes, dtype=self._np.float32)

                # Compute cosine similarity
                similarity = self._np.dot(query_embedding, stored_embedding) / (
                    self._np.linalg.norm(query_embedding) * self._np.linalg.norm(stored_embedding)
                )

                if similarity >= min_score:
                    results.append({
                        "id": entry_id,
                        "type": entry_type,
                        "similarity_score": round(float(similarity), 4),
                    })

            # Sort by similarity and limit
            results.sort(key=lambda x: x["similarity_score"], reverse=True)
            results = results[:limit]

            # Enrich with full data
            for result in results:
                entry_id = result["id"]
                entry_type = result["type"]

                if entry_type == "cwe":
                    data = self.get_sqlite_cwe(entry_id)
                    if data:
                        result["name"] = data.get("name", "")
                        result["description"] = data.get("description", "")[:200]
                elif entry_type == "capec":
                    data = self.get_sqlite_capec(entry_id)
                    if data:
                        result["name"] = data.get("name", "")
                        result["description"] = data.get("description", "")[:200]
                elif entry_type == "attack":
                    data = self.get_attack_technique(entry_id)
                    if data:
                        result["name"] = data.get("name", "")
                        result["description"] = data.get("description", "")[:200]
                elif entry_type == "stride":
                    cursor.execute(
                        "SELECT name, description FROM stride_category WHERE id = ?",
                        (entry_id.replace("STRIDE-", ""),)
                    )
                    row = cursor.fetchone()
                    if row:
                        result["name"] = row[0]
                        result["description"] = row[1][:200] if row[1] else ""
                elif entry_type == "owasp":
                    cursor.execute(
                        "SELECT name, description FROM owasp_top10 WHERE id = ?",
                        (entry_id.split("-")[-1],)  # Extract A01 from OWASP-2025-A01
                    )
                    row = cursor.fetchone()
                    if row:
                        result["name"] = row[0]
                        result["description"] = row[1][:200] if row[1] else ""

            return results
        except (sqlite3.Error, ValueError, TypeError) as e:
            logger.error(f"Vector search error: {e}")
            return []
        finally:
            conn.close()

    def _fts_unified_search(
        self,
        query: str,
        entry_types: Optional[List[str]],
        limit: int
    ) -> List[Dict]:
        """Unified FTS5 search across all knowledge base tables."""
        conn = self._get_sqlite_connection()
        if not conn:
            return []

        results = []
        try:
            cursor = conn.cursor()
            per_type_limit = max(limit // 3, 5)  # Distribute limit across types

            types_to_search = entry_types if entry_types else ['cwe', 'capec', 'attack']

            # Search CWE
            if 'cwe' in types_to_search:
                try:
                    cursor.execute("""
                        SELECT id, name, snippet(cwe_fts, 2, '[', ']', '...', 32)
                        FROM cwe_fts WHERE cwe_fts MATCH ? LIMIT ?
                    """, (_sanitize_fts5_query(query), per_type_limit))
                    for row in cursor.fetchall():
                        results.append({
                            "id": row[0],
                            "type": "cwe",
                            "name": row[1],
                            "description": row[2],
                            "match_type": "fts5"
                        })
                except (sqlite3.OperationalError, sqlite3.DatabaseError):
                    pass

            # Search CAPEC
            if 'capec' in types_to_search:
                try:
                    cursor.execute("""
                        SELECT id, name, snippet(capec_fts, 2, '[', ']', '...', 32)
                        FROM capec_fts WHERE capec_fts MATCH ? LIMIT ?
                    """, (_sanitize_fts5_query(query), per_type_limit))
                    for row in cursor.fetchall():
                        results.append({
                            "id": row[0],
                            "type": "capec",
                            "name": row[1],
                            "description": row[2],
                            "match_type": "fts5"
                        })
                except (sqlite3.OperationalError, sqlite3.DatabaseError):
                    pass

            # Search ATT&CK
            if 'attack' in types_to_search:
                try:
                    cursor.execute("""
                        SELECT id, name, snippet(attack_fts, 2, '[', ']', '...', 32)
                        FROM attack_fts WHERE attack_fts MATCH ? LIMIT ?
                    """, (_sanitize_fts5_query(query), per_type_limit))
                    for row in cursor.fetchall():
                        results.append({
                            "id": row[0],
                            "type": "attack",
                            "name": row[1],
                            "description": row[2],
                            "match_type": "fts5"
                        })
                except (sqlite3.OperationalError, sqlite3.DatabaseError):
                    pass

            return results[:limit]
        except (sqlite3.Error, ValueError) as e:
            logger.error(f"FTS search error: {e}")
            return []
        finally:
            conn.close()

    # =========================================================================
    # YAML Layer (Curated Data)
    # =========================================================================

    def _load_yaml(self, filename: str) -> dict:
        """Load YAML file with caching."""
        if filename in self._yaml_cache:
            return self._yaml_cache[filename]

        path = self.knowledge_dir / filename
        if not path.exists():
            logger.warning(f"YAML file not found: {path}")
            return {}

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            self._yaml_cache[filename] = data
            return data
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            logger.error(f"Error loading {path}: {e}")
            return {}

    def get_yaml_cwe(self, cwe_id: str) -> Optional[Dict]:
        """Get CWE from curated YAML (Top 25)."""
        cwe_id = self._normalize_cwe_id(cwe_id)
        data = self._load_yaml("cwe-mappings.yaml")
        top_25 = data.get("cwe_top_25_2025", {})
        return top_25.get(cwe_id)

    def get_yaml_capec(self, capec_id: str) -> Optional[Dict]:
        """Get CAPEC from curated YAML."""
        capec_id = self._normalize_capec_id(capec_id)
        data = self._load_yaml("capec-mappings.yaml")
        patterns = data.get("attack_patterns", {})
        return patterns.get(capec_id)

    def get_stride_info(self, category: str) -> Optional[Dict]:
        """Get STRIDE category information."""
        category = category.lower().replace(" ", "_")
        data = self._load_yaml("stride-library.yaml")
        categories = data.get("stride_categories", {})
        return categories.get(category)

    # =========================================================================
    # SQLite Layer (Full Database)
    # =========================================================================

    def _get_sqlite_connection(self) -> Optional[sqlite3.Connection]:
        """Get SQLite connection if database exists.

        NOTE (D2): No schema version validation is performed. The tool relies on
        table/column existence checks at query time (OperationalError handling)
        rather than upfront schema validation. This is acceptable for a read-only
        query tool where schema mismatches produce clear error messages.
        """
        if not self.sqlite_path.exists():
            logger.warning(f"SQLite database not found: {self.sqlite_path}")
            return None
        return sqlite3.connect(str(self.sqlite_path))

    def get_sqlite_cwe(self, cwe_id: str) -> Optional[Dict]:
        """Get CWE from SQLite database."""
        conn = self._get_sqlite_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            cwe_id = self._normalize_cwe_id(cwe_id)

            # Get basic CWE info (note: cwe table uses 'id', not 'cwe_id')
            cursor.execute(
                "SELECT id, name, description, abstraction, status FROM cwe WHERE id = ?",
                (cwe_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "abstraction": row[3],
                "status": row[4],
            }

            # Get STRIDE mappings
            cursor.execute(
                "SELECT stride_category FROM stride_cwe WHERE cwe_id = ?",
                (cwe_id,)
            )
            result["stride_categories"] = [r[0] for r in cursor.fetchall()]

            # Get CAPEC mappings (capec_cwe maps CAPEC→CWE, so we search by cwe_id)
            cursor.execute(
                "SELECT DISTINCT capec_id FROM capec_cwe WHERE cwe_id = ?",
                (cwe_id,)
            )
            result["related_capec"] = [r[0] for r in cursor.fetchall()]

            # Get hierarchy
            cursor.execute(
                "SELECT parent_id FROM cwe_hierarchy WHERE child_id = ?",
                (cwe_id,)
            )
            result["parents"] = [r[0] for r in cursor.fetchall()]

            cursor.execute(
                "SELECT child_id FROM cwe_hierarchy WHERE parent_id = ?",
                (cwe_id,)
            )
            result["children"] = [r[0] for r in cursor.fetchall()]

            # Get OWASP mappings (V2: JOIN with owasp_top10 for names)
            cursor.execute("""
                SELECT oc.owasp_id, ot.name, ot.year
                FROM owasp_cwe oc
                JOIN owasp_top10 ot ON oc.owasp_id = ot.id AND oc.year = ot.year
                WHERE oc.cwe_id = ?
            """, (cwe_id,))
            result["owasp_categories"] = [
                {"id": r[0], "name": r[1], "year": r[2]} for r in cursor.fetchall()
            ]

            return result
        finally:
            conn.close()

    def get_cwe_mitigations(self, cwe_id: str) -> List[Dict]:
        """Get mitigations for a CWE from SQLite (V2 schema)."""
        conn = self._get_sqlite_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()
            cwe_id = self._normalize_cwe_id(cwe_id)

            # V2: cwe_mitigation table with phase, strategy, description, effectiveness
            cursor.execute("""
                SELECT phase, strategy, description, effectiveness
                FROM cwe_mitigation
                WHERE cwe_id = ?
            """, (cwe_id,))
            return [
                {
                    "phase": r[0],
                    "strategy": r[1],
                    "description": r[2],
                    "effectiveness": r[3]
                }
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_sqlite_capec(self, capec_id: str) -> Optional[Dict]:
        """Get CAPEC from SQLite database (V2 schema)."""
        conn = self._get_sqlite_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            capec_id = self._normalize_capec_id(capec_id)

            # Get basic CAPEC info
            cursor.execute(
                "SELECT id, name, description FROM capec WHERE id = ?",
                (capec_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "capec_id": row[0],
                "name": row[1],
                "description": row[2],
            }

            # Get related CWEs
            cursor.execute(
                "SELECT cwe_id FROM capec_cwe WHERE capec_id = ?",
                (capec_id,)
            )
            result["related_cwes"] = [r[0] for r in cursor.fetchall()]

            # Get ATT&CK techniques (V2: JOIN with attack_technique for names)
            cursor.execute("""
                SELECT ca.attack_id, at.name, at.tactics
                FROM capec_attack ca
                JOIN attack_technique at ON ca.attack_id = at.id
                WHERE ca.capec_id = ?
            """, (capec_id,))
            result["attack_techniques"] = [
                {
                    "technique_id": r[0],
                    "technique_name": r[1],
                    "tactics": [t.strip() for t in r[2].split(',')] if r[2] else []
                }
                for r in cursor.fetchall()
            ]

            return result
        finally:
            conn.close()

    def get_capec_attack_chain(self, capec_id: str) -> List[Dict]:
        """Get ATT&CK techniques for a CAPEC from SQLite (V2 schema)."""
        conn = self._get_sqlite_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()
            capec_id = self._normalize_capec_id(capec_id)

            # V2: JOIN with attack_technique for technique details
            cursor.execute("""
                SELECT ca.attack_id, at.name, at.tactics, at.description
                FROM capec_attack ca
                JOIN attack_technique at ON ca.attack_id = at.id
                WHERE ca.capec_id = ?
            """, (capec_id,))
            return [
                {
                    "technique_id": r[0],
                    "technique_name": r[1],
                    "tactics": [t.strip() for t in r[2].split(',')] if r[2] else [],
                    "description": (r[3][:200] + "...") if r[3] and len(r[3]) > 200 else r[3]
                }
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_cwes_for_stride_sqlite(self, category: str) -> List[str]:
        """Get all CWEs for a STRIDE category from SQLite.

        Args:
            category: STRIDE category - accepts either:
                - Single letter code: 'S', 'T', 'R', 'I', 'D', 'E'
                - Full name: 'spoofing', 'tampering', etc.
        """
        # Map full names to single-letter codes
        stride_name_to_code = {
            "spoofing": "S",
            "tampering": "T",
            "repudiation": "R",
            "information_disclosure": "I",
            "denial_of_service": "D",
            "elevation_of_privilege": "E",
        }

        # Normalize input
        normalized = category.lower().replace(" ", "_")
        stride_code = stride_name_to_code.get(normalized, category.upper())

        conn = self._get_sqlite_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cwe_id FROM stride_cwe WHERE stride_category = ?",
                (stride_code,)
            )
            return [r[0] for r in cursor.fetchall()]
        finally:
            conn.close()

    # =========================================================================
    # ATT&CK Queries (V2 New)
    # =========================================================================

    def get_attack_technique(self, technique_id: str) -> Optional[Dict]:
        """Get ATT&CK technique details from V2 database."""
        conn = self._get_sqlite_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            # Normalize ID (T1234 or T1234.001)
            technique_id = technique_id.upper().strip()
            if not technique_id.startswith("T"):
                technique_id = f"T{technique_id}"

            cursor.execute("""
                SELECT id, stix_id, name, description, tactics, platforms,
                       detection, is_subtechnique, parent_technique, version
                FROM attack_technique
                WHERE id = ?
            """, (technique_id,))
            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "technique_id": row[0],
                "stix_id": row[1],
                "name": row[2],
                "description": row[3],
                "tactics": [t.strip() for t in row[4].split(',')] if row[4] else [],
                "platforms": [p.strip() for p in row[5].split(',')] if row[5] else [],
                "detection": row[6],
                "is_subtechnique": bool(row[7]),
                "parent_technique": row[8],
                "version": row[9],
            }

            # Get mitigations for this technique
            cursor.execute("""
                SELECT am.id, am.name, atm.description
                FROM attack_tech_mitigation atm
                JOIN attack_mitigation am ON atm.mitigation_id = am.id
                WHERE atm.technique_id = ?
            """, (technique_id,))
            result["mitigations"] = [
                {"id": r[0], "name": r[1], "relationship": r[2]}
                for r in cursor.fetchall()
            ]

            # Get related CAPECs
            cursor.execute("""
                SELECT capec_id FROM capec_attack WHERE attack_id = ?
            """, (technique_id,))
            result["related_capecs"] = [r[0] for r in cursor.fetchall()]

            return result
        finally:
            conn.close()

    def get_attack_mitigation(self, mitigation_id: str) -> Optional[Dict]:
        """Get ATT&CK mitigation details from V2 database."""
        conn = self._get_sqlite_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            # Normalize ID (M1234)
            mitigation_id = mitigation_id.upper().strip()
            if not mitigation_id.startswith("M"):
                mitigation_id = f"M{mitigation_id}"

            cursor.execute("""
                SELECT id, stix_id, name, description
                FROM attack_mitigation
                WHERE id = ?
            """, (mitigation_id,))
            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "mitigation_id": row[0],
                "stix_id": row[1],
                "name": row[2],
                "description": row[3],
            }

            # Get techniques mitigated
            cursor.execute("""
                SELECT at.id, at.name, atm.description
                FROM attack_tech_mitigation atm
                JOIN attack_technique at ON atm.technique_id = at.id
                WHERE atm.mitigation_id = ?
            """, (mitigation_id,))
            result["mitigates_techniques"] = [
                {"id": r[0], "name": r[1], "relationship": r[2]}
                for r in cursor.fetchall()
            ]

            return result
        finally:
            conn.close()

    def search_attack_techniques(self, query: str, limit: int = 10) -> List[Dict]:
        """Search ATT&CK techniques using FTS5."""
        conn = self._get_sqlite_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()
            # Try FTS5 search first
            try:
                cursor.execute("""
                    SELECT at.id, at.name, at.tactics, snippet(attack_fts, 2, '[', ']', '...', 32) as match_snippet
                    FROM attack_fts
                    JOIN attack_technique at ON attack_fts.id = at.id
                    WHERE attack_fts MATCH ?
                    LIMIT ?
                """, (_sanitize_fts5_query(query), limit))
                return [
                    {
                        "technique_id": r[0],
                        "name": r[1],
                        "tactics": [t.strip() for t in r[2].split(',')] if r[2] else [],
                        "match_snippet": r[3]
                    }
                    for r in cursor.fetchall()
                ]
            except (sqlite3.OperationalError, sqlite3.DatabaseError):
                # Fallback to LIKE search (handles FTS errors and corrupted indexes)
                # Escape LIKE wildcards to prevent unexpected pattern matching
                like_query = query.replace("%", "\\%").replace("_", "\\_")
                cursor.execute("""
                    SELECT id, name, tactics, description
                    FROM attack_technique
                    WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'
                    LIMIT ?
                """, (f"%{like_query}%", f"%{like_query}%", limit))
                return [
                    {
                        "technique_id": r[0],
                        "name": r[1],
                        "tactics": [t.strip() for t in r[2].split(',')] if r[2] else [],
                        "description": (r[3][:150] + "...") if r[3] and len(r[3]) > 150 else r[3]
                    }
                    for r in cursor.fetchall()
                ]
        finally:
            conn.close()

    def get_cwe_full_chain(self, cwe_id: str) -> Dict:
        """
        Get complete security chain for a CWE:
        STRIDE → CWE → CAPEC → ATT&CK + OWASP + Mitigations
        """
        cwe_id = self._normalize_cwe_id(cwe_id)

        # Try SQLite first (more complete)
        sqlite_data = self.get_sqlite_cwe(cwe_id)
        yaml_data = self.get_yaml_cwe(cwe_id)

        # Merge data (SQLite base + YAML enrichment)
        result = {
            "cwe_id": cwe_id,
            "source": "merged" if sqlite_data and yaml_data else (
                "sqlite" if sqlite_data else (
                    "yaml" if yaml_data else "not_found"
                )
            )
        }

        if sqlite_data:
            result.update({
                "name": sqlite_data.get("name", ""),
                "description": sqlite_data.get("description", ""),
                "abstraction": sqlite_data.get("abstraction", ""),
                "stride_categories": sqlite_data.get("stride_categories", []),
                "related_capec": sqlite_data.get("related_capec", []),
                "parents": sqlite_data.get("parents", []),
                "children": sqlite_data.get("children", []),
                "owasp_categories": sqlite_data.get("owasp_categories", []),
            })

            # Get mitigations
            result["mitigations"] = self.get_cwe_mitigations(cwe_id)

            # Get ATT&CK techniques for related CAPECs
            attack_techniques = []
            for capec_id in result.get("related_capec", [])[:10]:  # Limit
                techniques = self.get_capec_attack_chain(capec_id)
                for t in techniques:
                    t["via_capec"] = capec_id
                attack_techniques.extend(techniques)
            result["attack_techniques"] = attack_techniques

        if yaml_data:
            # Enrich with YAML data (better descriptions, examples)
            if not result.get("name"):
                result["name"] = yaml_data.get("name", "")
            if not result.get("description"):
                result["description"] = yaml_data.get("description", "")

            # Add consequences from YAML
            result["consequences"] = yaml_data.get("consequences", [])

            # Prefer YAML mitigations if available (more detailed)
            yaml_mitigations = yaml_data.get("mitigations", [])
            if yaml_mitigations:
                result["yaml_mitigations"] = yaml_mitigations

        return result

    # =========================================================================
    # KEV Layer (Live Data)
    # =========================================================================

    def _load_kev_cache(self) -> None:
        """Load KEV data into memory cache."""
        if self._kev_loaded:
            return

        kev_path = self.knowledge_dir.parent / "Library" / "NVD" / "kev" / "known_exploited_vulnerabilities.json"
        if not kev_path.exists():
            # Try alternative path
            kev_path = Path.home() / "STRIDE" / "Library" / "NVD" / "kev" / "known_exploited_vulnerabilities.json"

        if not kev_path.exists():
            logger.warning(f"KEV file not found: {kev_path}")
            self._kev_loaded = True
            return

        try:
            with open(kev_path, 'r') as f:
                data = json.load(f)

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    self._kev_cache[cve_id] = KEVEntry(
                        cve_id=cve_id,
                        vendor=vuln.get("vendorProject", ""),
                        product=vuln.get("product", ""),
                        vulnerability_name=vuln.get("vulnerabilityName", ""),
                        date_added=vuln.get("dateAdded", ""),
                        due_date=vuln.get("dueDate", ""),
                        known_ransomware=vuln.get("knownRansomwareCampaignUse", ""),
                        notes=vuln.get("notes", ""),
                    )

            self._kev_loaded = True
            logger.info(f"Loaded {len(self._kev_cache)} KEV entries")
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error(f"Error loading KEV: {e}")
            self._kev_loaded = True

    def check_kev(self, cve_id: str) -> Dict:
        """Check if a CVE is in CISA KEV."""
        self._load_kev_cache()
        cve_id = cve_id.upper()

        if cve_id in self._kev_cache:
            entry = self._kev_cache[cve_id]
            return {
                "is_known_exploited": True,
                "cve_id": entry.cve_id,
                "vendor": entry.vendor,
                "product": entry.product,
                "vulnerability_name": entry.vulnerability_name,
                "date_added": entry.date_added,
                "due_date": entry.due_date,
                "known_ransomware": entry.known_ransomware,
                "notes": entry.notes,
            }

        return {
            "is_known_exploited": False,
            "cve_id": cve_id,
        }

    # =========================================================================
    # Cloud & LLM Queries (from YAML)
    # =========================================================================

    def get_cloud_services(self, provider: str, category: Optional[str] = None) -> Dict:
        """Query cloud service threats."""
        data = self._load_yaml("cloud-services.yaml")
        if not data:
            return {"error": "Cloud services knowledge base not found"}

        provider = provider.lower()
        service_categories = data.get("service_categories", {})
        stride_by_category = data.get("stride_by_category", {})

        if category:
            category = category.lower()
            if category not in service_categories:
                return {"error": f"Invalid category: {category}"}

            cat_services = service_categories.get(category, {}).get("services", {})
            cat_stride = stride_by_category.get(category, {})

            return {
                "provider": provider.upper(),
                "category": category,
                "services": cat_services.get(provider, []),
                "stride_threats": cat_stride,
            }
        else:
            all_services = {}
            for cat_name, cat_info in service_categories.items():
                services = cat_info.get("services", {}).get(provider, [])
                if services:
                    all_services[cat_name] = services

            return {
                "provider": provider.upper(),
                "service_categories": all_services,
            }

    def get_llm_threat(self, llm_id: str) -> Dict:
        """Query OWASP LLM Top 10 threat."""
        data = self._load_yaml("llm-threats.yaml")
        if not data:
            return {"error": "LLM threats knowledge base not found"}

        llm_id = llm_id.upper()
        owasp_top10 = data.get("owasp_llm_top10", {})

        if llm_id not in owasp_top10:
            return {"error": f"Invalid LLM ID: {llm_id}. Valid: {list(owasp_top10.keys())}"}

        return owasp_top10[llm_id]

    def get_ai_component(self, component: str) -> Dict:
        """Query AI component threats."""
        data = self._load_yaml("llm-threats.yaml")
        if not data:
            return {"error": "LLM threats knowledge base not found"}

        component = component.lower()
        components = data.get("ai_components", {})

        if component not in components:
            return {"error": f"Invalid component: {component}. Valid: {list(components.keys())}"}

        return components[component]

    # =========================================================================
    # STRIDE Queries
    # =========================================================================

    def query_stride(self, category: str) -> Dict:
        """
        Query a STRIDE category with merged data from all sources.
        """
        category = category.lower().replace(" ", "_")

        # Get YAML info
        stride_info = self.get_stride_info(category)

        # Get all CWEs from SQLite (more complete)
        sqlite_cwes = self.get_cwes_for_stride_sqlite(category)

        # Get YAML CWEs (curated)
        yaml_cwes = stride_info.get("primary_cwes", []) if stride_info else []

        # Merge
        all_cwes = list(set(sqlite_cwes + yaml_cwes))

        result = {
            "category": category.upper(),
            "source": "merged",
        }

        if stride_info:
            result.update({
                "code": stride_info.get("code", ""),
                "name": stride_info.get("name", ""),
                "description": stride_info.get("description", ""),
                "security_property": stride_info.get("security_property", ""),
                "threat_examples": stride_info.get("threat_examples", []),
                "typical_mitigations": stride_info.get("typical_mitigations", []),
            })

        result["cwes"] = {
            "curated": yaml_cwes,
            "all": all_cwes[:50],  # Limit
            "total_count": len(all_cwes),
        }

        result["capecs"] = stride_info.get("primary_capec", []) if stride_info else []

        return result

    # =========================================================================
    # CVE Index Queries (323K+ records) - Requires Extension Database
    # =========================================================================

    def get_cve(self, cve_id: str) -> Dict:
        """
        Query a CVE by ID with full details including CWE mappings.

        Requires: security_kb_extension.sqlite or security_kb.sqlite

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Dict with CVE details, CVSS score, CWE mappings, and KEV status
        """
        if not self.has_extension:
            return {
                "error": "CVE extension database not available",
                "hint": "Download security_kb_extension.sqlite for CVE queries"
            }

        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        conn = self._get_extension_connection()
        if not conn:
            return {"error": "CVE database connection failed"}

        try:
            cursor = conn.cursor()

            # Get CVE details
            cursor.execute("""
                SELECT id, state, date_published, date_updated, description,
                       cvss_version, cvss_score, cvss_severity, cvss_vector,
                       vendors, products
                FROM cve WHERE id = ?
            """, (cve_id,))

            row = cursor.fetchone()
            if not row:
                return {"error": f"CVE not found: {cve_id}"}

            result = {
                "cve_id": row[0],
                "state": row[1],
                "date_published": row[2],
                "date_updated": row[3],
                "description": row[4],
                "cvss": {
                    "version": row[5],
                    "score": row[6],
                    "severity": row[7],
                    "vector": row[8],
                } if row[5] else None,
                "vendors": json.loads(row[9]) if row[9] else [],
                "products": json.loads(row[10]) if row[10] else [],
            }

            # Get CWE mappings
            cursor.execute("""
                SELECT cwe_id FROM cve_cwe WHERE cve_id = ?
            """, (cve_id,))
            result["cwes"] = [r[0] for r in cursor.fetchall()]

            # Check KEV status
            kev_status = self.check_kev(cve_id)
            result["kev"] = kev_status

            return result

        finally:
            conn.close()

    def search_cves(self, query: str, limit: int = 20, severity: str = None) -> List[Dict]:
        """
        Full-text search CVEs using FTS5 index.

        Requires: security_kb_extension.sqlite

        Args:
            query: Search terms (e.g., "SQL injection", "buffer overflow")
            limit: Max results (default 20)
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of matching CVEs with scores and descriptions
        """
        if not self.has_extension:
            return []

        conn = self._get_extension_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()

            # Build query with optional severity filter
            if severity:
                cursor.execute("""
                    SELECT c.id, c.cvss_score, c.cvss_severity,
                           substr(c.description, 1, 200) as desc,
                           c.date_published
                    FROM cve_fts f
                    JOIN cve c ON f.id = c.id
                    WHERE cve_fts MATCH ?
                    AND c.cvss_severity = ?
                    ORDER BY rank
                    LIMIT ?
                """, (_sanitize_fts5_query(query), severity.upper(), limit))
            else:
                cursor.execute("""
                    SELECT c.id, c.cvss_score, c.cvss_severity,
                           substr(c.description, 1, 200) as desc,
                           c.date_published
                    FROM cve_fts f
                    JOIN cve c ON f.id = c.id
                    WHERE cve_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """, (_sanitize_fts5_query(query), limit))

            return [
                {
                    "cve_id": r[0],
                    "cvss_score": r[1],
                    "severity": r[2],
                    "description": r[3] + "..." if r[3] and len(r[3]) >= 200 else r[3],
                    "date_published": r[4],
                }
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_cves_for_cwe(self, cwe_id: str, limit: int = 20,
                         severity: str = None) -> List[Dict]:
        """
        Get CVEs associated with a specific CWE.

        Requires: security_kb_extension.sqlite

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            limit: Max results
            severity: Filter by severity

        Returns:
            List of CVEs with this CWE mapping
        """
        if not self.has_extension:
            return []

        cwe_id = self._normalize_cwe_id(cwe_id)

        conn = self._get_extension_connection()
        if not conn:
            return []

        try:
            cursor = conn.cursor()

            if severity:
                cursor.execute("""
                    SELECT c.id, c.cvss_score, c.cvss_severity,
                           substr(c.description, 1, 150) as desc,
                           c.date_published
                    FROM cve_cwe cc
                    JOIN cve c ON cc.cve_id = c.id
                    WHERE cc.cwe_id = ?
                    AND c.cvss_severity = ?
                    ORDER BY c.cvss_score DESC, c.date_published DESC
                    LIMIT ?
                """, (cwe_id, severity.upper(), limit))
            else:
                cursor.execute("""
                    SELECT c.id, c.cvss_score, c.cvss_severity,
                           substr(c.description, 1, 150) as desc,
                           c.date_published
                    FROM cve_cwe cc
                    JOIN cve c ON cc.cve_id = c.id
                    WHERE cc.cwe_id = ?
                    ORDER BY c.cvss_score DESC, c.date_published DESC
                    LIMIT ?
                """, (cwe_id, limit))

            return [
                {
                    "cve_id": r[0],
                    "cvss_score": r[1],
                    "severity": r[2],
                    "description": r[3] + "..." if r[3] else None,
                    "date_published": r[4],
                }
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def get_cve_statistics(self) -> Dict:
        """Get CVE index statistics. Requires extension database."""
        if not self.has_extension:
            return {
                "error": "CVE extension database not available",
                "hint": "Download security_kb_extension.sqlite for CVE statistics"
            }

        conn = self._get_extension_connection()
        if not conn:
            return {"error": "CVE database connection failed"}

        try:
            cursor = conn.cursor()
            stats = {}

            # Check if CVE table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='cve'
            """)
            if not cursor.fetchone():
                return {"error": "CVE index not built. Run: python scripts/build_cve_index.py --full"}

            # Total CVEs
            cursor.execute("SELECT COUNT(*) FROM cve")
            stats['total_cves'] = cursor.fetchone()[0]

            # By state
            cursor.execute("""
                SELECT state, COUNT(*) FROM cve
                GROUP BY state ORDER BY COUNT(*) DESC
            """)
            stats['by_state'] = {r[0]: r[1] for r in cursor.fetchall()}

            # By severity
            cursor.execute("""
                SELECT cvss_severity, COUNT(*) FROM cve
                WHERE cvss_severity IS NOT NULL
                GROUP BY cvss_severity ORDER BY COUNT(*) DESC
            """)
            stats['by_severity'] = {r[0]: r[1] for r in cursor.fetchall()}

            # By year (recent 5)
            cursor.execute("""
                SELECT substr(id, 5, 4) as year, COUNT(*) FROM cve
                GROUP BY year ORDER BY year DESC LIMIT 5
            """)
            stats['by_year'] = {r[0]: r[1] for r in cursor.fetchall()}

            # CWE coverage
            cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cwe")
            stats['cves_with_cwe'] = cursor.fetchone()[0]

            # Top 5 CWEs
            cursor.execute("""
                SELECT cwe_id, COUNT(*) as cnt FROM cve_cwe
                GROUP BY cwe_id ORDER BY cnt DESC LIMIT 5
            """)
            stats['top_cwes'] = {r[0]: r[1] for r in cursor.fetchall()}

            return stats
        finally:
            conn.close()

    def get_stride_cve_chain(self, stride_category: str, limit: int = 10) -> List[Dict]:
        """
        Get CVEs for a STRIDE category via CWE mappings.

        Path: STRIDE → CWE → CVE
        Requires: Core database + Extension database

        Args:
            stride_category: Single letter (S/T/R/I/D/E)
            limit: Max results per CWE

        Returns:
            List of CVEs with STRIDE relevance
        """
        if not self.has_extension:
            return []

        stride_category = stride_category.upper()[0]

        # Get CWEs for STRIDE category from core database
        core_conn = self._get_sqlite_connection()
        if not core_conn:
            return []

        try:
            cursor = core_conn.cursor()
            cursor.execute(
                "SELECT cwe_id FROM stride_cwe WHERE stride_category = ?",
                (stride_category,)
            )
            cwe_ids = [r[0] for r in cursor.fetchall()]
        finally:
            core_conn.close()

        if not cwe_ids:
            return []

        # Get CVEs for those CWEs from extension database
        ext_conn = self._get_extension_connection()
        if not ext_conn:
            return []

        try:
            cursor = ext_conn.cursor()
            placeholders = ",".join(["?" for _ in cwe_ids])
            cursor.execute(f"""
                SELECT DISTINCT c.id, c.cvss_score, c.cvss_severity,
                       cc.cwe_id, substr(c.description, 1, 100) as desc
                FROM cve_cwe cc
                JOIN cve c ON cc.cve_id = c.id
                WHERE cc.cwe_id IN ({placeholders})
                AND c.cvss_severity IN ('CRITICAL', 'HIGH')
                ORDER BY c.cvss_score DESC
                LIMIT ?
            """, (*cwe_ids, limit))

            return [
                {
                    "cve_id": r[0],
                    "cvss_score": r[1],
                    "severity": r[2],
                    "via_cwe": r[3],
                    "description": r[4] + "..." if r[4] else None,
                }
                for r in cursor.fetchall()
            ]
        finally:
            ext_conn.close()

    # =========================================================================
    # Utilities
    # =========================================================================

    @staticmethod
    def _normalize_cwe_id(cwe_id: str) -> str:
        """Normalize CWE ID format."""
        cwe_id = str(cwe_id).upper().strip()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        return cwe_id

    @staticmethod
    def _normalize_capec_id(capec_id: str) -> str:
        """Normalize CAPEC ID format."""
        capec_id = str(capec_id).upper().strip()
        if not capec_id.startswith("CAPEC-"):
            capec_id = f"CAPEC-{capec_id}"
        return capec_id

    def get_statistics(self) -> Dict:
        """Get comprehensive knowledge base statistics (V2 schema)."""
        stats = {
            "version": "OWASP 2025 / CWE 4.19 / CAPEC 3.9 / ATT&CK 18.1",
            "last_updated": "2025-12-24",
            "schema_version": "V2",
            "database_architecture": {
                "core": str(self.sqlite_core_path),
                "extension": str(self.sqlite_extension_path),
                "extension_available": self.has_extension,
            },
            "data_sources": {
                "yaml_curated": {},
                "sqlite_core": {},
                "sqlite_extension": {},
                "kev_live": {},
            },
            "totals": {},
        }

        # YAML statistics
        try:
            stride_data = self._load_yaml("stride-library.yaml")
            cwe_data = self._load_yaml("cwe-mappings.yaml")
            capec_data = self._load_yaml("capec-mappings.yaml")
            llm_data = self._load_yaml("llm-threats.yaml")

            stats["data_sources"]["yaml_curated"] = {
                "stride_categories": len(stride_data.get("stride_categories", {})),
                "cwe_top25": len(cwe_data.get("cwe_top_25_2025", {})),
                "capec_patterns": len(capec_data.get("attack_patterns", {})),
                "llm_top10": len(llm_data.get("owasp_llm_top10", {})),
            }
        except (yaml.YAMLError, OSError, KeyError, TypeError) as e:
            stats["data_sources"]["yaml_curated"]["error"] = str(e)

        # SQLite Core statistics
        conn = self._get_sqlite_connection()
        if conn:
            try:
                cursor = conn.cursor()

                # Core tables (threat modeling essentials)
                core_tables = [
                    ("cwe", "CWE Definitions"),
                    ("cwe_hierarchy", "CWE Parent-Child Relations"),
                    ("cwe_mitigation", "CWE Mitigations"),
                    ("capec", "CAPEC Attack Patterns"),
                    ("capec_cwe", "CAPEC-CWE Mappings"),
                    ("capec_attack", "CAPEC-ATT&CK Mappings"),
                    ("attack_technique", "ATT&CK Techniques"),
                    ("attack_mitigation", "ATT&CK Mitigations"),
                    ("attack_tech_mitigation", "ATT&CK Tech-Mitigation Links"),
                    ("stride_cwe", "STRIDE-CWE Mappings"),
                    ("stride_category", "STRIDE Categories"),
                    ("owasp_cwe", "OWASP-CWE Mappings"),
                    ("owasp_top10", "OWASP Top 10 Categories"),
                ]

                core_stats = {}
                for table, desc in core_tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        core_stats[table] = {"count": count, "description": desc}
                    except sqlite3.OperationalError:
                        core_stats[table] = {"count": 0, "description": desc, "error": "table not found"}

                stats["data_sources"]["sqlite_core"] = core_stats

                # OWASP breakdown (V2: JOIN with owasp_top10)
                cursor.execute("""
                    SELECT ot.id, ot.name, ot.cwe_count
                    FROM owasp_top10 ot
                    ORDER BY ot.id
                """)
                stats["owasp_2025_breakdown"] = {
                    row[0]: {"name": row[1], "cwe_count": row[2]}
                    for row in cursor.fetchall()
                }

                # ATT&CK tactics breakdown
                cursor.execute("""
                    SELECT tactics, COUNT(*) as count
                    FROM attack_technique
                    WHERE tactics IS NOT NULL AND tactics != '[]'
                    GROUP BY tactics
                    ORDER BY count DESC
                    LIMIT 10
                """)
                stats["attack_tactics_breakdown"] = {
                    row[0]: row[1] for row in cursor.fetchall()
                }

            finally:
                conn.close()
        else:
            stats["data_sources"]["sqlite_core"]["error"] = "Core database not available"

        # SQLite Extension statistics (CVE index)
        ext_conn = self._get_extension_connection()
        if ext_conn:
            try:
                cursor = ext_conn.cursor()

                ext_tables = [
                    ("cve", "CVE Vulnerabilities"),
                    ("cve_cwe", "CVE-CWE Mappings"),
                ]

                ext_stats = {}
                for table, desc in ext_tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        ext_stats[table] = {"count": count, "description": desc}
                    except sqlite3.OperationalError:
                        ext_stats[table] = {"count": 0, "description": desc, "error": "table not found"}

                stats["data_sources"]["sqlite_extension"] = ext_stats

            finally:
                ext_conn.close()
        else:
            stats["data_sources"]["sqlite_extension"] = {
                "status": "not_installed",
                "hint": "Download security_kb_extension.sqlite for CVE vulnerability intelligence"
            }

        # KEV statistics
        self._load_kev_cache()
        stats["data_sources"]["kev_live"] = {
            "total_entries": len(self._kev_cache),
            "source": "CISA Known Exploited Vulnerabilities",
        }

        # Calculate totals
        core_data = stats["data_sources"].get("sqlite_core", {})
        ext_data = stats["data_sources"].get("sqlite_extension", {})

        stats["totals"] = {
            "cwe_definitions": core_data.get("cwe", {}).get("count", 0),
            "capec_patterns": core_data.get("capec", {}).get("count", 0),
            "cwe_mitigations": core_data.get("cwe_mitigation", {}).get("count", 0),
            "attack_techniques": core_data.get("attack_technique", {}).get("count", 0),
            "attack_mitigations": core_data.get("attack_mitigation", {}).get("count", 0),
            "capec_attack_mappings": core_data.get("capec_attack", {}).get("count", 0),
            "kev_entries": len(self._kev_cache),
            "owasp_2025_cwes": core_data.get("owasp_cwe", {}).get("count", 0),
            "cve_vulnerabilities": ext_data.get("cve", {}).get("count", 0),
            "cve_cwe_mappings": ext_data.get("cve_cwe", {}).get("count", 0),
        }

        return stats

    # =========================================================================
    # Verification Set Queries (v2.0)
    # =========================================================================

    def get_stride_tests(self, stride_code: str) -> Dict:
        """
        Get verification tests for a STRIDE category.

        Uses v_stride_all_tests view to retrieve WSTG, MASTG, and ASVS tests
        mapped to the specified STRIDE category.

        Args:
            stride_code: STRIDE code (S, T, R, I, D, E)

        Returns:
            Dict with STRIDE info and associated tests by type
        """
        stride_code = stride_code.upper()
        if stride_code not in ("S", "T", "R", "I", "D", "E"):
            return {"error": f"Invalid STRIDE code: {stride_code}. Use S, T, R, I, D, or E"}

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT test_type, test_id, test_name, test_detail, relevance
                FROM v_stride_all_tests
                WHERE stride_code = ?
                ORDER BY test_type, relevance DESC, test_id
            """, (stride_code,))

            rows = cursor.fetchall()

            # Group by test type
            tests_by_type = {"wstg": [], "mastg": [], "asvs": []}
            for row in rows:
                test_type, test_id, test_name, test_detail, relevance = row
                tests_by_type[test_type].append({
                    "test_id": test_id,
                    "name": test_name,
                    "detail": test_detail,
                    "relevance": relevance,
                })

            stride_names = {
                "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information Disclosure", "D": "Denial of Service",
                "E": "Elevation of Privilege"
            }

            return {
                "stride_code": stride_code,
                "stride_name": stride_names.get(stride_code, "Unknown"),
                "total_tests": len(rows),
                "tests": tests_by_type,
            }
        finally:
            conn.close()

    def get_cwe_tests(self, cwe_id: str) -> Dict:
        """
        Get verification tests for a CWE.

        Uses v_cwe_all_tests view to retrieve WSTG, MASTG, and ASVS tests
        mapped to the specified CWE.

        Args:
            cwe_id: CWE identifier (e.g., CWE-89)

        Returns:
            Dict with CWE info and associated tests by type
        """
        cwe_id = self._normalize_cwe_id(cwe_id)

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT test_type, test_id, test_name, relevance
                FROM v_cwe_all_tests
                WHERE cwe_id = ?
                ORDER BY test_type, relevance DESC, test_id
            """, (cwe_id,))

            rows = cursor.fetchall()

            # Group by test type
            tests_by_type = {"wstg": [], "mastg": [], "asvs": []}
            for row in rows:
                test_type, test_id, test_name, relevance = row
                tests_by_type[test_type].append({
                    "test_id": test_id,
                    "name": test_name,
                    "relevance": relevance,
                })

            # Get CWE name
            cursor.execute("SELECT name FROM cwe WHERE id = ?", (cwe_id,))
            cwe_row = cursor.fetchone()
            cwe_name = cwe_row[0] if cwe_row else "Unknown"

            return {
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "total_tests": len(rows),
                "tests": tests_by_type,
            }
        finally:
            conn.close()

    def get_asvs_by_level(self, level: str) -> Dict:
        """
        Get ASVS requirements by verification level.

        Args:
            level: ASVS level (L1, L2, or L3)

        Returns:
            Dict with requirements for the specified level
        """
        level = level.upper()
        if level not in ("L1", "L2", "L3"):
            return {"error": f"Invalid ASVS level: {level}. Use L1, L2, or L3"}

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()

            # Map level to column
            level_col = {"L1": "level_1", "L2": "level_2", "L3": "level_3"}[level]

            cursor.execute(f"""
                SELECT requirement_id, chapter, chapter_name, section, section_name,
                       description, verification_method,
                       level_1, level_2, level_3
                FROM asvs_requirement
                WHERE {level_col} = 1
                ORDER BY chapter, section, requirement_id
            """)

            rows = cursor.fetchall()

            # Group by chapter
            chapters = {}
            for row in rows:
                req_id, chapter, chapter_name, section, section_name, desc, method, l1, l2, l3 = row
                if chapter not in chapters:
                    chapters[chapter] = {
                        "chapter_name": chapter_name,
                        "requirements": [],
                    }
                chapters[chapter]["requirements"].append({
                    "requirement_id": req_id,
                    "section": section,
                    "section_name": section_name,
                    "description": desc,
                    "verification_method": method,
                    "levels": {"L1": bool(l1), "L2": bool(l2), "L3": bool(l3)},
                })

            return {
                "level": level,
                "total_requirements": len(rows),
                "chapters": chapters,
            }
        finally:
            conn.close()

    def get_asvs_by_chapter(self, chapter: str) -> Dict:
        """
        Get ASVS requirements by chapter.

        Args:
            chapter: ASVS chapter (V1-V17)

        Returns:
            Dict with all requirements in the chapter
        """
        chapter = chapter.upper()
        if not chapter.startswith("V"):
            chapter = "V" + chapter

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT requirement_id, chapter, chapter_name, section, section_name,
                       description, verification_method,
                       level_1, level_2, level_3
                FROM asvs_requirement
                WHERE chapter = ?
                ORDER BY section, requirement_id
            """, (chapter,))

            rows = cursor.fetchall()
            if not rows:
                return {"error": f"No requirements found for chapter: {chapter}"}

            requirements = []
            chapter_name = None
            for row in rows:
                req_id, ch, ch_name, section, section_name, desc, method, l1, l2, l3 = row
                chapter_name = ch_name
                requirements.append({
                    "requirement_id": req_id,
                    "section": section,
                    "section_name": section_name,
                    "description": desc,
                    "verification_method": method,
                    "levels": {"L1": bool(l1), "L2": bool(l2), "L3": bool(l3)},
                })

            return {
                "chapter": chapter,
                "chapter_name": chapter_name,
                "total_requirements": len(requirements),
                "requirements": requirements,
            }
        finally:
            conn.close()

    def get_wstg_by_category(self, category: str) -> Dict:
        """
        Get WSTG tests by category.

        Args:
            category: WSTG category code (e.g., ATHN, AUTHZ, INPV)

        Returns:
            Dict with all tests in the category
        """
        category = category.upper()

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT test_id, category_name, name, objective, test_steps, tools, severity
                FROM wstg_test
                WHERE category = ?
                ORDER BY test_id
            """, (category,))

            rows = cursor.fetchall()
            if not rows:
                return {"error": f"No tests found for category: {category}"}

            tests = []
            category_name = None
            for row in rows:
                test_id, cat_name, name, objective, steps, tools, severity = row
                category_name = cat_name
                tests.append({
                    "test_id": test_id,
                    "name": name,
                    "objective": objective,
                    "test_steps": steps,
                    "tools": tools,
                    "severity": severity,
                })

            return {
                "category": category,
                "category_name": category_name,
                "total_tests": len(tests),
                "tests": tests,
            }
        finally:
            conn.close()

    def get_mastg_by_platform(self, platform: str) -> Dict:
        """
        Get MASTG tests by platform.

        Args:
            platform: Platform (android, ios, or both)

        Returns:
            Dict with all tests for the platform
        """
        platform = platform.lower()
        if platform not in ("android", "ios", "both"):
            return {"error": f"Invalid platform: {platform}. Use android, ios, or both"}

        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()
            if platform == "both":
                cursor.execute("""
                    SELECT test_id, masvs_id, platform, name, objective,
                           static_analysis, dynamic_analysis, tools, severity
                    FROM mastg_test
                    ORDER BY masvs_id, test_id
                """)
            else:
                cursor.execute("""
                    SELECT test_id, masvs_id, platform, name, objective,
                           static_analysis, dynamic_analysis, tools, severity
                    FROM mastg_test
                    WHERE platform IN (?, 'both')
                    ORDER BY masvs_id, test_id
                """, (platform,))

            rows = cursor.fetchall()

            tests = []
            for row in rows:
                test_id, masvs_id, plat, name, objective, static, dynamic, tools, severity = row
                tests.append({
                    "test_id": test_id,
                    "masvs_id": masvs_id,
                    "platform": plat,
                    "name": name,
                    "objective": objective,
                    "static_analysis": static,
                    "dynamic_analysis": dynamic,
                    "tools": tools,
                    "severity": severity,
                })

            return {
                "platform": platform,
                "total_tests": len(tests),
                "tests": tests,
            }
        finally:
            conn.close()

    def get_verification_stats(self) -> Dict:
        """Get statistics about the Verification Set."""
        conn = self._get_sqlite_connection()
        if not conn:
            return {"error": "SQLite database not available"}

        try:
            cursor = conn.cursor()

            stats = {}

            # WSTG stats
            cursor.execute("SELECT COUNT(*) FROM wstg_test")
            stats["wstg_tests"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT category) FROM wstg_test")
            stats["wstg_categories"] = cursor.fetchone()[0]

            # MASTG stats
            cursor.execute("SELECT COUNT(*) FROM mastg_test")
            stats["mastg_tests"] = cursor.fetchone()[0]

            cursor.execute("SELECT platform, COUNT(*) FROM mastg_test GROUP BY platform")
            stats["mastg_by_platform"] = {row[0]: row[1] for row in cursor.fetchall()}

            # ASVS stats
            cursor.execute("SELECT COUNT(*) FROM asvs_requirement")
            stats["asvs_requirements"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT chapter) FROM asvs_requirement")
            stats["asvs_chapters"] = cursor.fetchone()[0]

            cursor.execute("""
                SELECT
                    SUM(CASE WHEN level_1 = 1 THEN 1 ELSE 0 END) as l1,
                    SUM(CASE WHEN level_2 = 1 THEN 1 ELSE 0 END) as l2,
                    SUM(CASE WHEN level_3 = 1 THEN 1 ELSE 0 END) as l3
                FROM asvs_requirement
            """)
            row = cursor.fetchone()
            stats["asvs_by_level"] = {"L1": row[0], "L2": row[1], "L3": row[2]}

            # Mapping stats
            cursor.execute("SELECT COUNT(*) FROM stride_verification")
            stats["stride_test_mappings"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM cwe_verification")
            stats["cwe_test_mappings"] = cursor.fetchone()[0]

            return {
                "verification_set": stats,
                "total_tests": stats["wstg_tests"] + stats["mastg_tests"],
                "total_requirements": stats["asvs_requirements"],
            }
        finally:
            conn.close()

    # =========================================================================
    # STRIDE Controls Queries (v3.0 - C3/C4/C5 fixes)
    # =========================================================================

    def get_stride_controls(self, stride_code: str) -> Dict:
        """
        Get security controls mapped to a STRIDE category.

        Args:
            stride_code: Single letter STRIDE code (S, T, R, I, D, E)

        Returns:
            Dict with controls, mitigation patterns, and test patterns
        """
        stride_map = {
            "S": "spoofing",
            "T": "tampering",
            "R": "repudiation",
            "I": "information_disclosure",
            "D": "denial_of_service",
            "E": "elevation_of_privilege",
        }

        stride_key = stride_map.get(stride_code.upper())
        if not stride_key:
            return {"error": f"Invalid STRIDE code: {stride_code}. Use S, T, R, I, D, or E"}

        data = self._load_yaml("stride-controls-mapping.yaml")
        if not data:
            return {"error": "stride-controls-mapping.yaml not found"}

        stride_controls = data.get("stride_to_controls", {})
        control_data = stride_controls.get(stride_key)

        if not control_data:
            return {"error": f"No controls found for STRIDE category: {stride_code}"}

        return {
            "stride_code": stride_code.upper(),
            "stride_name": stride_key.replace("_", " ").title(),
            "security_property": control_data.get("security_property", ""),
            "description": control_data.get("description", ""),
            "primary_controls": control_data.get("primary_controls", []),
            "secondary_controls": control_data.get("secondary_controls", []),
            "mitigation_patterns": control_data.get("mitigation_patterns", []),
            "test_patterns": control_data.get("test_patterns", []),
        }

    def get_control(self, domain: str) -> Dict:
        """
        Get security control details by domain code.

        Args:
            domain: Domain code (e.g., AUTHN, AUTHZ, INPUT, CRYPTO, etc.)

        Returns:
            Dict with domain details, requirements, and control references
        """
        data = self._load_yaml("security-design.yaml")
        if not data:
            return {"error": "security-design.yaml not found"}

        domain_upper = domain.upper()

        # Check core domains
        core_domains = data.get("core_domains", {})
        for key, domain_data in core_domains.items():
            if domain_data.get("code") == domain_upper:
                return {
                    "domain_code": domain_upper,
                    "domain_name": domain_data.get("name", ""),
                    "sequence": domain_data.get("seq", ""),
                    "stride_category": domain_data.get("stride_category", ""),
                    "description": domain_data.get("description", ""),
                    "core_requirements": domain_data.get("core_requirements", []),
                    "core_principles": domain_data.get("core_principles", []),
                    "controls_ref": domain_data.get("controls_ref", ""),
                    "patterns_ref": domain_data.get("patterns_ref", ""),
                    "owasp_refs": domain_data.get("owasp_refs", []),
                    "domain_type": "core",
                }

        # Check extended domains
        extended_domains = data.get("extended_domains", {})
        for key, domain_data in extended_domains.items():
            if domain_data.get("code") == domain_upper:
                return {
                    "domain_code": domain_upper,
                    "domain_name": domain_data.get("name", ""),
                    "sequence": domain_data.get("seq", ""),
                    "stride_category": domain_data.get("stride_category", ""),
                    "description": domain_data.get("description", ""),
                    "core_requirements": domain_data.get("core_requirements", []),
                    "core_principles": domain_data.get("core_principles", []),
                    "controls_ref": domain_data.get("controls_ref", ""),
                    "owasp_refs": domain_data.get("owasp_refs", []),
                    "domain_type": "extended",
                }

        # List available domains if not found
        available_core = [d.get("code") for d in core_domains.values()]
        available_ext = [d.get("code") for d in extended_domains.values() if d.get("code")]

        return {
            "error": f"Domain not found: {domain}",
            "available_core_domains": available_core,
            "available_extended_domains": available_ext,
        }

    def get_all_controls(self) -> Dict:
        """Get overview of all security control domains."""
        data = self._load_yaml("security-design.yaml")
        if not data:
            return {"error": "security-design.yaml not found"}

        core_domains = data.get("core_domains", {})
        extended_domains = data.get("extended_domains", {})

        return {
            "core_domains": {
                domain_data.get("code"): {
                    "name": domain_data.get("name", ""),
                    "stride_category": domain_data.get("stride_category", ""),
                    "description": domain_data.get("description", ""),
                }
                for domain_data in core_domains.values()
            },
            "extended_domains": {
                domain_data.get("code"): {
                    "name": domain_data.get("name", ""),
                    "stride_category": domain_data.get("stride_category", ""),
                    "description": domain_data.get("description", ""),
                }
                for domain_data in extended_domains.values()
                if domain_data.get("code")
            },
            "total_core": len(core_domains),
            "total_extended": len(extended_domains),
        }

    def get_compliance(self, framework: str = None) -> Dict:
        """
        Get compliance framework information and mappings.

        Args:
            framework: Optional framework ID (e.g., OWASP-ASVS, NIST-CSF)
                      If None, returns list of all frameworks

        Returns:
            Dict with framework details or list of frameworks
        """
        data = self._load_yaml("compliance-mappings.yaml")
        if not data:
            return {"error": "compliance-mappings.yaml not found"}

        frameworks = data.get("frameworks", {})

        if framework is None:
            # Return all frameworks grouped by category
            by_category = {}
            for fw_key, fw_data in frameworks.items():
                category = fw_data.get("category", "other")
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append({
                    "id": fw_data.get("id", fw_key),
                    "name": fw_data.get("name", ""),
                    "version": fw_data.get("version", ""),
                })

            return {
                "frameworks_by_category": by_category,
                "total_frameworks": len(frameworks),
            }

        # Find specific framework
        framework_upper = framework.upper().replace("-", "_")
        framework_lower = framework.lower().replace("-", "_")

        # Try exact match first
        fw_data = frameworks.get(framework_lower) or frameworks.get(framework_upper)

        # Try by ID match
        if not fw_data:
            for key, data_item in frameworks.items():
                if data_item.get("id", "").upper() == framework.upper():
                    fw_data = data_item
                    break

        if not fw_data:
            available = [f.get("id", k) for k, f in frameworks.items()]
            return {
                "error": f"Framework not found: {framework}",
                "available_frameworks": available,
            }

        result = {
            "framework_id": fw_data.get("id", ""),
            "name": fw_data.get("name", ""),
            "version": fw_data.get("version", ""),
            "category": fw_data.get("category", ""),
            "url": fw_data.get("url", ""),
        }

        # Add optional fields if present
        if "document" in fw_data:
            result["document"] = fw_data["document"]
        if "chapters" in fw_data:
            result["chapters"] = fw_data["chapters"]
        if "functions" in fw_data:
            result["functions"] = fw_data["functions"]
        if "families" in fw_data:
            result["families"] = fw_data["families"]

        return result

    def get_stride_compliance_mapping(self, stride_code: str) -> Dict:
        """
        Get compliance requirements mapped to a STRIDE category.

        Args:
            stride_code: Single letter STRIDE code (S, T, R, I, D, E)

        Returns:
            Dict with compliance mappings for the STRIDE category
        """
        data = self._load_yaml("compliance-mappings.yaml")
        if not data:
            return {"error": "compliance-mappings.yaml not found"}

        stride_map = {
            "S": "spoofing",
            "T": "tampering",
            "R": "repudiation",
            "I": "information_disclosure",
            "D": "denial_of_service",
            "E": "elevation_of_privilege",
        }

        stride_key = stride_map.get(stride_code.upper())
        if not stride_key:
            return {"error": f"Invalid STRIDE code: {stride_code}. Use S, T, R, I, D, or E"}

        mappings = data.get("stride_compliance_mapping", {})
        stride_mapping = mappings.get(stride_key, {})

        if not stride_mapping:
            return {
                "stride_code": stride_code.upper(),
                "stride_name": stride_key.replace("_", " ").title(),
                "mappings": {},
                "note": "No compliance mappings defined for this STRIDE category",
            }

        return {
            "stride_code": stride_code.upper(),
            "stride_name": stride_key.replace("_", " ").title(),
            "asvs_chapters": stride_mapping.get("asvs", []),
            "nist_families": stride_mapping.get("nist_800_53", []),
            "cis_controls": stride_mapping.get("cis", []),
            "iso27001_controls": stride_mapping.get("iso27001", []),
        }


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Unified Security Knowledge Base Query Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # STRIDE queries
    python unified_kb_query.py --stride spoofing
    python unified_kb_query.py --all-stride

    # CWE queries
    python unified_kb_query.py --cwe CWE-89
    python unified_kb_query.py --cwe CWE-89 --full-chain
    python unified_kb_query.py --cwe CWE-89 --mitigations

    # CAPEC queries
    python unified_kb_query.py --capec CAPEC-66
    python unified_kb_query.py --capec CAPEC-66 --attack-chain

    # ATT&CK queries (V2 new)
    python unified_kb_query.py --attack-technique T1059
    python unified_kb_query.py --attack-technique T1059.001
    python unified_kb_query.py --attack-mitigation M1049
    python unified_kb_query.py --attack-search "command line"

    # KEV queries
    python unified_kb_query.py --check-kev CVE-2021-44228

    # CVE Index queries (323K+ local records)
    python unified_kb_query.py --cve CVE-2021-44228
    python unified_kb_query.py --cve-search "SQL injection" --cve-severity CRITICAL
    python unified_kb_query.py --cve-for-cwe CWE-89 --cve-severity HIGH
    python unified_kb_query.py --cve-stats
    python unified_kb_query.py --stride-cve T  # Tampering CVEs

    # NVD API queries (real-time)
    python unified_kb_query.py --nvd-cve CVE-2021-44228
    python unified_kb_query.py --nvd-cwe CWE-89 --nvd-limit 5

    # Cloud queries
    python unified_kb_query.py --cloud aws
    python unified_kb_query.py --cloud aws --category compute

    # LLM/AI queries
    python unified_kb_query.py --llm LLM01
    python unified_kb_query.py --all-llm
    python unified_kb_query.py --ai-component rag_retrieval

    # Element queries
    python unified_kb_query.py --element process

    # Semantic search (natural language)
    python unified_kb_query.py --semantic-search "SQL injection in web forms"
    python unified_kb_query.py -S "authentication bypass" --search-type cwe
    python unified_kb_query.py --search "buffer overflow attack" --search-limit 5

    # Verification Set queries (v2.0 new)
    python unified_kb_query.py --stride-tests S         # Spoofing verification tests
    python unified_kb_query.py --stride-tests T         # Tampering verification tests
    python unified_kb_query.py --cwe-tests CWE-89       # CWE-specific tests
    python unified_kb_query.py --asvs-level L2          # ASVS L2 requirements
    python unified_kb_query.py --asvs-chapter V6        # Authentication chapter
    python unified_kb_query.py --wstg-category ATHN     # WSTG Authentication tests
    python unified_kb_query.py --mastg-platform android # Mobile security tests
    python unified_kb_query.py --verification-stats     # Verification Set statistics
        """
    )

    # STRIDE arguments
    parser.add_argument("--stride", "-s",
        choices=["spoofing", "tampering", "repudiation",
                 "information_disclosure", "denial_of_service",
                 "elevation_of_privilege"],
        help="Query by STRIDE category"
    )
    parser.add_argument("--all-stride", "-a", action="store_true",
        help="Get all STRIDE categories overview"
    )

    # CWE arguments
    parser.add_argument("--cwe", "-c", help="Query a specific CWE (e.g., CWE-89)")
    parser.add_argument("--full-chain", nargs="?", const=True, default=False,
        metavar="CWE",
        help="Get full security chain for CWE (e.g., --full-chain CWE-89 or --cwe CWE-89 --full-chain)"
    )
    parser.add_argument("--mitigations", action="store_true",
        help="Include detailed mitigations"
    )

    # CAPEC arguments
    parser.add_argument("--capec", help="Query a specific CAPEC (e.g., CAPEC-66)")
    parser.add_argument("--attack-chain", action="store_true",
        help="Get ATT&CK techniques for CAPEC"
    )

    # ATT&CK arguments (V2 new)
    parser.add_argument("--attack-technique", "-t",
        help="Query ATT&CK technique (e.g., T1059 or T1059.001)")
    parser.add_argument("--attack-mitigation", "-m",
        help="Query ATT&CK mitigation (e.g., M1049)")
    parser.add_argument("--attack-search",
        help="Search ATT&CK techniques (e.g., 'command line')")

    # KEV arguments
    parser.add_argument("--check-kev", help="Check if CVE is in CISA KEV")

    # CVE Index arguments (323K+ local records)
    parser.add_argument("--cve", help="Query CVE by ID (e.g., CVE-2021-44228)")
    parser.add_argument("--cve-search", help="Full-text search CVEs (e.g., 'SQL injection')")
    parser.add_argument("--cve-for-cwe", help="Get CVEs for a CWE (e.g., CWE-89)")
    parser.add_argument("--cve-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter CVEs by severity (use with --cve-search or --cve-for-cwe)")
    parser.add_argument("--cve-stats", action="store_true",
        help="Show CVE index statistics")
    parser.add_argument("--stride-cve",
        choices=["S", "T", "R", "I", "D", "E"],
        help="Get high-severity CVEs for STRIDE category")

    # NVD API arguments
    parser.add_argument("--nvd-cve", help="Get CVE details from NVD API (e.g., CVE-2021-44228)")
    parser.add_argument("--nvd-cwe", help="Search CVEs by CWE from NVD API (e.g., CWE-89)")
    parser.add_argument("--nvd-limit", type=int, default=10,
        help="Limit NVD search results (default: 10, max: 100)")
    parser.add_argument("--nvd-api-key", help="NVD API key (prefer NVD_API_KEY env var for security)")

    # Cloud arguments
    parser.add_argument("--cloud",
        choices=["aws", "azure", "gcp", "alibaba", "tencent"],
        help="Query cloud provider services"
    )
    parser.add_argument("--category",
        choices=["compute", "storage", "database", "networking", "identity", "serverless"],
        help="Cloud service category (use with --cloud)"
    )

    # LLM/AI arguments
    parser.add_argument("--llm", help="Query OWASP LLM Top 10 threat (e.g., LLM01)")
    parser.add_argument("--all-llm", action="store_true",
        help="Get all OWASP LLM Top 10 threats"
    )
    parser.add_argument("--ai-component",
        choices=["llm_inference_service", "rag_retrieval", "vector_database",
                 "model_training_pipeline", "agent_tool_executor"],
        help="Query AI component threats"
    )

    # Security Controls arguments (v3.0 - C3/C4/C5)
    parser.add_argument("--stride-controls",
        choices=["S", "T", "R", "I", "D", "E"],
        help="Get security controls for STRIDE category (e.g., S for Spoofing)"
    )
    parser.add_argument("--control",
        help="Get security control by domain (e.g., AUTHN, AUTHZ, INPUT, CRYPTO)"
    )
    parser.add_argument("--all-controls", action="store_true",
        help="Get overview of all security control domains"
    )
    parser.add_argument("--compliance",
        nargs="?", const=None, default=False,
        help="Get compliance framework info (e.g., OWASP-ASVS, NIST-CSF). Without argument, lists all frameworks"
    )
    parser.add_argument("--stride-compliance",
        choices=["S", "T", "R", "I", "D", "E"],
        help="Get compliance mappings for STRIDE category"
    )

    # Element arguments
    parser.add_argument("--element", "-e",
        choices=["process", "data_store", "data_flow", "external_interactor"],
        help="Get applicable STRIDE for element type"
    )

    # Output arguments
    parser.add_argument("--pretty", "-p", action="store_true",
        help="Pretty-print JSON output"
    )

    # Statistics
    parser.add_argument("--stats", action="store_true",
        help="Show knowledge base statistics"
    )

    # Semantic search arguments
    parser.add_argument("--semantic-search", "--search", "-S",
        help="Semantic search query (natural language, e.g., 'SQL injection in web forms')"
    )
    parser.add_argument("--search-type",
        choices=["cwe", "capec", "all"],
        default="all",
        help="Filter semantic search results by type (default: all)"
    )
    parser.add_argument("--search-limit", type=int, default=10,
        help="Limit semantic search results (default: 10)"
    )
    parser.add_argument("--search-stats", action="store_true",
        help="Show semantic search index statistics"
    )

    # Verification Set arguments (v2.0 new)
    parser.add_argument("--stride-tests",
        choices=["S", "T", "R", "I", "D", "E"],
        help="Get verification tests for STRIDE category (S=Spoofing, T=Tampering, etc.)"
    )
    parser.add_argument("--cwe-tests",
        help="Get verification tests for CWE (e.g., CWE-89)"
    )
    parser.add_argument("--asvs-level",
        choices=["L1", "L2", "L3"],
        help="Get ASVS requirements by level (L1=Opportunistic, L2=Standard, L3=Advanced)"
    )
    parser.add_argument("--asvs-chapter",
        help="Get ASVS requirements by chapter (e.g., V6 for Authentication)"
    )
    parser.add_argument("--wstg-category",
        help="Get WSTG tests by category (e.g., ATHN, AUTHZ, INPV, SESS)"
    )
    parser.add_argument("--mastg-platform",
        choices=["android", "ios", "both"],
        help="Get MASTG tests by platform"
    )
    parser.add_argument("--verification-stats", action="store_true",
        help="Show Verification Set statistics (WSTG, MASTG, ASVS)"
    )

    args = parser.parse_args()

    # S9 fix: Prefer environment variable for API key
    nvd_api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")

    # Initialize knowledge base
    kb = UnifiedKnowledgeBase()
    result = None

    # Execute query
    if args.stride:
        result = kb.query_stride(args.stride)

    elif args.all_stride:
        data = kb._load_yaml("stride-library.yaml")
        categories = data.get("stride_categories", {})
        result = {
            "stride_categories": {
                cat.upper(): {
                    "code": info.get("code", ""),
                    "description": info.get("description", ""),
                    "security_property": info.get("security_property", ""),
                }
                for cat, info in categories.items()
            }
        }

    elif args.full_chain and args.full_chain is not True:
        # --full-chain CWE-94 (shorthand syntax)
        result = kb.get_cwe_full_chain(args.full_chain)

    elif args.cwe:
        if args.full_chain:
            # --cwe CWE-94 --full-chain (original syntax)
            result = kb.get_cwe_full_chain(args.cwe)
        elif args.mitigations:
            result = {
                "cwe_id": kb._normalize_cwe_id(args.cwe),
                "mitigations": kb.get_cwe_mitigations(args.cwe),
            }
        else:
            # Basic CWE query - try SQLite first, then YAML
            sqlite_data = kb.get_sqlite_cwe(args.cwe)
            yaml_data = kb.get_yaml_cwe(args.cwe)

            if sqlite_data:
                result = sqlite_data
                result["source"] = "sqlite"
            elif yaml_data:
                result = yaml_data
                result["source"] = "yaml"
            else:
                result = {"error": f"CWE not found: {args.cwe}"}

    elif args.capec:
        capec_id = kb._normalize_capec_id(args.capec)
        yaml_data = kb.get_yaml_capec(capec_id)
        sqlite_data = kb.get_sqlite_capec(capec_id)

        if yaml_data:
            result = yaml_data
            result["source"] = "yaml"
            if args.attack_chain:
                result["attack_techniques"] = kb.get_capec_attack_chain(capec_id)
        elif sqlite_data:
            result = sqlite_data
            result["source"] = "sqlite"
            # SQLite data already includes attack_techniques
        else:
            result = {"error": f"CAPEC not found: {args.capec}"}

    elif args.attack_technique:
        # V2: Query ATT&CK technique directly
        result = kb.get_attack_technique(args.attack_technique)
        if not result:
            result = {"error": f"ATT&CK technique not found: {args.attack_technique}"}

    elif args.attack_mitigation:
        # V2: Query ATT&CK mitigation directly
        result = kb.get_attack_mitigation(args.attack_mitigation)
        if not result:
            result = {"error": f"ATT&CK mitigation not found: {args.attack_mitigation}"}

    elif args.attack_search:
        # V2: Search ATT&CK techniques
        results = kb.search_attack_techniques(args.attack_search, limit=args.search_limit)
        result = {
            "query": args.attack_search,
            "result_count": len(results),
            "techniques": results,
        }

    elif args.check_kev:
        result = kb.check_kev(args.check_kev)

    elif args.cve:
        # Query CVE from local index (323K+ records)
        result = kb.get_cve(args.cve)

    elif args.cve_search:
        # Full-text search CVEs
        results = kb.search_cves(
            query=args.cve_search,
            limit=args.search_limit,
            severity=args.cve_severity
        )
        result = {
            "query": args.cve_search,
            "severity_filter": args.cve_severity,
            "result_count": len(results),
            "cves": results,
        }

    elif args.cve_for_cwe:
        # Get CVEs for a specific CWE
        cve_results = kb.get_cves_for_cwe(
            cwe_id=args.cve_for_cwe,
            limit=args.search_limit,
            severity=args.cve_severity
        )
        result = {
            "cwe_id": kb._normalize_cwe_id(args.cve_for_cwe),
            "severity_filter": args.cve_severity,
            "result_count": len(cve_results),
            "cves": cve_results,
        }

    elif args.cve_stats:
        # CVE index statistics
        result = kb.get_cve_statistics()

    elif args.stride_cve:
        # Get CVEs for STRIDE category
        cve_results = kb.get_stride_cve_chain(
            stride_category=args.stride_cve,
            limit=20
        )
        stride_names = {
            "S": "Spoofing",
            "T": "Tampering",
            "R": "Repudiation",
            "I": "Information Disclosure",
            "D": "Denial of Service",
            "E": "Elevation of Privilege",
        }
        result = {
            "stride_category": args.stride_cve,
            "stride_name": stride_names.get(args.stride_cve, "Unknown"),
            "result_count": len(cve_results),
            "cves": cve_results,
        }

    elif args.cloud:
        result = kb.get_cloud_services(args.cloud, args.category)

    elif args.llm:
        result = kb.get_llm_threat(args.llm)

    elif args.all_llm:
        data = kb._load_yaml("llm-threats.yaml")
        owasp_top10 = data.get("owasp_llm_top10", {})
        result = {
            "owasp_llm_top10": {
                llm_id: {
                    "name": info.get("name", ""),
                    "stride_categories": info.get("stride_categories", []),
                    "severity": info.get("severity", ""),
                }
                for llm_id, info in owasp_top10.items()
            }
        }

    elif args.ai_component:
        result = kb.get_ai_component(args.ai_component)

    # Security Controls handlers (v3.0 - C3/C4/C5)
    elif args.stride_controls:
        result = kb.get_stride_controls(args.stride_controls)

    elif args.control:
        result = kb.get_control(args.control)

    elif args.all_controls:
        result = kb.get_all_controls()

    elif args.compliance is not False:
        # --compliance with or without argument
        result = kb.get_compliance(args.compliance)

    elif args.stride_compliance:
        result = kb.get_stride_compliance_mapping(args.stride_compliance)

    elif args.element:
        data = kb._load_yaml("stride-library.yaml")
        stride_per_element = data.get("stride_per_element", {})
        element = args.element.lower()

        if element in stride_per_element:
            categories = stride_per_element[element]
            result = {
                "element_type": element.upper(),
                "applicable_stride": categories,
                "count": len(categories),
            }
        else:
            result = {"error": f"Invalid element type: {args.element}"}

    elif args.stats:
        result = kb.get_statistics()

    elif args.nvd_cve:
        # Real-time CVE lookup from NVD API
        nvd_client = NVDClient(api_key=nvd_api_key)
        cve_data = nvd_client.get_cve(args.nvd_cve)
        if cve_data:
            # Enrich with KEV status
            kev_status = kb.check_kev(args.nvd_cve)
            is_in_kev = kev_status.get("is_known_exploited", False)
            cve_data["in_kev"] = is_in_kev
            if is_in_kev:
                cve_data["kev_details"] = {
                    "vendor": kev_status.get("vendor"),
                    "product": kev_status.get("product"),
                    "vulnerability_name": kev_status.get("vulnerability_name"),
                    "date_added": kev_status.get("date_added"),
                    "due_date": kev_status.get("due_date"),
                    "known_ransomware": kev_status.get("known_ransomware"),
                }
            result = cve_data
        else:
            result = {"error": f"CVE not found or NVD API error: {args.nvd_cve}"}

    elif args.nvd_cwe:
        # Search CVEs by CWE from NVD API
        nvd_client = NVDClient(api_key=nvd_api_key)
        cwe_id = kb._normalize_cwe_id(args.nvd_cwe)
        limit = min(args.nvd_limit, 100)

        print(f"Querying NVD API for {cwe_id} (limit: {limit})...", file=sys.stderr)
        print(f"Note: NVD API rate limit ~6s without API key", file=sys.stderr)

        cves = nvd_client.search_by_cwe(cwe_id, limit=limit)

        if cves:
            result = {
                "cwe_id": cwe_id,
                "cve_count": len(cves),
                "cves": cves,
                "source": "nvd_api",
            }
        else:
            result = {"error": f"No CVEs found for {cwe_id} or NVD API error"}

    elif args.semantic_search:
        # Semantic search for CWE/CAPEC
        searcher = SemanticSearcher(kb.sqlite_path)

        entry_type = None if args.search_type == "all" else args.search_type.upper()

        print(f"Building search index and querying...", file=sys.stderr)
        results = searcher.search(
            query=args.semantic_search,
            top_k=args.search_limit,
            entry_type=entry_type
        )

        if results:
            result = {
                "query": args.semantic_search,
                "filter_type": args.search_type,
                "result_count": len(results),
                "results": results,
                "search_method": searcher.get_index_stats().get("search_method", "unknown"),
            }
        else:
            result = {"error": f"No results found for: {args.semantic_search}"}

    elif args.search_stats:
        # Show semantic search index statistics
        searcher = SemanticSearcher(kb.sqlite_path)
        result = searcher.get_index_stats()

    # Verification Set handlers (v2.0 new)
    elif args.stride_tests:
        result = kb.get_stride_tests(args.stride_tests)

    elif args.cwe_tests:
        result = kb.get_cwe_tests(args.cwe_tests)

    elif args.asvs_level:
        result = kb.get_asvs_by_level(args.asvs_level)

    elif args.asvs_chapter:
        result = kb.get_asvs_by_chapter(args.asvs_chapter)

    elif args.wstg_category:
        result = kb.get_wstg_by_category(args.wstg_category)

    elif args.mastg_platform:
        result = kb.get_mastg_by_platform(args.mastg_platform)

    elif args.verification_stats:
        result = kb.get_verification_stats()

    else:
        parser.print_help()
        sys.exit(1)

    # Output
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
