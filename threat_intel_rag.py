"""
RAG-based threat intelligence enrichment for log-analyzer.

Parses a MITRE ATT&CK STIX bundle, embeds TTP descriptions using a local
embedding model (no API cost), stores vectors in pgvector, and retrieves
semantically similar TTPs to augment AI-generated incident summaries.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import stix2

logger = logging.getLogger(__name__)

_EMBEDDING_MODEL = None  # lazy singleton — model download only happens once


def _model():
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        from fastembed import TextEmbedding
        _EMBEDDING_MODEL = TextEmbedding("BAAI/bge-small-en-v1.5")
    return _EMBEDDING_MODEL


def load_stix_ttps(path: str | Path) -> list[dict]:
    """Parse an ATT&CK STIX bundle and return a list of TTP records.

    Each record has: technique_id, name, tactic, description.
    Only attack-pattern objects with a mitre-attack external reference are included.
    """
    bundle = stix2.parse(Path(path).read_text(), allow_custom=True)
    ttps = []
    for obj in bundle.objects:
        if obj.type != "attack-pattern":
            continue
        ext_ref = next(
            (r for r in getattr(obj, "external_references", [])
             if r.get("source_name") == "mitre-attack"
             and r.get("external_id", "").startswith("T")),
            None,
        )
        if not ext_ref:
            continue
        tactic = next(
            (p["phase_name"].replace("-", " ").title()
             for p in getattr(obj, "kill_chain_phases", [])
             if p.get("kill_chain_name") == "mitre-attack"),
            "Unknown",
        )
        ttps.append({
            "technique_id": ext_ref["external_id"],
            "name": obj.name,
            "tactic": tactic,
            "description": getattr(obj, "description", "") or "",
        })
    return ttps


def embed_and_store(conn, ttps: list[dict]) -> int:
    """Embed TTP descriptions and upsert into the pgvector table.

    Skips TTPs that are already present in the table (upsert keeps data fresh).
    Returns the number of records upserted.
    """
    if not ttps:
        return 0
    texts = [f"{t['name']}: {t['description'][:500]}" for t in ttps]
    embeddings = list(_model().embed(texts))
    with conn.cursor() as cur:
        for ttp, vec in zip(ttps, embeddings):
            vec_str = "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
            cur.execute(
                """
                INSERT INTO threat_ttp_embeddings
                    (technique_id, name, tactic, description, embedding)
                VALUES (%s, %s, %s, %s, %s::vector)
                ON CONFLICT (technique_id) DO UPDATE
                    SET name        = EXCLUDED.name,
                        tactic      = EXCLUDED.tactic,
                        description = EXCLUDED.description,
                        embedding   = EXCLUDED.embedding
                """,
                (ttp["technique_id"], ttp["name"], ttp["tactic"],
                 ttp["description"], vec_str),
            )
        conn.commit()
    return len(ttps)


def retrieve_context(conn, incident_texts: list[str], top_k: int = 3) -> list[dict]:
    """Return the top-k TTPs most semantically similar to the given incident texts.

    Embeds all incident texts and averages them into a single query vector,
    then uses pgvector cosine distance (<=> operator) to rank stored TTPs.
    Returns an empty list on any database or embedding error.
    """
    if not incident_texts:
        return []
    try:
        vecs = list(_model().embed(incident_texts))
        query_vec = np.mean(vecs, axis=0)
        vec_str = "[" + ",".join(f"{x:.6f}" for x in query_vec) + "]"
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT technique_id, name, tactic, description,
                       1 - (embedding <=> %s::vector) AS similarity
                FROM threat_ttp_embeddings
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (vec_str, vec_str, top_k),
            )
            return [
                {
                    "technique_id": r[0],
                    "name": r[1],
                    "tactic": r[2],
                    "description": r[3][:200],
                    "similarity": round(float(r[4]), 3),
                }
                for r in cur.fetchall()
            ]
    except Exception as exc:
        logger.warning("RAG retrieval failed: %s", exc)
        return []


def format_context(ttps: list[dict]) -> str:
    """Format retrieved TTPs as a concise string for LLM prompt injection."""
    if not ttps:
        return ""
    lines = ["Relevant ATT&CK techniques:"]
    lines.extend(
        f"  {t['technique_id']} ({t['tactic']}): {t['name']}"
        for t in ttps
    )
    return "\n".join(lines)
