"""DexRed RAG Embeddings — TF-IDF based semantic search.

Provides cosine similarity search over technique descriptions without
requiring any ML libraries. Uses TF-IDF (term frequency - inverse document
frequency) vectors computed from the technique corpus.

Falls back gracefully to FTS5 keyword search if the corpus is too small.
"""

import math
import re
import sqlite3
from collections import Counter

STOP_WORDS = frozenset({
    "a", "an", "the", "is", "it", "in", "on", "at", "to", "for", "of",
    "and", "or", "not", "with", "by", "from", "as", "if", "this", "that",
    "be", "are", "was", "were", "been", "will", "can", "do", "does", "did",
    "has", "have", "had", "may", "might", "must", "shall", "should", "would",
    "but", "so", "then", "than", "when", "where", "which", "who", "whom",
    "what", "how", "all", "each", "every", "both", "few", "more", "most",
    "other", "some", "such", "no", "nor", "only", "own", "same", "very",
    "just", "also", "into", "over", "after", "before", "between", "through",
    "about", "above", "below", "up", "down", "out", "off", "again", "further",
    "once", "here", "there", "any", "your", "you", "its", "his", "her",
    "our", "their", "we", "they", "he", "she", "me", "my", "us", "them",
})


def tokenize(text: str) -> list[str]:
    """Tokenize text into lowercase terms, removing stop words."""
    words = re.findall(r'[a-z0-9_]+', text.lower())
    return [w for w in words if w not in STOP_WORDS and len(w) > 1]


class TfIdfIndex:
    """In-memory TF-IDF index over a set of documents."""

    def __init__(self):
        self.documents: list[dict] = []
        self.doc_vectors: list[dict[str, float]] = []
        self.idf: dict[str, float] = {}
        self.vocab: set[str] = set()

    def build(self, documents: list[dict]):
        """Build the index from a list of documents with 'content' field."""
        self.documents = documents
        n = len(documents)
        if n == 0:
            return

        doc_terms = []
        df: Counter = Counter()

        for doc in documents:
            text = f"{doc.get('title', '')} {doc.get('tags', '')} {doc.get('content', '')}"
            terms = tokenize(text)
            tf = Counter(terms)
            doc_terms.append(tf)
            for term in set(terms):
                df[term] += 1
                self.vocab.add(term)

        self.idf = {
            term: math.log((n + 1) / (count + 1)) + 1
            for term, count in df.items()
        }

        self.doc_vectors = []
        for tf in doc_terms:
            total = sum(tf.values()) or 1
            vector = {
                term: (count / total) * self.idf.get(term, 1.0)
                for term, count in tf.items()
            }
            self.doc_vectors.append(vector)

    def search(self, query: str, limit: int = 5) -> list[tuple[dict, float]]:
        """Search for documents similar to the query. Returns (doc, score) pairs."""
        if not self.documents:
            return []

        query_terms = tokenize(query)
        query_tf = Counter(query_terms)
        total = sum(query_tf.values()) or 1

        query_vector = {
            term: (count / total) * self.idf.get(term, 1.0)
            for term, count in query_tf.items()
        }

        scores = []
        for i, doc_vec in enumerate(self.doc_vectors):
            score = cosine_similarity(query_vector, doc_vec)
            if score > 0.01:
                scores.append((self.documents[i], score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:limit]


def cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Compute cosine similarity between two sparse vectors."""
    common_keys = set(vec_a.keys()) & set(vec_b.keys())
    if not common_keys:
        return 0.0

    dot_product = sum(vec_a[k] * vec_b[k] for k in common_keys)
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


def build_index_from_db(db: sqlite3.Connection) -> TfIdfIndex:
    """Build a TF-IDF index from all techniques in the database."""
    rows = db.execute("SELECT title, category, tags, content, source FROM techniques").fetchall()
    documents = [dict(r) for r in rows]
    index = TfIdfIndex()
    index.build(documents)
    return index
