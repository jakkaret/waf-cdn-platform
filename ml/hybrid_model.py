"""
Gen 3 hybrid WAF model: content token model stacked under LightGBM.

- Token model: decoded, lower-cased request text -> hashed token unigrams +
  bigrams (letter runs, digit runs, each punctuation char) -> TF-IDF ->
  logistic regression. Reads the payload itself, wherever it sits.
- LightGBM: the 36 structural features from ml/feature_engineering.py plus
  the token model's score as one extra column ("token_score"). During
  training that column holds out-of-fold scores (standard stacking), so the
  tree model never sees a score the token model produced on its own
  training rows.

Serving only needs `score_request(method, url, body)`; the object is
pickled with joblib by ml/train_gen3_full_real_benchmark.py.
"""

import json
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import SGDClassifier

TOKEN_PATTERN = r"[a-z]+|\d+|[^\sa-z\d]"
HASH_FEATURES = 2 ** 20
TEXT_CAP = 2048
TOKEN_SCORE_COLUMN = "token_score"


def request_text(method, uri, query, body):
    """Decoded, lower-cased request text (method + path + query + body, capped) for token models."""
    raw = f"{method} {uri}" + (f"?{query}" if query else "") + (f" {body}" if body else "")
    text = raw[: TEXT_CAP * 2]
    for _ in range(2):  # double-encoding is a common evasion
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text[:TEXT_CAP].lower()


UNIT_CAP = 512
MAX_UNITS = 64


def _decode(value):
    for _ in range(2):  # double-encoding is a common evasion
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def _json_leaves(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _json_leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _json_leaves(v, out)
    elif obj is not None:
        out.append(str(obj))


def request_units(method, uri, query, body):
    """Split a request into independently scored units: path segments, parameter
    names and values (query and form body), JSON leaves, or the raw body.

    Units carry no surrounding context, so a model scoring them cannot learn
    "attacks live at /?p=" or "/api/... is benign"; the request score is the
    max over units (multiple-instance learning).
    """
    units = [seg for seg in (_decode(s) for s in str(uri).split("/")) if seg]
    if query:
        # No max_num_fields: parse_qsl raises past it instead of truncating; units are capped below
        pairs = parse_qsl(query, keep_blank_values=True)
        units += [x for kv in pairs for x in kv if x] if pairs else [_decode(query)]
    body = str(body or "")
    if body:
        stripped = body.lstrip()
        if stripped[:1] in ("{", "["):
            leaves = []
            try:
                _json_leaves(json.loads(stripped), leaves)
                units += leaves
            except ValueError:
                units.append(body)
        elif "=" in body:
            pairs = parse_qsl(body, keep_blank_values=True)
            units += [x for kv in pairs for x in kv if x] if pairs else [body]
        else:
            units.append(body)
    units = [u[:UNIT_CAP].lower() for u in units if u and u.strip()][:MAX_UNITS]
    return units or [str(method).lower()]


def make_vectorizer():
    return HashingVectorizer(token_pattern=TOKEN_PATTERN, ngram_range=(1, 2), n_features=HASH_FEATURES,
                             alternate_sign=False, norm=None, lowercase=False, dtype=np.float32)


class TokenModel:
    """Hashed token n-grams -> TF-IDF (fit on training rows) -> weighted logistic regression."""

    def __init__(self, alpha=1e-6):
        self.alpha = alpha
        self.vectorizer = make_vectorizer()

    def fit(self, texts_or_matrix, y, sample_weight=None):
        H = self._matrix(texts_or_matrix)
        self.tfidf = TfidfTransformer(sublinear_tf=True).fit(H)
        self.clf = SGDClassifier(loss="log_loss", alpha=self.alpha, max_iter=30, tol=1e-4,
                                 random_state=42).fit(self.tfidf.transform(H), y, sample_weight=sample_weight)
        return self

    def predict_proba(self, texts_or_matrix):
        return self.clf.predict_proba(self.tfidf.transform(self._matrix(texts_or_matrix)))[:, 1]

    def _matrix(self, texts_or_matrix):
        if isinstance(texts_or_matrix, (list, tuple, pd.Series, np.ndarray)) and len(texts_or_matrix) and \
                isinstance(texts_or_matrix[0], str):
            return self.vectorizer.transform(list(texts_or_matrix))
        return texts_or_matrix


class UnitMatrix:
    """Hashed token matrix over all units of many requests, with per-request offsets."""

    def __init__(self, units_per_row):
        lengths = np.array([len(u) for u in units_per_row], dtype=np.int64)
        self.offsets = np.concatenate([[0], np.cumsum(lengths)])
        flat = [u for units in units_per_row for u in units]
        self.H = make_vectorizer().transform(flat).tocsr()

    def select(self, rows):
        """Unit row indices and the position (0..len(rows)-1) of their owning request."""
        rows = np.asarray(rows)
        starts, ends = self.offsets[rows], self.offsets[rows + 1]
        counts = ends - starts
        idx = np.concatenate([np.arange(s, e) for s, e in zip(starts, ends)]) if len(rows) else np.array([], int)
        owner = np.repeat(np.arange(len(rows)), counts)
        return idx, owner, counts


def max_by_owner(values, owner, n):
    out = np.zeros(n)
    np.maximum.at(out, owner, values)
    return out


class UnitTokenModel:
    """Per-unit token classifier trained by multiple-instance learning; request score = max over units.

    Benign requests: every unit is a negative. Attack requests: the payload
    unit is unknown, so round 0 treats all their units as weak positives and
    later rounds keep only each attack request's highest-scoring unit
    (MI-SVM "witness" selection). Each request carries its near-duplicate
    weight in total, split evenly over its units.
    """

    def __init__(self, alpha=1e-6, mil_rounds=2):
        self.alpha = alpha
        self.mil_rounds = mil_rounds

    def _fit_units(self, H, y, w):
        self.tfidf = TfidfTransformer(sublinear_tf=True).fit(H)
        self.clf = SGDClassifier(loss="log_loss", alpha=self.alpha, max_iter=30, tol=1e-4,
                                 random_state=42).fit(self.tfidf.transform(H), y, sample_weight=w)

    def unit_proba(self, H):
        return self.clf.predict_proba(self.tfidf.transform(H))[:, 1]

    def fit_matrix(self, um, rows, y_rows, w_rows):
        idx, owner, counts = um.select(rows)
        H = um.H[idx]
        y_rows, w_rows = np.asarray(y_rows), np.asarray(w_rows, dtype=float)
        unit_y = y_rows[owner]
        unit_w = (w_rows / np.maximum(counts, 1))[owner]
        self._fit_units(H, unit_y, unit_w)
        for _ in range(self.mil_rounds):
            p = self.unit_proba(H)
            keep = unit_y == 0
            att = np.flatnonzero(unit_y == 1)
            if len(att):
                # witness = highest-scoring unit of each attack request
                order = np.lexsort((-p[att], owner[att]))
                first = np.ones(len(order), bool)
                first[1:] = owner[att][order][1:] != owner[att][order][:-1]
                witness = att[order[first]]
                keep[witness] = True
            w_round = np.where(unit_y == 1, w_rows[owner], unit_w)
            self._fit_units(H[keep], unit_y[keep], w_round[keep])
        return self

    def predict_matrix(self, um, rows):
        idx, owner, _ = um.select(rows)
        return max_by_owner(self.unit_proba(um.H[idx]), owner, len(rows))

    def predict_units(self, units_per_row):
        um = UnitMatrix(units_per_row)
        return self.predict_matrix(um, np.arange(len(units_per_row)))


class Gen3UnitModel:
    """Serving wrapper: per-unit MIL token model, request score = max over units."""

    def __init__(self, unit_model, threshold):
        self.unit_model = unit_model
        self.threshold = float(threshold)

    def score_request(self, method="GET", url="/", body=""):
        parts = urlsplit(url)
        units = request_units(method, parts.path or "/", parts.query, body)
        return float(self.unit_model.predict_units([units])[0])


class Gen3HybridModel:
    """Token model + LightGBM(36 structural features + token_score)."""

    def __init__(self, token_model, lgbm, feature_columns, threshold):
        self.token_model = token_model
        self.lgbm = lgbm
        self.feature_columns = list(feature_columns)
        self.threshold = float(threshold)

    def predict_proba_frame(self, X_features, texts):
        """Batch scoring: X_features has the structural columns, texts the request_text() strings."""
        X = pd.DataFrame(X_features, columns=self.feature_columns[:-1]).copy()
        X[TOKEN_SCORE_COLUMN] = self.token_model.predict_proba(texts)
        return self.lgbm.predict_proba(X[self.feature_columns])[:, 1]

    def score_request(self, method="GET", url="/", body=""):
        """One request -> attack probability (same path the serving API would use)."""
        from ml.feature_engineering import extract_features_from_request
        feats = extract_features_from_request(url=url, method=method, body=body)
        parts = urlsplit(url)
        text = request_text(method, parts.path or "/", parts.query, body)
        X = pd.DataFrame([feats])[self.feature_columns[:-1]]
        return float(self.predict_proba_frame(X, [text])[0])
