"""Local, privacy-preserving scan history storage.

The history database keeps *sanitized metadata only*:

- scan id
- UTC timestamp
- module key
- label and normalized risk level
- risk score (0-100, when the module produces one)
- completion status
- sanitized numeric counts
- engine/schema version marker

It never stores raw URLs, hostnames, messages, HTML, uploaded image bytes,
filenames, OCR text, login-form content, credentials, passwords, OTPs,
tokens or detector reasons/recommendations. Values are whitelisted by
construction instead of being copied from detector output, so adding a new
field to a detector cannot leak into the database by accident.

A failure to read or write history must never break a detection API. Route
code uses :func:`safe_record` for writes and wraps reads where a fallback
UI state is acceptable.

The default database lives at ``instance/drishti_ai.db``. An existing
``instance/phishguard.db`` file is moved to the new name on first use. Tests
and tools can point the module at another file with
:func:`set_database_path` or the ``DRISHTI_DB`` environment variable. The
legacy ``PHISHGUARD_DB`` variable is still accepted.
"""

import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "instance" / "drishti_ai.db"
LEGACY_DB_PATH = PROJECT_ROOT / "instance" / "phishguard.db"

ENGINE_VERSION = "drishti-ai-4.0"
SCHEMA_VERSION = 1

MODULE_KEYS = ("url", "text", "ocr", "brand", "login_form", "combined")

MODULE_LABELS = {
    "url": "URL Analysis",
    "text": "Text Analysis",
    "ocr": "OCR Analysis",
    "brand": "Image & Brand Analysis",
    "login_form": "Login Form Analysis",
    "combined": "Combined Risk Assessment",
}

RISK_LEVELS = {"safe", "suspicious", "high_risk", "inconclusive"}

RISK_LABELS = {
    "safe": "Safe",
    "suspicious": "Suspicious",
    "high_risk": "High Risk",
    "inconclusive": "Inconclusive",
}

BADGE_CLASSES = {
    "safe": "badge-safe",
    "suspicious": "badge-suspicious",
    "high_risk": "badge-high-risk",
    "inconclusive": "badge-inconclusive",
}

LABEL_BADGES = {
    "Phishing": "badge-high-risk",
    "High Risk": "badge-high-risk",
    "Suspicious": "badge-suspicious",
    "Legitimate": "badge-safe",
    "Safe": "badge-safe",
    "Possible Match": "badge-info",
    "Low Similarity": "badge-inconclusive",
    "Unknown": "badge-inconclusive",
}

STATUS_LABELS = {
    "completed": "Completed",
    "inconclusive": "Inconclusive",
    "failed": "Failed",
}

# Detector labels we are willing to persist. Anything else becomes "Unknown".
ALLOWED_LABELS = {
    "Phishing",
    "Legitimate",
    "Safe",
    "Suspicious",
    "High Risk",
    "Possible Match",
    "Low Similarity",
    "Unknown",
}

# Numeric counters we are willing to persist.
COUNT_KEYS = {
    "prediction",
    "indicators",
    "characters",
    "forms",
    "password_fields",
    "email_fields",
    "username_fields",
    "pin_fields",
    "otp_fields",
    "references_checked",
    "matches",
    "modules_analyzed",
    "modules_missing",
    "modules_inconclusive",
}

MODULE_STATES = {"analyzed", "inconclusive", "not_provided"}

MAX_COUNT = 10_000_000
MAX_QUERY_LENGTH = 60

# Static, generic safety guidance shown in reports. These are not detector
# reasons and are never read from storage.
RECOMMENDATIONS = {
    "high_risk": (
        "Do not enter passwords, OTPs or personal information.",
        "Do not click links or download attachments from this source.",
        "Verify the sender or website through a channel you find yourself.",
        "Report the message or page to your IT/security team.",
    ),
    "suspicious": (
        "Verify the sender or website independently before acting.",
        "Avoid entering credentials until the request is confirmed.",
        "Check the address carefully and prefer typing it manually.",
    ),
    "safe": (
        "No strong phishing indicators were found, but stay cautious.",
        "Verify unexpected requests before sharing any information.",
    ),
    "inconclusive": (
        "Some modules produced no usable verdict; run more modules for a fuller picture.",
        "Treat unverified sources with caution even when no indicators were found.",
    ),
}

_db_path_override = None


class HistoryError(RuntimeError):
    """Raised when the local history database cannot be used."""


# ---------------------------------------------------------------------------
# Database location and schema
# ---------------------------------------------------------------------------


def set_database_path(path):
    """Point the store at a specific database file (``None`` restores default)."""
    global _db_path_override
    _db_path_override = Path(path) if path else None


def _running_under_test_runner():
    """Return True only for an actual unittest/pytest invocation.

    Checking ``sys.modules`` for ``unittest`` is unreliable because unrelated
    libraries may import it. The process arguments are a precise signal.
    """
    argv = getattr(sys, "orig_argv", None) or sys.argv
    text = " ".join(str(part) for part in argv).lower()
    return "unittest" in text or "pytest" in text


def get_database_path():
    """Return the SQLite file currently in use."""
    if _db_path_override is not None:
        return _db_path_override

    env_path = os.environ.get("DRISHTI_DB") or os.environ.get("PHISHGUARD_DB")
    if env_path:
        return Path(env_path)

    # Running under a test runner: never touch the real local history.
    if _running_under_test_runner():
        return Path(tempfile.gettempdir()) / "drishti-ai-unittest.db"

    # Preserve local history from the previous brand filename.
    if not DEFAULT_DB_PATH.exists() and LEGACY_DB_PATH.exists():
        try:
            LEGACY_DB_PATH.replace(DEFAULT_DB_PATH)
        except OSError:
            return LEGACY_DB_PATH

    return DEFAULT_DB_PATH


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    module TEXT NOT NULL,
    label TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score INTEGER,
    completion_status TEXT NOT NULL,
    counts_json TEXT NOT NULL DEFAULT '{}',
    version TEXT NOT NULL,
    schema_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_module ON scans(module);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
"""


def _connect(db_path=None):
    path = Path(db_path) if db_path else get_database_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), timeout=5)
    except (OSError, sqlite3.Error) as exc:
        raise HistoryError("The scan history database is unavailable.") from exc

    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA_SQL)
    except sqlite3.Error as exc:
        connection.close()
        raise HistoryError("The scan history database is unavailable.") from exc
    return connection


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _clean_label(value):
    if isinstance(value, str):
        text = value.strip()
        if text in ALLOWED_LABELS:
            return text
    return "Unknown"


def _clean_score(value):
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)):
        return None
    if value != value:  # NaN
        return None
    number = int(round(value))
    if number < 0 or number > 100:
        return None
    return number


def _clean_count(value):
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)) or value != value:
        return None
    number = int(value)
    if number < 0 or number > MAX_COUNT:
        return None
    return number


def _sanitize_counts(raw):
    """Whitelist numeric counters and a numeric-only module breakdown."""
    clean = {}
    if not isinstance(raw, dict):
        return clean

    for key in COUNT_KEYS:
        if key in raw:
            number = _clean_count(raw.get(key))
            if number is not None:
                clean[key] = number

    modules = raw.get("modules")
    if isinstance(modules, dict):
        clean_modules = {}
        for module_key in MODULE_KEYS:
            item = modules.get(module_key)
            if not isinstance(item, dict):
                continue
            entry = {"available": bool(item.get("available"))}
            score = _clean_score(item.get("score"))
            if score is not None:
                entry["score"] = score
            state = item.get("state")
            if state in MODULE_STATES:
                entry["state"] = state
            clean_modules[module_key] = entry
        if clean_modules:
            clean["modules"] = clean_modules

    return clean


def _risk_from_label(label):
    if label == "Phishing":
        return "high_risk"
    if label == "Legitimate":
        return "safe"
    if label == "Safe":
        return "safe"
    if label == "Suspicious":
        return "suspicious"
    if label == "High Risk":
        return "high_risk"
    return "inconclusive"


def _module_breakdown(modules):
    """Reduce an assess-risk module map to booleans, scores and states."""
    clean = {}
    if not isinstance(modules, dict):
        return clean
    for key in ("url", "text", "ocr", "brand", "login_form"):
        item = modules.get(key)
        if not isinstance(item, dict):
            continue
        available = bool(item.get("available"))
        if available:
            state = "analyzed"
        elif item.get("status") == "inconclusive":
            state = "inconclusive"
        else:
            state = "not_provided"
        entry = {"available": available, "state": state}
        score = _clean_score(item.get("risk_score"))
        if score is not None:
            entry["score"] = score
        clean[key] = entry
    return clean


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def build_record(module, result):
    """Build a sanitized record from a detector result.

    Only whitelisted metadata is copied. Raw input fields that detectors may
    echo back (for example the ``url`` field in ``detect()`` output) are
    intentionally ignored.
    """
    if module not in MODULE_KEYS:
        raise ValueError("Unknown analysis module.")

    result = result if isinstance(result, dict) else {}
    record = {
        "module": module,
        "label": "Unknown",
        "risk_level": "inconclusive",
        "score": None,
        "status": "inconclusive",
        "counts": {},
    }

    if module == "url":
        label = result.get("label")
        if label == "Phishing":
            record.update(label="Phishing", risk_level="high_risk", status="completed")
        elif label == "Legitimate":
            record.update(label="Legitimate", risk_level="safe", status="completed")
        prediction = _clean_count(result.get("prediction"))
        if prediction in (0, 1):
            record["counts"]["prediction"] = prediction

    elif module == "text":
        label = _clean_label(result.get("result"))
        score = _clean_score(result.get("score"))
        reasons = result.get("reasons")
        record["label"] = label
        record["score"] = score
        record["risk_level"] = _risk_from_label(label)
        record["status"] = "completed" if score is not None else "inconclusive"
        if isinstance(reasons, list):
            record["counts"]["indicators"] = len(reasons)

    elif module == "ocr":
        extracted = result.get("extracted_text")
        text_length = len(extracted) if isinstance(extracted, str) else 0
        label = _clean_label(result.get("result"))
        score = _clean_score(result.get("score"))
        reasons = result.get("reasons")
        record["label"] = label
        record["score"] = score
        record["counts"]["characters"] = text_length
        if isinstance(reasons, list):
            record["counts"]["indicators"] = len(reasons)
        if text_length == 0:
            record["risk_level"] = "inconclusive"
            record["status"] = "inconclusive"
        else:
            record["risk_level"] = _risk_from_label(label)
            record["status"] = "completed"

    elif module == "brand":
        label = _clean_label(result.get("result"))
        record["label"] = label
        record["score"] = _clean_score(result.get("score"))
        # Brand similarity is supporting evidence only, never a verdict.
        record["risk_level"] = "inconclusive"
        record["status"] = "inconclusive"
        references = _clean_count(result.get("references_checked"))
        if references is not None:
            record["counts"]["references_checked"] = references
        matches = result.get("matches")
        if isinstance(matches, list):
            record["counts"]["matches"] = len(matches)

    elif module == "login_form":
        label = _clean_label(result.get("risk_level"))
        score = _clean_score(result.get("score"))
        record["label"] = label
        record["score"] = score
        record["risk_level"] = _risk_from_label(label)
        record["status"] = "completed" if score is not None else "inconclusive"

        forms = _clean_count(result.get("forms_found"))
        if forms is not None:
            record["counts"]["forms"] = forms

        fields = result.get("fields")
        if isinstance(fields, dict):
            for key, count_key in (
                ("password", "password_fields"),
                ("email", "email_fields"),
                ("username", "username_fields"),
                ("pin", "pin_fields"),
                ("otp", "otp_fields"),
            ):
                number = _clean_count(fields.get(key))
                if number is not None:
                    record["counts"][count_key] = number

        reasons = result.get("reasons")
        if isinstance(reasons, list):
            record["counts"]["indicators"] = len(reasons)

    elif module == "combined":
        label = _clean_label(result.get("risk_level"))
        score = _clean_score(result.get("overall_score"))
        modules = _module_breakdown(result.get("modules"))
        record["label"] = label
        record["score"] = score
        record["risk_level"] = _risk_from_label(label)
        record["status"] = "completed" if score is not None else "inconclusive"

        if modules:
            record["counts"]["modules"] = modules
            record["counts"]["modules_analyzed"] = sum(
                1 for item in modules.values() if item.get("available")
            )
            record["counts"]["modules_missing"] = sum(
                1 for item in modules.values() if item.get("state") == "not_provided"
            )
            record["counts"]["modules_inconclusive"] = sum(
                1 for item in modules.values() if item.get("state") == "inconclusive"
            )

        missing = result.get("missing_modules")
        if isinstance(missing, list):
            record["counts"]["modules_missing"] = len(missing)
        inconclusive = result.get("inconclusive_modules")
        if isinstance(inconclusive, list):
            record["counts"]["modules_inconclusive"] = len(inconclusive)

    record["counts"] = _sanitize_counts(record["counts"])
    return record


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def record_analysis(module, result, db_path=None):
    """Persist one sanitized analysis record and return its scan id."""
    record = build_record(module, result)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    connection = _connect(db_path)
    try:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                created_at, module, label, risk_level, risk_score,
                completion_status, counts_json, version, schema_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                record["module"],
                record["label"],
                record["risk_level"],
                record["score"],
                record["status"],
                json.dumps(record["counts"], sort_keys=True),
                ENGINE_VERSION,
                SCHEMA_VERSION,
            ),
        )
        connection.commit()
        return cursor.lastrowid
    except sqlite3.Error as exc:
        connection.rollback()
        raise HistoryError("The scan could not be saved to history.") from exc
    finally:
        connection.close()


def safe_record(module, result, db_path=None):
    """Record a scan without ever raising into a detection API."""
    try:
        return record_analysis(module, result, db_path=db_path)
    except Exception:
        return None


def delete_scan(scan_id, db_path=None):
    """Delete one record. Returns True when a row was removed."""
    connection = _connect(db_path)
    try:
        cursor = connection.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        connection.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as exc:
        connection.rollback()
        raise HistoryError("The scan record could not be deleted.") from exc
    finally:
        connection.close()


def clear_scans(db_path=None):
    """Delete every record. Returns the number of removed rows."""
    connection = _connect(db_path)
    try:
        cursor = connection.execute("DELETE FROM scans")
        connection.commit()
        return cursor.rowcount
    except sqlite3.Error as exc:
        connection.rollback()
        raise HistoryError("The scan history could not be cleared.") from exc
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def _display_time(value):
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError):
        return value or ""
    return "%d %s %d, %02d:%02d UTC" % (
        moment.day,
        moment.strftime("%b"),
        moment.year,
        moment.hour,
        moment.minute,
    )


def _summary(module, label, status):
    if status == "inconclusive" and module != "brand":
        return "Result inconclusive"
    if module == "brand":
        return {
            "Possible Match": "Visual similarity found",
            "Low Similarity": "Low visual similarity",
        }.get(label, "Not enough reference data")
    return {
        "Phishing": "Phishing detected",
        "Legitimate": "No phishing detected",
        "Safe": "No strong indicators",
        "Suspicious": "Suspicious indicators",
        "High Risk": "High-risk indicators",
    }.get(label, "No usable verdict")


def _row_to_dict(row):
    try:
        counts = json.loads(row["counts_json"]) if row["counts_json"] else {}
    except (TypeError, ValueError):
        counts = {}
    if not isinstance(counts, dict):
        counts = {}

    risk_level = row["risk_level"] if row["risk_level"] in RISK_LEVELS else "inconclusive"
    status = row["completion_status"]
    if status not in STATUS_LABELS:
        status = "inconclusive"
    module = row["module"] if row["module"] in MODULE_KEYS else "combined"

    return {
        "scan_id": row["scan_id"],
        "created_at": _display_time(row["created_at"]),
        "created_at_iso": row["created_at"],
        "module": module,
        "analysis_type_label": MODULE_LABELS[module],
        "label": row["label"],
        "label_badge_class": LABEL_BADGES.get(row["label"], "badge-inconclusive"),
        "risk_level": RISK_LABELS[risk_level],
        "risk_level_key": risk_level,
        "badge_class": BADGE_CLASSES[risk_level],
        "risk_score": row["risk_score"],
        "completion_status": STATUS_LABELS[status],
        "completion_status_key": status,
        "summary": _summary(module, row["label"], status),
        "counts": counts,
        "version": row["version"],
        "schema_version": row["schema_version"],
        "report_url": "/reports/%d" % row["scan_id"],
    }


def _clean_query(query):
    if not isinstance(query, str):
        return ""
    text = query.strip()
    if len(text) > MAX_QUERY_LENGTH:
        text = text[:MAX_QUERY_LENGTH]
    return text


def _like_escape(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _build_filters(module=None, risk_level=None, query=None):
    clauses = []
    params = []

    if module in MODULE_KEYS:
        clauses.append("module = ?")
        params.append(module)

    if risk_level in RISK_LEVELS:
        clauses.append("risk_level = ?")
        params.append(risk_level)

    text = _clean_query(query)
    if text:
        needle = "%" + _like_escape(text.lower()) + "%"
        normalized = "%" + _like_escape(
            text.lower().replace(" ", "_").replace("-", "_")
        ) + "%"
        clauses.append(
            "("
            "lower(label) LIKE ? ESCAPE '\\' OR "
            "module LIKE ? ESCAPE '\\' OR "
            "risk_level LIKE ? ESCAPE '\\' OR "
            "completion_status LIKE ? ESCAPE '\\'"
            ")"
        )
        params.extend([needle, normalized, normalized, normalized])

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _empty_page(page=1, per_page=10):
    return {
        "items": [],
        "total": 0,
        "page": 1,
        "per_page": per_page,
        "pages": 0,
        "has_prev": False,
        "has_next": False,
    }


def list_scans(module=None, risk_level=None, query=None, page=1, per_page=10, db_path=None):
    """Return a filtered, paginated page of sanitized records."""
    try:
        page = max(1, int(page))
    except (TypeError, ValueError):
        page = 1
    try:
        per_page = max(1, min(50, int(per_page)))
    except (TypeError, ValueError):
        per_page = 10

    where, params = _build_filters(module, risk_level, query)
    connection = _connect(db_path)
    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM scans" + where, params
        ).fetchone()[0]

        pages = (total + per_page - 1) // per_page if total else 0
        if pages and page > pages:
            page = pages
        offset = (page - 1) * per_page

        rows = connection.execute(
            "SELECT * FROM scans"
            + where
            + " ORDER BY created_at DESC, scan_id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
    except sqlite3.Error as exc:
        raise HistoryError("The scan history could not be read.") from exc
    finally:
        connection.close()

    return {
        "items": [_row_to_dict(row) for row in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


def get_scan(scan_id, db_path=None):
    """Return one sanitized record or None."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        return None

    connection = _connect(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    except sqlite3.Error as exc:
        raise HistoryError("The scan record could not be read.") from exc
    finally:
        connection.close()

    return _row_to_dict(row) if row is not None else None


def get_recent_scans(limit=6, db_path=None):
    """Return the newest records for the overview page."""
    try:
        limit = max(1, min(20, int(limit)))
    except (TypeError, ValueError):
        limit = 6

    connection = _connect(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, scan_id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise HistoryError("The scan history could not be read.") from exc
    finally:
        connection.close()

    return [_row_to_dict(row) for row in rows]


def get_latest_combined(db_path=None):
    """Return the newest combined assessment record, or None."""
    connection = _connect(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM scans WHERE module = 'combined' "
            "ORDER BY created_at DESC, scan_id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.Error as exc:
        raise HistoryError("The scan history could not be read.") from exc
    finally:
        connection.close()

    return _row_to_dict(row) if row is not None else None


def get_statistics(db_path=None):
    """Return aggregate counts for the overview dashboard."""
    connection = _connect(db_path)
    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(risk_level = 'safe'), 0) AS safe,
                COALESCE(SUM(risk_level = 'suspicious'), 0) AS suspicious,
                COALESCE(SUM(risk_level = 'high_risk'), 0) AS high_risk,
                COALESCE(SUM(risk_level = 'inconclusive'), 0) AS inconclusive
            FROM scans
            """
        ).fetchone()
    except sqlite3.Error as exc:
        raise HistoryError("Scan statistics could not be read.") from exc
    finally:
        connection.close()

    return {
        "total": int(row["total"] or 0),
        "safe": int(row["safe"] or 0),
        "suspicious": int(row["suspicious"] or 0),
        "high_risk": int(row["high_risk"] or 0),
        "inconclusive": int(row["inconclusive"] or 0),
    }


def count_scans(db_path=None):
    connection = _connect(db_path)
    try:
        return int(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
    except sqlite3.Error as exc:
        raise HistoryError("Scan statistics could not be read.") from exc
    finally:
        connection.close()


def recommendations_for(risk_level):
    """Static safety guidance for a risk level (never stored reasons)."""
    return list(RECOMMENDATIONS.get(risk_level, RECOMMENDATIONS["inconclusive"]))


COUNT_LABELS = {
    "prediction": "Binary prediction value",
    "indicators": "Indicators matched",
    "characters": "Characters analyzed",
    "forms": "Forms found",
    "password_fields": "Password fields",
    "email_fields": "Email fields",
    "username_fields": "Username fields",
    "pin_fields": "PIN fields",
    "otp_fields": "OTP / verification-code fields",
    "references_checked": "Reference logos checked",
    "matches": "Reference matches",
    "modules_analyzed": "Modules analyzed",
    "modules_missing": "Modules not analyzed",
    "modules_inconclusive": "Inconclusive modules",
}


def display_counts(record):
    """Turn the stored numeric counts into ordered label/value pairs."""
    counts = record.get("counts") or {}
    rows = []
    for key, label in COUNT_LABELS.items():
        if key in counts:
            rows.append({"label": label, "value": counts[key]})
    return rows


def display_breakdown(record):
    """Turn a stored combined module breakdown into display rows."""
    counts = record.get("counts") or {}
    modules = counts.get("modules")
    if not isinstance(modules, dict):
        return []

    rows = []
    for key in ("url", "text", "ocr", "brand", "login_form"):
        item = modules.get(key)
        if not isinstance(item, dict):
            continue
        state = item.get("state", "not_provided")
        if state == "analyzed":
            status = "Analyzed"
        elif state == "inconclusive":
            status = "Inconclusive"
        else:
            status = "Not analyzed"
        rows.append(
            {
                "label": MODULE_LABELS[key],
                "module": key,
                "status": status,
                "score": item.get("score"),
            }
        )
    return rows
