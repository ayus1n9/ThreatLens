"""
Local Cache Manager.

Implements SQLite-backed persistent caching for threat intelligence lookups
to minimize redundant API calls, preserve quotas, and track data freshness.
Only successful and definitive lookups are cached (transient errors are never cached).
Includes corruption recovery and graceful degradation.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from soc_intel.providers.base import ProviderRawResult, ProviderStatus
from soc_intel.validators import IndicatorType

logger = logging.getLogger("soc_intel.cache")


class ThreatIntelCache:
    """SQLite-backed cache for raw provider findings."""

    def __init__(self, db_path: str = ".soc_intel_cache.db", ttl_hours: int = 24, enabled: bool = True):
        self.db_path = Path(db_path)
        self.ttl_hours = ttl_hours
        self.enabled = enabled
        if self.enabled:
            self._init_db()

    def _init_db(self) -> None:
        """Create cache tables and indexes if not already initialized."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intel_cache (
                        cache_key TEXT PRIMARY KEY,
                        provider_name TEXT NOT NULL,
                        indicator_value TEXT NOT NULL,
                        indicator_type TEXT NOT NULL,
                        status TEXT NOT NULL,
                        http_status_code INTEGER,
                        detections INTEGER DEFAULT 0,
                        total_evaluators INTEGER DEFAULT 0,
                        reputation_score REAL,
                        tags TEXT,
                        last_analysis_date TEXT,
                        cached_at TEXT NOT NULL,
                        raw_data TEXT
                    )
                    """
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_key ON intel_cache (cache_key)")
                conn.commit()
        except (sqlite3.Error, OSError) as err:
            logger.warning("Failed to initialize cache DB at '%s': %s. Disabling cache.", self.db_path, err)
            self.enabled = False

    @staticmethod
    def _make_key(provider_name: str, indicator_type: IndicatorType, indicator_value: str) -> str:
        """Generate unique cache lookup key."""
        return f"{provider_name.lower()}:{indicator_type.value}:{indicator_value.lower()}"

    def get(self, provider_name: str, indicator_type: IndicatorType, indicator_value: str) -> Optional[ProviderRawResult]:
        """
        Retrieve valid, unexpired cached provider result.
        Returns None if disabled, not found, expired, or corrupted.
        """
        if not self.enabled:
            return None

        key = self._make_key(provider_name, indicator_type, indicator_value)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT provider_name, indicator_value, indicator_type, status,
                           http_status_code, detections, total_evaluators,
                           reputation_score, tags, last_analysis_date, cached_at, raw_data
                    FROM intel_cache
                    WHERE cache_key = ?
                    """,
                    (key,),
                )
                row = cursor.fetchone()
        except sqlite3.Error as err:
            logger.warning("SQLite error reading cache key '%s': %s", key, err)
            return None

        if not row:
            return None

        (
            prov, ind_val, ind_type_str, status_str,
            http_code, detections, total_eval,
            rep_score, tags_json, last_date, cached_at_str, raw_data_json
        ) = row

        # Check TTL expiration
        try:
            cached_at = datetime.fromisoformat(cached_at_str)
            now = datetime.now(timezone.utc)
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)

            if now - cached_at > timedelta(hours=self.ttl_hours):
                return None
        except (ValueError, TypeError):
            return None

        # Reconstruct ProviderRawResult with safe deserialization
        try:
            tags = json.loads(tags_json) if tags_json else []
            raw_data = json.loads(raw_data_json) if raw_data_json else None
        except (json.JSONDecodeError, TypeError) as decode_err:
            logger.warning("Corrupted JSON in cache for '%s': %s. Treating as cache miss.", key, decode_err)
            return None

        return ProviderRawResult(
            provider_name=prov,
            indicator_value=ind_val,
            indicator_type=IndicatorType(ind_type_str),
            status=ProviderStatus(status_str),
            query_timestamp=cached_at_str,
            http_status_code=http_code,
            raw_data=raw_data,
            detections=detections or 0,
            total_evaluators=total_eval or 0,
            reputation_score=rep_score,
            tags=tags,
            last_analysis_date=last_date,
        )

    def set(self, result: ProviderRawResult) -> None:
        """
        Store a successful or not-found provider result in the cache.
        Does NOT cache network errors, timeouts, or auth failures.
        """
        if not self.enabled:
            return

        # Cache only definitive responses
        if result.status not in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND):
            return

        key = self._make_key(result.provider_name, result.indicator_type, result.indicator_value)
        cached_at = datetime.now(timezone.utc).isoformat()
        try:
            tags_json = json.dumps(result.tags)
            raw_data_json = json.dumps(result.raw_data) if result.raw_data else None

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO intel_cache (
                        cache_key, provider_name, indicator_value, indicator_type,
                        status, http_status_code, detections, total_evaluators,
                        reputation_score, tags, last_analysis_date, cached_at, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        result.provider_name,
                        result.indicator_value,
                        result.indicator_type.value,
                        result.status.value,
                        result.http_status_code,
                        result.detections,
                        result.total_evaluators,
                        result.reputation_score,
                        tags_json,
                        result.last_analysis_date,
                        cached_at,
                        raw_data_json,
                    ),
                )
                conn.commit()
        except (sqlite3.Error, TypeError, OSError) as err:
            logger.warning("Failed to write to cache for key '%s': %s", key, err)

    def clear(self) -> None:
        """Purge all cached entries."""
        if not self.enabled:
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM intel_cache")
                conn.commit()
        except sqlite3.Error as err:
            logger.warning("Failed to clear cache: %s", err)
