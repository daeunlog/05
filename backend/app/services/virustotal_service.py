import base64
from typing import Literal, TypedDict

import httpx

from app.core.config import settings


ReportStatus = Literal[
    "completed",
    "not_found",
    "rate_limited",
    "timeout",
    "error",
    "disabled",
]
ErrorCode = Literal[
    "missing_api_key",
    "not_found",
    "rate_limited",
    "request_timeout",
    "authentication_error",
    "permission_error",
    "http_error",
    "network_error",
    "invalid_response",
]


class AnalysisStats(TypedDict):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int


class URLReport(TypedDict):
    status: ReportStatus
    stats: AnalysisStats | None
    last_analysis_date: int | None
    error_code: ErrorCode | None


def _result(status: ReportStatus, error_code: ErrorCode | None = None) -> URLReport:
    return {
        "status": status,
        "stats": None,
        "last_analysis_date": None,
        "error_code": error_code,
    }


async def get_url_report(url: str) -> URLReport:
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key.strip():
        return _result("disabled", "missing_api_key")

    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(endpoint, headers={"x-apikey": api_key})
    except httpx.TimeoutException:
        return _result("timeout", "request_timeout")
    except httpx.RequestError:
        return _result("error", "network_error")

    if response.status_code == 404:
        return _result("not_found", "not_found")
    if response.status_code == 429:
        return _result("rate_limited", "rate_limited")
    if response.status_code == 401:
        return _result("error", "authentication_error")
    if response.status_code == 403:
        return _result("error", "permission_error")
    if response.status_code != 200:
        return _result("error", "http_error")

    try:
        payload = response.json()
        data = payload["data"]
        attributes = data["attributes"]
        raw_stats = attributes["last_analysis_stats"]

        if not isinstance(data, dict) or not isinstance(attributes, dict):
            raise TypeError
        if not isinstance(raw_stats, dict):
            raise TypeError

        stats: AnalysisStats = {
            "malicious": raw_stats["malicious"],
            "suspicious": raw_stats["suspicious"],
            "harmless": raw_stats["harmless"],
            "undetected": raw_stats["undetected"],
            "timeout": raw_stats["timeout"],
        }
        if any(isinstance(value, bool) or not isinstance(value, int) for value in stats.values()):
            raise TypeError

        last_analysis_date = attributes.get("last_analysis_date")
        if last_analysis_date is not None and (
            isinstance(last_analysis_date, bool) or not isinstance(last_analysis_date, int)
        ):
            raise TypeError
    except (KeyError, TypeError, ValueError):
        return _result("error", "invalid_response")

    return {
        "status": "completed",
        "stats": stats,
        "last_analysis_date": last_analysis_date,
        "error_code": None,
    }
