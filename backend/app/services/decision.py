from urllib.parse import urlsplit
from ipaddress import ip_address
import tldextract

from app.schemas.scan import ModelResult, VirusTotalResult

_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def can_share(url: str) -> bool:
    """Conservative demo policy: only public apex/www and a small set of public paths."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        ip_address(host)
        return False
    except ValueError:
        pass
    domain = _domain(host)
    return bool(domain.domain and domain.suffix and domain.subdomain.lower() in {"", "www"}
                and parts.username is None and parts.password is None
                and parts.port in {None, 80, 443} and not parts.query and not parts.fragment
                and parts.path in {"", "/", "/login", "/login/"})


def final_decision(model: ModelResult, vt: VirusTotalResult) -> tuple[str, bool]:
    complete = vt.status == "completed" and vt.stats is not None
    if model.ai_risk_level == "danger" or (complete and vt.stats.malicious > 0):
        return "danger", complete
    if model.ai_risk_level == "caution" or (complete and vt.stats.suspicious > 0):
        return "caution", complete
    if complete and vt.stats.harmless > 0 and not model.truncated:
        return "low", True
    return "unknown", False
