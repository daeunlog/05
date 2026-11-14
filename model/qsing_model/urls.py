"""URL 파싱 유틸리티.

학습·평가·서버 추론이 모두 이 모듈을 쓰므로 전처리 기준이 하나로 유지된다(제안서 2.2절).
URL은 문자열로만 다루며 어떤 네트워크 접속도 하지 않는다.
"""

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

SUPPORTED_SCHEMES = ("http", "https")
MAX_URL_CHARS = 2048

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", re.DOTALL)
_PORT_RE = re.compile(r"^\d+(?:[/?#]|$)")
_HTTP_PREFIX_RE = re.compile(r"^https?://", re.IGNORECASE)
_WWW_PREFIX_RE = re.compile(r"^www\.", re.IGNORECASE)

# 유명 단축 URL 서비스 (최종 목적지는 확인하지 않는다 — 제안서 4.3절)
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bit.do", "lnkd.in",
    "me2.do", "vo.la", "han.gl", "url.kr", "s.id", "v.gd", "t.ly", "shorturl.asia",
})

# tldextract가 없을 때 쓰는 2단계 공용 접미사 (대표적인 것만)
_FALLBACK_SECOND_LEVEL = frozenset({
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "ms.kr", "hs.kr", "es.kr", "sc.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk", "com.sg", "com.my",
    "co.in", "net.in", "org.in", "gov.in", "co.id", "co.za", "co.nz", "com.mx", "com.ar",
    "com.tr", "com.vn", "com.ph", "com.pk", "com.ng", "com.eg", "com.sa", "com.ua", "co.il",
})


@lru_cache(maxsize=1)
def _tld_extractor():
    """오프라인(내장 Public Suffix List 스냅샷) tldextract. 없으면 None."""
    try:
        import tldextract
    except ImportError:
        return None
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def using_tldextract():
    return _tld_extractor() is not None


def detect_scheme(url):
    """URL의 scheme을 판별한다.

    반환: (scheme 또는 None, 'hierarchical'|'opaque'|'none')
    - 'http://a.com' -> ('http', 'hierarchical')
    - 'javascript:alert(1)' -> ('javascript', 'opaque')
    - 'a.com:8080/x', 'a.com/x' -> (None, 'none')
    """
    m = _SCHEME_RE.match(url)
    if not m:
        return None, "none"
    scheme, rest = m.group(1).lower(), m.group(2)
    if rest.startswith("//"):
        return scheme, "hierarchical"
    # 점이 들어간 호스트('a.com:8080')나 'localhost:포트'는 scheme이 아니다.
    # 'tel:0101234'처럼 점 없는 단어 뒤 숫자는 scheme으로 본다.
    if "." in scheme or (scheme == "localhost" and _PORT_RE.match(rest)):
        return None, "none"
    return scheme, "opaque"


def split_url(url):
    """URL을 urlsplit 결과로 나눈다. scheme이 없으면 http://를 임시로 붙인다(저장 URL은 바꾸지 않음)."""
    scheme, kind = detect_scheme(url)
    target = url if kind == "hierarchical" else "http://" + url
    return urlsplit(target)


def parse_host(url):
    """호스트를 소문자로 돌려준다. 추출할 수 없으면 None. 포트와 사용자정보는 제외된다."""
    if not isinstance(url, str):
        return None
    s = url.strip()
    if not s:
        return None
    try:
        host = split_url(s).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.strip(".")
    if not host:
        return None
    if is_ip(host):
        return host
    if "." not in host and host != "localhost":
        return None
    if not re.fullmatch(r"[a-z0-9\-._~%!$&'()*+,;=¡-￿]+", host):
        return None
    return host


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host):
    """등록 도메인(그룹 키). IP면 IP 자체. 'login.secure.example.co.kr' -> 'example.co.kr'."""
    if host is None:
        return None
    if is_ip(host):
        return host
    ext = _tld_extractor()
    if ext is not None:
        r = ext(host)
        if r.domain and r.suffix:
            return f"{r.domain}.{r.suffix}"
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _FALLBACK_SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def check_url(url):
    """추론 전 입력 검사. 반환: (status, host)

    status: 'ok' | 'invalid_url' | 'unsupported_scheme'
    """
    if not isinstance(url, str) or not url.strip():
        return "invalid_url", None
    s = url.strip()
    scheme, kind = detect_scheme(s)
    if kind == "opaque" or (kind == "hierarchical" and scheme not in SUPPORTED_SCHEMES):
        return "unsupported_scheme", None
    host = parse_host(s)
    if host is None:
        return "invalid_url", None
    return "ok", host


_HOME_SLASH_RE = re.compile(r"^([^/?#]+)/$")


def normalize(url, mode):
    """모델 입력 정규화.

    - raw   : 공백 제거만
    - strip : 앞쪽 http(s)://와 www. 제거
    - strip2: strip + 경로가 '/' 하나뿐인 홈페이지 형태의 끝 '/' 제거 ('a.com/' → 'a.com')  [개정 5]
    """
    s = url.strip()
    if mode == "raw":
        return s
    if mode in ("strip", "strip2"):
        s = _HTTP_PREFIX_RE.sub("", s)
        s = _WWW_PREFIX_RE.sub("", s)
        if mode == "strip2":
            s = _HOME_SLASH_RE.sub(r"\1", s)
        return s
    raise ValueError(f"알 수 없는 정규화 방식: {mode}")


SCHEME_VARIANTS = ("noscheme", "https")


def scheme_variant(url, kind):
    """scheme 편향 점검용 변형.

    'noscheme': 앞쪽 http(s)://를 뗀다 / 'https': scheme이 없으면 https://를 붙인다(QR URL과 비슷한 형태).
    """
    s = url.strip()
    if kind == "noscheme":
        return _HTTP_PREFIX_RE.sub("", s)
    if kind == "https":
        return s if detect_scheme(s)[1] == "hierarchical" else "https://" + s
    raise ValueError(f"알 수 없는 변형: {kind}")


def loose_key(url):
    """라벨 충돌 검사용 키: scheme·www. 제거, 호스트 부분만 소문자. 경로·쿼리는 그대로."""
    s = normalize(url, "strip")
    m = re.search(r"[/?#]", s)
    if m:
        return s[: m.start()].lower() + s[m.start():]
    return s.lower()


def scheme_kind(url):
    """scheme 점검용 분류: 'https' | 'http' | 'none' | 'other'."""
    scheme, kind = detect_scheme(url.strip())
    if kind == "none":
        return "none"
    return scheme if scheme in SUPPORTED_SCHEMES else "other"


def signals(url, host=None):
    """URL 규칙 점검 결과(보조 정보, 제안서 3.3절). AI 판단 이유가 아니다."""
    s = url.strip()
    host = host if host is not None else parse_host(s)
    ip = host is not None and is_ip(host)
    depth = 0
    if host and not ip:
        reg = registered_domain(host)
        depth = max(0, host.count(".") - reg.count("."))
    try:
        netloc = split_url(s).netloc
    except ValueError:
        netloc = ""
    return {
        "is_ip_host": bool(ip),
        "subdomain_depth": int(depth),
        "has_at_symbol": "@" in netloc,
        "has_punycode": bool(host) and "xn--" in host,
        "url_length": len(s),
        "is_known_shortener": bool(host) and (registered_domain(host) in KNOWN_SHORTENERS or host in KNOWN_SHORTENERS),
    }
