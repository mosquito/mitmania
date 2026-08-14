#!/usr/bin/env python3
"""Download and merge host-wide filter lists into mitmania rules.

This intentionally implements only the subset that can be represented safely
as a hostname decision. URL/path filters, cosmetic filters, and filters scoped
by request type or page context are skipped instead of being widened into a
whole-host block.

The default output is a complete rules/default payload for both IPv4 and IPv6
clients. It allows all hosts not selected by the input lists with mitm:false,
while retaining mitmania's deny-first egress floor.

By default (--action block), a selected host is rejected at the connection
phase via mitmania's connection:{accept:false} rule field, matched purely on
host (SNI for HTTPS, the CONNECT/absolute-form authority otherwise). No TLS
termination is ever attempted, so blocked hosts do not require the client to
trust mitmania's signing CA at all. --action raise instead serves a custom
status/body, which does need interception (mitm:true plus a request-phase
raise action) to actually speak HTTP back to the client; that path still
requires CA trust, the same tradeoff mitm:true interception always has.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import io
import ipaddress
import json
import re
import socket
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Iterable, Iterator, TextIO


HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
# ABP/uBO commonly use ||example.org^; AdGuard DNS also documents the
# separator-less ||example.org spelling with the same hostname/subdomain
# meaning.
ABP_HOST_RE = re.compile(r"^\|\|([^/^|*]+?)(?:\^)?$")
COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
SAFE_OPTIONS = {"all", "important", "match-case"}
HOSTS_SINKS = {
    "0.0.0.0",
    "127.0.0.1",
    "::",
    "::1",
}
IGNORED_HOSTS = {
    "broadcasthost",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-localhost",
    "ip6-loopback",
    "localhost",
    "localhost.localdomain",
    "local",
}

# TrackerDB classifies behaviors; it is not itself a blocklist and includes
# benign categories. Keep the automatic import to explicitly advertising and
# analytics-oriented categories. This can be changed from the CLI.
DEFAULT_GHOSTERY_CATEGORIES = frozenset(
    {"advertising", "pornvertising", "site_analytics"}
)

# Keep the generated default table at the same SSRF-safe floor as a freshly
# bootstrapped mitmania cluster. Every source-address bucket contains both
# destination families because source and destination address families are
# independent.
DENY_FIRST_EGRESS = [
    {"cidr": "127.0.0.0/8", "action": "deny"},
    {"cidr": "::1/128", "action": "deny"},
    {"cidr": "10.0.0.0/8", "action": "deny"},
    {"cidr": "172.16.0.0/12", "action": "deny"},
    {"cidr": "192.168.0.0/16", "action": "deny"},
    {"cidr": "fc00::/7", "action": "deny"},
    {"cidr": "169.254.0.0/16", "action": "deny"},
    {"cidr": "fe80::/10", "action": "deny"},
    {"cidr": "0.0.0.0/0", "action": "allow"},
    {"cidr": "::/0", "action": "allow"},
]

# Mirrors the control API's dedicated rules/default limit. Check locally before a
# mutating request so an oversized generated document cannot surprise an
# operator with a failed deployment after a lengthy import.
CONTROL_MAX_RULESET_BYTES = 64 << 20


class RulesProvider(ABC):
    """Interface implemented by every typed filter source."""

    name: ClassVar[str] = ""
    default_url: ClassVar[str] = ""
    source: str

    @abstractmethod
    def load(
        self,
        max_bytes: int,
        ghostery_categories: frozenset[str],
    ) -> tuple[str, Iterable[str]]:
        raise NotImplementedError

    @abstractmethod
    def __str__(self) -> str:
        raise NotImplementedError


@dataclass(frozen=True)
class AdBlockProvider(RulesProvider):
    source: str
    name: ClassVar[str] = "adblock"
    default_url: ClassVar[str] = (
        "https://easylist-downloads.adblockplus.org/easylist.txt"
    )

    def decode(
        self,
        data: bytes,
        source_name: str,
        max_bytes: int,
        ghostery_categories: frozenset[str],
    ) -> Iterator[str]:
        del ghostery_categories
        yield from decode_text_source(data, source_name, max_bytes)

    def load(
        self,
        max_bytes: int,
        ghostery_categories: frozenset[str],
    ) -> tuple[str, Iterable[str]]:
        source_name, data = read_source_bytes(self.source, max_bytes)
        label = f"{self.name}={source_name}"
        return label, self.decode(data, source_name, max_bytes, ghostery_categories)

    def __str__(self) -> str:
        return f"{self.name}={self.source}"


@dataclass(frozen=True)
class EasyPrivacyProvider(AdBlockProvider):
    name: ClassVar[str] = "easyprivacy"
    default_url: ClassVar[str] = "https://easylist.to/easylist/easyprivacy.txt"


@dataclass(frozen=True)
class AdGuardProvider(AdBlockProvider):
    name: ClassVar[str] = "adguard"
    default_url: ClassVar[str] = (
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
    )


@dataclass(frozen=True)
class UBlockProvider(AdBlockProvider):
    name: ClassVar[str] = "ublock"
    default_url: ClassVar[str] = (
        "https://ublockorigin.github.io/uAssets/filters/filters.txt"
    )


@dataclass(frozen=True)
class UBlockPrivacyProvider(AdBlockProvider):
    name: ClassVar[str] = "ublock-privacy"
    default_url: ClassVar[str] = (
        "https://ublockorigin.github.io/uAssets/filters/privacy.txt"
    )


@dataclass(frozen=True)
class PeterLoweProvider(AdBlockProvider):
    name: ClassVar[str] = "peterlowe"
    default_url: ClassVar[str] = (
        "https://pgl.yoyo.org/adservers/serverlist.php?"
        "hostformat=plain&mimetype=plaintext&showintro=0"
    )


@dataclass(frozen=True)
class HageziLightProvider(AdBlockProvider):
    name: ClassVar[str] = "hagezi-light"
    default_url: ClassVar[str] = (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/light.txt"
    )


@dataclass(frozen=True)
class HageziTIFMiniProvider(AdBlockProvider):
    name: ClassVar[str] = "hagezi-tif-mini"
    default_url: ClassVar[str] = (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/"
        "tif.mini.txt"
    )


@dataclass(frozen=True)
class GhosteryProvider(RulesProvider):
    source: str
    name: ClassVar[str] = "ghostery"
    default_url: ClassVar[str] = (
        "https://github.com/ghostery/trackerdb/archive/refs/heads/main.tar.gz"
    )

    def decode(
        self,
        data: bytes,
        source_name: str,
        max_bytes: int,
        ghostery_categories: frozenset[str],
    ) -> Iterator[str]:
        archive_lines = ghostery_archive_lines(data, ghostery_categories, max_bytes)
        if archive_lines is None:
            raise ValueError(f"Ghostery source {source_name!r} is not a TrackerDB archive")
        yield from archive_lines

    def load(
        self,
        max_bytes: int,
        ghostery_categories: frozenset[str],
    ) -> tuple[str, Iterable[str]]:
        source_name, data = read_source_bytes(self.source, max_bytes)
        label = f"{self.name}={source_name}"
        return label, self.decode(data, source_name, max_bytes, ghostery_categories)

    def __str__(self) -> str:
        return f"{self.name}={self.source}"


PROVIDER_TYPES = {
    provider.name: provider
    for provider in (
        AdBlockProvider,
        EasyPrivacyProvider,
        AdGuardProvider,
        UBlockProvider,
        UBlockPrivacyProvider,
        PeterLoweProvider,
        HageziLightProvider,
        HageziTIFMiniProvider,
        GhosteryProvider,
    )
}

DEFAULT_PROVIDER_NAMES = (
    HageziLightProvider.name,
    HageziTIFMiniProvider.name,
)
PRESET_CHOICES = (*PROVIDER_TYPES, "all")


def parse_provider_spec(raw: str) -> RulesProvider:
    provider_name, separator, source = raw.partition("=")
    if not separator or not provider_name or not source:
        raise argparse.ArgumentTypeError(
            "source must use PROVIDER=LOCATION, for example "
            "adblock=https://example.test/filter.txt"
        )
    provider_type = PROVIDER_TYPES.get(provider_name)
    if provider_type is None:
        choices = ", ".join(PROVIDER_TYPES)
        raise argparse.ArgumentTypeError(
            f"unknown source provider {provider_name!r} (choose from {choices})"
        )
    return provider_type(source)


@dataclass
class ParsedFilters:
    blocked: set[str] = field(default_factory=set)
    important: set[str] = field(default_factory=set)
    exceptions: set[str] = field(default_factory=set)
    important_exceptions: set[str] = field(default_factory=set)
    disabled_blocked: set[str] = field(default_factory=set)
    disabled_important: set[str] = field(default_factory=set)
    disabled_exceptions: set[str] = field(default_factory=set)
    disabled_important_exceptions: set[str] = field(default_factory=set)
    stats: Counter[str] = field(default_factory=Counter)
    source_stats: list[tuple[str, Counter[str]]] = field(default_factory=list)

    def finish(self) -> None:
        self.blocked.difference_update(self.disabled_blocked)
        self.important.difference_update(self.disabled_important)
        self.exceptions.difference_update(self.disabled_exceptions)
        self.important_exceptions.difference_update(self.disabled_important_exceptions)
        # AdGuard's priority is important exception, important block, ordinary
        # exception, ordinary block. uBO likewise lets important blocks defeat
        # ordinary exceptions.
        self.important.difference_update(self.important_exceptions)
        self.exceptions.difference_update(self.important)
        self.exceptions.difference_update(self.important_exceptions)
        self.blocked.difference_update(self.important)
        self.blocked.difference_update(self.exceptions)
        self.blocked.difference_update(self.important_exceptions)


def normalize_hostname(raw: str) -> str | None:
    host = raw.strip().rstrip(".").lower()
    if not host or host in IGNORED_HOSTS:
        return None
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(host) > 253 or not HOST_RE.fullmatch(host):
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def parse_options(raw: str) -> tuple[set[str], bool]:
    options: set[str] = set()
    badfilter = False
    for item in raw.split(","):
        item = item.strip().lower()
        if not item:
            continue
        name = item.split("=", 1)[0]
        if name == "badfilter":
            badfilter = True
        else:
            options.add(name if "=" not in item else item)
    return options, badfilter


def add_filter(
    parsed: ParsedFilters,
    host: str,
    *,
    exception: bool = False,
    important: bool = False,
    badfilter: bool = False,
) -> None:
    if badfilter:
        if exception and important:
            parsed.disabled_important_exceptions.add(host)
        elif exception:
            parsed.disabled_exceptions.add(host)
        elif important:
            parsed.disabled_important.add(host)
        else:
            parsed.disabled_blocked.add(host)
        parsed.stats["badfilter"] += 1
    elif exception and important:
        parsed.important_exceptions.add(host)
        parsed.stats["important_exception"] += 1
    elif exception:
        parsed.exceptions.add(host)
        parsed.stats["exception"] += 1
    elif important:
        parsed.important.add(host)
        parsed.stats["important"] += 1
    else:
        parsed.blocked.add(host)
        parsed.stats["block"] += 1


def parse_line(line: str, parsed: ParsedFilters) -> None:
    parsed.stats["lines"] += 1
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith(("!", "[", "#")):
        parsed.stats["ignored"] += 1
        return
    if any(marker in line for marker in COSMETIC_MARKERS):
        parsed.stats["unsupported"] += 1
        return

    # AdGuard domains-only lists permit an inline comment after a hostname.
    # Cosmetic markers were rejected above, so stripping a remaining comment
    # cannot turn an extended/cosmetic rule into a hostname rule.
    line = line.split("#", 1)[0].strip()
    if not line:
        parsed.stats["ignored"] += 1
        return

    # HOSTS format: "0.0.0.0 ads.example tracker.example # comment".
    fields = line.split()
    if len(fields) >= 2 and fields[0] in HOSTS_SINKS:
        found = False
        for candidate in fields[1:]:
            host = normalize_hostname(candidate)
            if host:
                add_filter(parsed, host)
                found = True
        parsed.stats["hosts"] += int(found)
        if not found:
            parsed.stats["unsupported"] += 1
        return

    exception = line.startswith("@@")
    if exception:
        line = line[2:]

    pattern, separator, raw_options = line.partition("$")
    options, badfilter = parse_options(raw_options) if separator else (set(), False)
    match = ABP_HOST_RE.fullmatch(pattern)
    if match:
        host = normalize_hostname(match.group(1))
        # Options with values or request/page scoping cannot be represented by
        # a connection hostname without broadening the source filter.
        if not host or options.difference(SAFE_OPTIONS):
            parsed.stats["unsupported"] += 1
            return
        add_filter(
            parsed,
            host,
            exception=exception,
            important="important" in options,
            badfilter=badfilter,
        )
        parsed.stats["abp"] += 1
        return

    # uBO treats a syntactically valid bare hostname as ||hostname^.
    if not exception and not separator:
        host = normalize_hostname(pattern)
        if host:
            add_filter(parsed, host)
            parsed.stats["hostname"] += 1
            return

    parsed.stats["unsupported"] += 1


def parse_sources(sources: Iterable[tuple[str, Iterable[str]]]) -> ParsedFilters:
    parsed = ParsedFilters()
    mined_keys = ("block", "important", "exception", "important_exception", "badfilter")
    for name, lines in sources:
        before = parsed.stats.copy()
        parsed.stats["sources"] += 1
        for line in lines:
            parse_line(line, parsed)
        delta = Counter(
            {
                key: parsed.stats[key] - before[key]
                for key in parsed.stats
                if parsed.stats[key] != before[key]
            }
        )
        delta["mined"] = sum(delta[key] for key in mined_keys)
        parsed.source_stats.append((name.partition("=")[0], delta))
    parsed.finish()
    return parsed


def read_limited(response: TextIO | object, limit: int) -> bytes:
    # urllib responses and binary files both expose read().
    data = response.read(limit + 1)  # type: ignore[attr-defined]
    if len(data) > limit:
        raise ValueError(f"input exceeds --max-input-bytes ({limit} bytes)")
    return data


def ghostery_archive_lines(
    data: bytes, categories: frozenset[str], max_bytes: int
) -> Iterator[str] | None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        return None

    members = [
        member
        for member in archive.getmembers()
        if member.isfile()
        and "/db/patterns/" in member.name
        and member.name.endswith(".eno")
    ]
    if not members:
        archive.close()
        return None

    def iter_domains() -> Iterator[str]:
        extracted_bytes = 0
        with archive:
            for member in members:
                extracted_bytes += member.size
                if extracted_bytes > max_bytes:
                    raise ValueError(
                        "Ghostery archive contents exceed --max-input-bytes "
                        f"({max_bytes} bytes)"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                text = handle.read().decode("utf-8-sig", errors="replace")
                category = ""
                domains: list[str] = []
                in_domains = False
                for raw_line in text.splitlines():
                    line = raw_line.strip()
                    if line.startswith("category:") and not in_domains:
                        category = line.partition(":")[2].strip().lower()
                    elif line == "--- domains":
                        in_domains = not in_domains
                    elif in_domains and line:
                        domains.append(line)
                if category in categories:
                    yield from domains

    return iter_domains()


def decode_text_source(data: bytes, name: str, max_bytes: int) -> Iterator[str]:
    if data.startswith(b"\x1f\x8b") or name.lower().endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            data = compressed.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"decompressed input exceeds --max-input-bytes ({max_bytes} bytes)")
    text = data.decode("utf-8-sig", errors="replace")
    yield from io.StringIO(text)


def read_source_bytes(source: str, max_bytes: int) -> tuple[str, bytes]:
    if source == "-":
        data = sys.stdin.buffer.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"stdin exceeds --max-input-bytes ({max_bytes} bytes)")
        return "stdin", data

    parsed_url = urllib.parse.urlparse(source)
    if parsed_url.scheme in {"http", "https"}:
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "mitmania-adblock-converter/1"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = read_limited(response, max_bytes)
        return source, data

    path = Path(source)
    with path.open("rb") as handle:
        data = read_limited(handle, max_bytes)
    return str(path), data


def regex_atom(host: str) -> str:
    # Valid normalized hostnames contain only letters, digits, hyphens and
    # dots. Only the dot is special outside a regexp character class. Python's
    # re.escape also emits \-; Go's regexp parser (used by mitmania) does not
    # accept every Python-only identity escape.
    return host.replace(".", r"\.")


def chunk_domains(domains: Iterable[str], max_chars: int) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    size = 0
    for host in sorted(set(domains)):
        atom_size = len(regex_atom(host)) + (1 if current else 0)
        if current and size + atom_size > max_chars:
            chunks.append(current)
            current = []
            size = 0
        current.append(host)
        size += atom_size
    if current:
        chunks.append(current)
    return chunks


def host_regex(domains: list[str]) -> str:
    alternatives = "|".join(regex_atom(host) for host in domains)
    # Hostnames are canonicalized to lowercase on ordinary proxy paths, while
    # (?i) also covers transparent TLS SNI supplied with unusual casing.
    return rf"re:(?i)(?:^|\.)(?:{alternatives})$"


def block_rule(domains: list[str], action: str, status: int, body: str) -> dict:
    if action == "block":
        # A connection-phase reject needs no TLS termination and no CA
        # trust from the client. host-based ad/tracker blocking never
        # needed path/method/header granularity, so the only thing this
        # gives up relative to mitm:true plus a request-phase block is
        # exactly the thing that made every blocked host show a
        # certificate error.
        return {"match": {"host": host_regex(domains)}, "connection": {"accept": False}}
    request_action: dict = {"action": action}
    if action == "raise":
        request_action["params"] = {"http": status, "body": body}
    return {
        "match": {"host": host_regex(domains)},
        "request": [request_action],
    }


def allow_rule(domains: list[str]) -> dict:
    return {"match": {"host": host_regex(domains)}, "mitm": False}


def build_http_rules(
    parsed: ParsedFilters,
    args: argparse.Namespace,
    *,
    include_catch_all: bool = True,
) -> list[dict]:
    rules: list[dict] = []
    # First-match rule ordering encodes AdGuard's priority and the overlapping
    # uBO semantics.
    for chunk in chunk_domains(parsed.important_exceptions, args.max_regex_chars):
        rules.append(allow_rule(chunk))
    for chunk in chunk_domains(parsed.important, args.max_regex_chars):
        rules.append(block_rule(chunk, args.action, args.status, args.body))
    for chunk in chunk_domains(parsed.exceptions, args.max_regex_chars):
        rules.append(allow_rule(chunk))
    for chunk in chunk_domains(parsed.blocked, args.max_regex_chars):
        rules.append(block_rule(chunk, args.action, args.status, args.body))
    if include_catch_all and not args.no_catch_all:
        rules.append({"match": {}, "mitm": False})
    return rules


def load_base_ruleset(path_name: str) -> dict:
    path = Path(path_name)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid base ruleset JSON: {exc}") from exc
    if not isinstance(document, dict) or not document:
        raise ValueError("base ruleset must be a non-empty JSON object")
    for bucket_name, bucket in document.items():
        if not isinstance(bucket_name, str) or not isinstance(bucket, dict):
            raise ValueError("base ruleset buckets must be named JSON objects")
        http_rules = bucket.get("http")
        if not isinstance(http_rules, list):
            raise ValueError(f"base ruleset bucket {bucket_name!r} must contain an http array")
    return document


def parse_ruleset_document(raw: bytes, source: str) -> dict:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid rules/default JSON from {source}: {exc}") from exc
    if not isinstance(document, dict) or not document:
        raise ValueError(f"rules/default from {source} must be a non-empty JSON object")
    for bucket_name, bucket in document.items():
        if not isinstance(bucket_name, str) or not isinstance(bucket, dict):
            raise ValueError(f"rules/default from {source} has an invalid bucket")
        if not isinstance(bucket.get("http"), list):
            raise ValueError(
                f"rules/default bucket {bucket_name!r} from {source} must contain an http array"
            )
    return document


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


def control_connection(control_url: str, timeout: float) -> http.client.HTTPConnection:
    parsed = urllib.parse.urlparse(control_url)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError(
            "control URL must not contain credentials, a query, or a fragment"
        )
    if parsed.scheme == "unix":
        if parsed.netloc not in {"", "localhost"} or not parsed.path.startswith("/"):
            raise ValueError("Unix control URL must look like unix:///run/mitmania.sock")
        return UnixHTTPConnection(urllib.parse.unquote(parsed.path), timeout)
    if parsed.scheme in {"tcp", "http"}:
        if not parsed.hostname or parsed.port is None or parsed.path not in {"", "/"}:
            raise ValueError("TCP control URL must look like tcp://127.0.0.1:5555")
        return http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    raise ValueError("control URL scheme must be unix://, tcp://, or http://")


def control_rules_endpoint(control_url: str) -> str:
    return f"{control_url.rstrip('/')}/rules/default"


def control_request(
    control_url: str,
    method: str,
    body: bytes | None,
    timeout: float,
) -> tuple[int, bytes]:
    connection = control_connection(control_url, timeout)
    endpoint = control_rules_endpoint(control_url)
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, "/rules/default", body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(CONTROL_MAX_RULESET_BYTES + 1)
        if len(response_body) > CONTROL_MAX_RULESET_BYTES:
            raise ValueError("control response exceeds 16 MiB")
        return response.status, response_body
    except OSError as exc:
        raise ValueError(
            f"{method} {endpoint}: TCP connect failed: {exc}"
        ) from exc
    except http.client.HTTPException as exc:
        raise ValueError(
            f"{method} {endpoint}: invalid response from remote control API: {exc}"
        ) from exc
    finally:
        connection.close()


def fetch_control_ruleset(control_url: str, timeout: float) -> dict:
    status, body = control_request(control_url, "GET", None, timeout)
    if status != 200:
        detail = body.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"GET {control_rules_endpoint(control_url)} returned HTTP {status}: {detail}"
        )
    return parse_ruleset_document(body, control_url)


def push_control_ruleset(control_url: str, document: bytes, timeout: float) -> None:
    if len(document) > CONTROL_MAX_RULESET_BYTES:
        raise ValueError(
            f"generated rules/default is {len(document)} bytes, but the control API "
            f"limit is {CONTROL_MAX_RULESET_BYTES} bytes; refusing to send"
        )
    status, body = control_request(control_url, "PUT", document, timeout)
    if status != 204:
        detail = body.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"PUT {control_rules_endpoint(control_url)} returned HTTP {status}: {detail}"
        )


# GENERATION_BOUNDARY marks the end of this script's own generated rules
# within a bucket's http[] array. On every run, whatever precedes the last
# occurrence of this exact rule is this tool's own prior output and is
# discarded before prepending the freshly generated batch; whatever follows
# it (or the whole array, if the marker is absent) is the operator's real
# base, never touched. Without this, running --control repeatedly against
# its own prior output prepends onto what it prepended last time, growing
# the table by one full generation on every run. The host is deliberately
# under the IANA-reserved .invalid TLD (RFC 2606): guaranteed to never
# resolve, so this rule can never match real traffic even if it were
# somehow reached.
GENERATION_BOUNDARY = {
    "match": {"host": "adblock-to-mitmania.generation-boundary.invalid"},
    "mitm": False,
}


def strip_previous_generation(existing_rules: list[dict]) -> list[dict]:
    boundary_at = -1
    for i, rule in enumerate(existing_rules):
        if rule == GENERATION_BOUNDARY:
            boundary_at = i
    if boundary_at < 0:
        return existing_rules
    return existing_rules[boundary_at + 1 :]


def merge_base_ruleset(base: dict, filter_rules: list[dict]) -> dict:
    # Round-trip through JSON-compatible values so callers' in-memory base is
    # never mutated. Bucket metadata (including uuid, auth, and egress) stays
    # byte-for-value identical; only http[] receives a new prefix.
    merged = json.loads(json.dumps(base))
    for bucket in merged.values():
        true_base = strip_previous_generation(bucket["http"])
        bucket["http"] = [*filter_rules, GENERATION_BOUNDARY, *true_base]
    return merged


def format_output(
    rules: list[dict],
    args: argparse.Namespace,
    base_ruleset: dict | None = None,
) -> object:
    if base_ruleset is not None:
        return merge_base_ruleset(base_ruleset, rules)
    if args.format == "http-rules":
        return rules
    if args.format == "rule-file":
        return {"http": rules}

    bucket = {"http": rules, "egress": DENY_FIRST_EGRESS}
    # json.dump serializes each independently; sharing the in-memory value is
    # harmless and avoids constructing a second huge rule list.
    return {"0.0.0.0/0": bucket, "::/0": bucket}


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download and merge host-wide filters into mitmania JSON.",
        epilog=(
            "Only hostname-wide filters are converted. The default payload allows "
            "non-listed HTTP(S) hosts with mitm:false and rejects selected hosts "
            "at the connection phase (connection:{accept:false}, no interception); "
            "see this script's module documentation, and --action, for the raise "
            "alternative that does need interception."
        ),
    )
    parser.add_argument(
        "sources",
        nargs="*",
        type=parse_provider_spec,
        default=[],
        help=(
            "typed sources in PROVIDER=LOCATION form; LOCATION may be a file, "
            "HTTP(S) URL, or '-' for stdin; when omitted, use the compatibility-"
            "focused ads and malware defaults"
        ),
    )
    parser.add_argument(
        "--preset",
        nargs="+",
        choices=PRESET_CHOICES,
        help=(
            "select providers using each class's default URL; 'all' selects every "
            "registered provider"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        help="output JSON file (default: stdout unless --control is used)",
    )
    parser.add_argument(
        "--base-ruleset",
        help=(
            "preserve this rules/default JSON and prepend generated filter "
            "rules to every bucket's http array"
        ),
    )
    parser.add_argument(
        "--control",
        help=(
            "GET the base and PUT generated rules/default through unix:///path, "
            "tcp://host:port, or http://host:port"
        ),
    )
    parser.add_argument(
        "--control-timeout",
        type=positive_int,
        default=30,
        help="control GET/PUT timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--domains-output",
        help="also write the sorted, deduplicated effective block domains",
    )
    parser.add_argument(
        "--ghostery-categories",
        default=",".join(sorted(DEFAULT_GHOSTERY_CATEGORIES)),
        help=(
            "comma-separated TrackerDB categories to import (default: "
            "advertising,pornvertising,site_analytics)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=("default-ruleset", "rule-file", "http-rules"),
        default="default-ruleset",
        help="JSON shape to emit (default: complete rules/default payload)",
    )
    parser.add_argument(
        "--action",
        choices=("block", "raise"),
        default="block",
        help=(
            "how selected hosts are rejected: block (default) uses "
            "connection:{accept:false}, no interception or CA trust "
            "needed; raise intercepts and serves a custom status/body, which "
            "does need the client to trust mitmania's signing CA"
        ),
    )
    parser.add_argument("--status", type=int, default=403, help="HTTP status used with --action raise")
    parser.add_argument(
        "--body",
        default="Blocked by advertising policy.",
        help="error-page message used with --action raise",
    )
    parser.add_argument(
        "--max-regex-chars",
        type=positive_int,
        default=12_000,
        help="approximate domain-alternation characters per generated rule",
    )
    parser.add_argument(
        "--max-input-bytes",
        type=positive_int,
        default=64 * 1024 * 1024,
        help="maximum input and decompressed bytes accepted from each source",
    )
    parser.add_argument(
        "--no-catch-all",
        action="store_true",
        help="omit the final mitm:false allow rule (unmatched hosts fail with 511)",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="permit output when no effective blocking hostname was parsed",
    )
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress conversion statistics")
    args = parser.parse_args(argv)
    if not 100 <= args.status <= 599:
        parser.error("--status must be between 100 and 599")
    if args.base_ruleset and args.format != "default-ruleset":
        parser.error("--base-ruleset requires --format default-ruleset")
    if args.control and args.format != "default-ruleset":
        parser.error("--control requires --format default-ruleset")
    if args.control and args.base_ruleset:
        parser.error("use either --control (fetch current base) or --base-ruleset, not both")
    providers: list[RulesProvider] = []
    if args.preset:
        for name in args.preset:
            selected_names = PROVIDER_TYPES if name == "all" else (name,)
            providers.extend(
                PROVIDER_TYPES[selected](PROVIDER_TYPES[selected].default_url)
                for selected in selected_names
            )
    providers.extend(args.sources)
    if not providers:
        providers.extend(
            PROVIDER_TYPES[name](PROVIDER_TYPES[name].default_url)
            for name in DEFAULT_PROVIDER_NAMES
        )
    args.sources = list(
        {
            (provider.name, provider.source): provider
            for provider in providers
        }.values()
    )
    if sum(provider.source == "-" for provider in args.sources) > 1:
        parser.error("stdin ('-') may be specified only once")
    categories = frozenset(
        item.strip().lower()
        for item in args.ghostery_categories.split(",")
        if item.strip()
    )
    if not categories:
        parser.error("--ghostery-categories must name at least one category")
    if any(not re.fullmatch(r"[a-z][a-z0-9_]*", item) for item in categories):
        parser.error("--ghostery-categories contains an invalid category name")
    args.ghostery_categories = categories
    return args


def serialize_json(document: object, args: argparse.Namespace) -> bytes:
    kwargs = {"ensure_ascii": False, "sort_keys": False}
    if args.compact:
        kwargs["separators"] = (",", ":")
    else:
        kwargs["indent"] = 2

    return (json.dumps(document, **kwargs) + "\n").encode("utf-8")


def write_json(data: bytes, output_name: str) -> None:
    if output_name == "-":
        sys.stdout.buffer.write(data)
        return
    Path(output_name).write_bytes(data)


def effective_blocked_domains(parsed: ParsedFilters) -> list[str]:
    return sorted(parsed.blocked | parsed.important)


def write_domains(parsed: ParsedFilters, output_name: str) -> None:
    domains = effective_blocked_domains(parsed)
    if output_name == "-":
        for domain in domains:
            print(domain)
        return
    with Path(output_name).open("w", encoding="utf-8", newline="\n") as handle:
        for domain in domains:
            handle.write(domain)
            handle.write("\n")


def print_stats(parsed: ParsedFilters, rules: list[dict]) -> None:
    for provider, stats in parsed.source_stats:
        print(
            "mined "
            f"provider={provider} "
            f"rules={stats['mined']} "
            f"lines={stats['lines']} "
            f"unsupported={stats['unsupported']}",
            file=sys.stderr,
        )
    mined = sum(stats["mined"] for _, stats in parsed.source_stats)
    print(
        "converted "
        f"sources={parsed.stats['sources']} "
        f"lines={parsed.stats['lines']} "
        f"mined={mined} "
        f"effective_domains={len(effective_blocked_domains(parsed))} "
        f"blocked={len(parsed.blocked)} "
        f"important={len(parsed.important)} "
        f"exceptions={len(parsed.exceptions)} "
        f"important_exceptions={len(parsed.important_exceptions)} "
        f"disabled={parsed.stats['badfilter']} "
        f"unsupported={parsed.stats['unsupported']} "
        f"http_rules={len(rules)}",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        output_name = args.output if args.output is not None else (None if args.control else "-")
        if output_name is not None and args.domains_output == output_name:
            raise ValueError("--output and --domains-output must be different files")
        if args.base_ruleset and output_name not in {None, "-"}:
            if Path(args.base_ruleset).resolve() == Path(output_name).resolve():
                raise ValueError("refusing to overwrite --base-ruleset in place")

        # Validate and fetch the mutation boundary before spending time and
        # bandwidth on remote lists. A bad route/listener must fail without
        # downloading providers or constructing a replacement document.
        if args.control:
            if not args.quiet:
                print(f"fetching current rules/default from {args.control}", file=sys.stderr)
            base_ruleset = fetch_control_ruleset(args.control, args.control_timeout)
        else:
            base_ruleset = load_base_ruleset(args.base_ruleset) if args.base_ruleset else None

        def load_sources() -> Iterator[tuple[str, Iterable[str]]]:
            for provider in args.sources:
                if not args.quiet:
                    print(f"loading provider={provider.name}", file=sys.stderr)
                yield provider.load(
                    args.max_input_bytes,
                    args.ghostery_categories,
                )

        if (
            any(isinstance(provider, GhosteryProvider) for provider in args.sources)
            and not args.quiet
        ):
            print(
                "note: Ghostery TrackerDB is CC-BY-NC-SA-4.0 and is included "
                "for non-commercial use; review its license before redistributing output",
                file=sys.stderr,
            )
        sources = load_sources()
        parsed = parse_sources(sources)
        if not args.allow_empty and not (parsed.blocked or parsed.important):
            raise ValueError(
                "no effective blocking hostnames parsed; refusing to emit an "
                "allow-only policy (use --allow-empty to override)"
            )
        rules = build_http_rules(
            parsed,
            args,
            include_catch_all=base_ruleset is None,
        )
        if not args.quiet:
            print_stats(parsed, rules)
        document = format_output(rules, args, base_ruleset)
        json_data = serialize_json(document, args)
        if args.domains_output == "-" and output_name == "-":
            raise ValueError("--domains-output and --output cannot both use stdout")
        if output_name is not None:
            write_json(json_data, output_name)
        if args.domains_output:
            write_domains(parsed, args.domains_output)
        if args.control:
            if not args.quiet:
                print(
                    f"pushing {len(json_data)} bytes to {args.control}/rules/default",
                    file=sys.stderr,
                )
            push_control_ruleset(args.control, json_data, args.control_timeout)
            if not args.quiet:
                print("control update accepted (HTTP 204)", file=sys.stderr)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
