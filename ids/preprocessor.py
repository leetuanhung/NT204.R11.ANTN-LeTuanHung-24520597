"""Preprocessor: kiểm tra và chuẩn hóa event trước khi đưa sang Flow Tracker (mục 4 của đề).

Thêm vào mỗi event:
    preprocess_status   valid    đủ và đúng các trường mà module phía sau cần
                        partial  dùng được nhưng có vấn đề: gói hỏng hoặc bị cắt ở tầng trên,
                                 giao thức không hỗ trợ
                        invalid  thiếu hoặc sai trường bắt buộc: thời gian, địa chỉ IP, port.
                                 Flow Tracker không biết gói xảy ra lúc nào, giữa ai với ai.
    reason              danh sách lý do, [] khi valid
    norm                giá trị đã chuẩn hóa: tên giao thức viết đúng chuẩn, IP dạng chuẩn,
                        port là số, tên miền chữ thường. Luôn đủ các khóa; không có thì null.

Không ghi đè dữ liệu gốc của Bài 1. Không bao giờ ném lỗi (mục 2 của đề).
"""

import ipaddress
import math
import time
from dataclasses import dataclass
from typing import Any

from ids.detector import DNS, HTTP, SMTP, UNKNOWN
from ids.parsers.network import IP_PROTO_NAMES

VALID, PARTIAL, INVALID = "valid", "partial", "invalid"
_UNSUPPORTED = "unsupported"   # Mức nội bộ: event đúng nhưng thuộc giao thức không hỗ trợ -> partial

MAX_CLOCK_SKEW = 86400.0       # Giây. Timestamp ở tương lai xa hơn mức này so với đồng hồ máy là sai

# Tên chuẩn của giao thức ở từng tầng, đúng như Bài 1 ghi
NETWORKS = {"IPv4", UNKNOWN}
TRANSPORTS = set(IP_PROTO_NAMES.values()) | {"FRAGMENT", UNKNOWN}
APPS = {HTTP, DNS, SMTP, UNKNOWN}
SUPPORTED_TRANSPORTS = {"TCP", "UDP"}

# Viết hoa -> tên chuẩn, để nhận cả "tcp", "Tcp", "ipv4"
_CANONICAL = {name.upper(): name for name in NETWORKS | TRANSPORTS | APPS}

NORM_FIELDS = ("network", "transport", "app_protocol",
               "src_ip", "dst_ip", "src_port", "dst_port", "domain")


@dataclass
class PreprocessConfig:
    max_clock_skew: float = MAX_CLOCK_SKEW


def _show(value: Any, limit: int = 60) -> str:
    """repr ngắn gọn để đưa vào reason: giá trị sai có thể rất dài (input độc hại), không chép nguyên."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _bad(field: str, value: Any) -> str:
    """Lý do cho một trường bắt buộc: phân biệt thiếu (None) với có nhưng sai."""
    return f"thiếu {field}" if value is None else f"{field} không hợp lệ: {_show(value)}"


def _protocol(value: Any, names: set[str], numbers: dict[int, str] | None = None) -> str | None:
    """'tcp', ' Tcp ' -> 'TCP'; với tầng 4 nhận cả số IANA (6 -> 'TCP'). None nếu không nhận ra."""
    if isinstance(value, str):
        name = _CANONICAL.get(value.strip().upper())
    elif numbers and isinstance(value, int) and not isinstance(value, bool):
        name = numbers.get(value)
    else:
        return None
    return name if name in names else None


def _ip(value: Any) -> tuple[str | None, str | None]:
    """Địa chỉ IP -> (dạng chuẩn, ghi chú). (None, None) nếu không phải địa chỉ IP.

    Dạng chuẩn do module ipaddress sinh ra: IPv6 viết thường và rút gọn, IPv4 nằm trong IPv6
    (::ffff:1.2.3.4) đổi về IPv4. Octet có số 0 ở đầu (010) bị ipaddress từ chối vì mơ hồ: một số
    hàm C hiểu là hệ 8. Ở đây hiểu theo thập phân như phần lớn công cụ hiện nay, kèm ghi chú.
    """
    if not isinstance(value, str):
        return None, None
    text = value.strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        octets = text.split(".")
        if (len(octets) == 4 and all(o.isascii() and o.isdigit() and len(o) <= 3 for o in octets)
                and all(int(o) <= 255 for o in octets)):
            return ".".join(str(int(o)) for o in octets), "có số 0 ở đầu octet, hiểu theo thập phân"
        return None, None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip), None


def _port(value: Any) -> int | None:
    """Port 0-65535. Nhận cả số viết dạng chuỗi ("80")."""
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535:
        return value
    return None


def _domain(value: Any) -> str | None:
    """Tên miền dạng chuẩn: bỏ khoảng trắng, chữ thường, bỏ dấu chấm cuối.

    "WWW.Example.COM." -> "www.example.com". Tên gốc (Bài 1 ghi "<Root>") -> ".".
    """
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if name in ("<root>", "."):
        return "."
    return name.rstrip(".") or None


def _host_domain(host: Any) -> str | None:
    """Header Host -> tên miền. Bỏ port ("example.com:8080"); Host là địa chỉ IP thì không có tên miền."""
    if not isinstance(host, str):
        return None
    host = host.strip()
    if host.startswith("["):                       # IPv6 dạng [::1]:80
        return None
    if host.count(":") == 1:
        host = host.split(":")[0]
    if _ip(host)[0] is not None:
        return None
    return _domain(host)


def _event_domain(event: dict) -> str | None:
    """Tên miền của event: Host của HTTP, hoặc tên được hỏi trong DNS."""
    http = event.get("http")
    if isinstance(http, dict) and http.get("host") is not None:
        return _host_domain(http["host"])
    dns = event.get("dns")
    if isinstance(dns, dict) and isinstance(dns.get("qry"), list) and dns["qry"]:
        first = dns["qry"][0]
        if isinstance(first, dict):
            return _domain(first.get("name"))
    return None


def _timestamp(value: Any, max_clock_skew: float) -> tuple[float | None, str | None]:
    """Epoch (giây) -> (timestamp, lỗi)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, _bad("timestamp", value)
    if not math.isfinite(value) or value <= 0:
        return None, f"timestamp ngoài khoảng hợp lệ: {_show(value)}"
    if value > time.time() + max_clock_skew:
        return None, f"timestamp ở tương lai: {_show(value)}"
    return float(value), None


def _check(event: dict, cfg: PreprocessConfig) -> tuple[list[tuple[str, str]], dict]:
    """Trả về (danh sách (mức, lý do), các giá trị đã chuẩn hóa).

    Mức là INVALID, PARTIAL hoặc _UNSUPPORTED.
    """
    issues = []
    norm = dict.fromkeys(NORM_FIELDS)

    _, error = _timestamp(event.get("timestamp"), cfg.max_clock_skew)
    if error:
        issues.append((INVALID, error))

    malformed = bool(event.get("malformed"))
    network = norm["network"] = _protocol(event.get("network"), NETWORKS)
    if network is None:
        issues.append((INVALID, _bad("network", event.get("network"))))
    elif network == UNKNOWN:
        if malformed:
            # Bài 1 không đọc được cả header lớp 2: không có gì để phân tích tiếp
            issues.append((INVALID, "không đọc được tầng mạng"))
        else:
            name = event.get("ethertype_name") or "không rõ"
            issues.append((_UNSUPPORTED, f"giao thức mạng không hỗ trợ: {name}"))
    else:
        for field in ("src_ip", "dst_ip"):
            ip, note = _ip(event.get(field))
            norm[field] = ip
            if ip is None:
                issues.append((INVALID, _bad(field, event.get(field))))
            elif note:
                issues.append((PARTIAL, f"{field}: {note}"))

        transport = norm["transport"] = _protocol(event.get("transport"), TRANSPORTS, IP_PROTO_NAMES)
        if transport is None:
            issues.append((INVALID, _bad("transport", event.get("transport"))))
        elif transport not in SUPPORTED_TRANSPORTS:
            issues.append((_UNSUPPORTED, f"giao thức tầng 4 không hỗ trợ: {transport}"))
        else:
            for field in ("src_port", "dst_port"):
                norm[field] = _port(event.get(field))
                if norm[field] is None:
                    issues.append((INVALID, _bad(field, event.get(field))))

    app = event.get("app_protocol")
    norm["app_protocol"] = _protocol(app, APPS)
    if app is not None and norm["app_protocol"] is None:
        issues.append((PARTIAL, f"app_protocol không nhận ra: {_show(app)}"))
    norm["domain"] = _event_domain(event)

    if malformed:
        errors = event.get("errors") or []
        detail = "; ".join(map(str, errors)) if isinstance(errors, list) else str(errors)
        issues.append((PARTIAL, f"Bài 1 báo gói hỏng: {detail}" if detail else "Bài 1 báo gói hỏng"))
    if event.get("truncated"):
        issues.append((PARTIAL, "gói bị cắt, thiếu phần cuối"))
    return issues, norm


def preprocess_event(event: Any, cfg: PreprocessConfig | None = None) -> dict:
    """Kiểm tra và chuẩn hóa một event, thêm preprocess_status, reason và norm.

    Trả về chính event đó. Không ném lỗi.
    """
    cfg = cfg or PreprocessConfig()
    if not isinstance(event, dict):
        event = {"raw_event": event}      # Ví dụ một dòng JSON Lines là số hay danh sách
    try:
        issues, norm = _check(event, cfg)
    except Exception as exc:
        issues = [(INVALID, f"lỗi nội bộ khi kiểm tra: {type(exc).__name__}: {exc}")]
        norm = dict.fromkeys(NORM_FIELDS)

    levels = {level for level, _ in issues}
    event["preprocess_status"] = INVALID if INVALID in levels else PARTIAL if levels else VALID
    event["reason"] = [message for _, message in issues]
    event["norm"] = norm
    return event
