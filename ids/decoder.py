"""Decoder: đưa dữ liệu đã mã hóa/biểu diễn khác đi về dạng đọc được (mục 3 của đề).

Nguyên tắc: KHÔNG đổi ý nghĩa logic và KHÔNG ghi đè dữ liệu gốc. Kết quả đặt riêng trong
nhóm "decoded" của event, các trường của Bài 1 giữ nguyên để còn đối chiếu.

Mỗi mục giải mã kèm trạng thái:
    ok       giải mã trọn vẹn
    partial  có phần không đọc được (byte hỏng, mã % sai, bị cắt vì quá dài)
    error    không giải mã được
"""

import re
import urllib.parse
from typing import Any, NamedTuple

MAX_DECODED = 4096          # Số ký tự tối đa của một mục đã giải mã

OK, PARTIAL, ERROR = "ok", "partial", "error"

REPLACEMENT = "�"      # Ký tự U+FFFD mà bộ giải mã chèn vào chỗ byte hỏng

# Dấu % không theo sau bởi 2 chữ số hex: không phải percent-encoding hợp lệ
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


class Decoded(NamedTuple):
    value: Any
    status: str                 # OK, PARTIAL hoặc ERROR
    reason: str | None = None   # Lý do khi không phải OK


def _to_bytes(text: str) -> bytes:
    """Lấy lại byte gốc. Parser HTTP của Bài 1 decode header bằng latin-1 (1 byte -> 1 ký tự),
    nên encode ngược bằng latin-1 cho ra đúng byte ban đầu."""
    return text.encode("latin-1", "replace")


def percent_decode(text: str, max_len: int = MAX_DECODED) -> Decoded:
    """Giải percent-encoding: %27%20OR%201%3D1 -> ' OR 1=1

    Mã % sai được giữ nguyên thay vì bỏ đi, vì bỏ đi là đổi ý nghĩa dữ liệu.
    """
    reasons = []
    if _BAD_PERCENT.search(text):
        reasons.append("có dấu % không phải mã hợp lệ, giữ nguyên")

    value = urllib.parse.unquote_to_bytes(_to_bytes(text)).decode("utf-8", "replace")
    if REPLACEMENT in value and REPLACEMENT not in text:
        reasons.append("byte không hợp lệ UTF-8, đã thay bằng ký tự thay thế")
    if len(value) > max_len:
        value = value[:max_len]
        reasons.append(f"cắt còn {max_len} ký tự")

    return Decoded(value, PARTIAL if reasons else OK, "; ".join(reasons) or None)


def decode_form(body: str, max_len: int = MAX_DECODED) -> Decoded:
    """Giải application/x-www-form-urlencoded -> {tên: [giá trị]}.

    Giữ dạng danh sách vì một tên có thể xuất hiện nhiều lần (a=1&a=2), và tham số trùng tên
    là một kỹ thuật né bộ lọc (HTTP parameter pollution).
    """
    reasons = []
    if len(body) > max_len:
        body = body[:max_len]
        reasons.append(f"cắt còn {max_len} ký tự")
    if _BAD_PERCENT.search(body):
        reasons.append("có dấu % không phải mã hợp lệ, giữ nguyên")

    try:
        fields = urllib.parse.parse_qs(body, keep_blank_values=True, errors="replace")
    except ValueError as exc:
        return Decoded({}, ERROR, str(exc))

    if REPLACEMENT not in body and any(
            REPLACEMENT in name or any(REPLACEMENT in v for v in values)
            for name, values in fields.items()):
        reasons.append("byte không hợp lệ UTF-8, đã thay bằng ký tự thay thế")

    return Decoded(fields, PARTIAL if reasons else OK, "; ".join(reasons) or None)


def _put(out: dict, name: str, result: Decoded) -> None:
    """Ghi một mục đã giải mã kèm trạng thái: <name>, <name>_status, <name>_reason."""
    out[name] = result.value
    out[f"{name}_status"] = result.status
    if result.reason:
        out[f"{name}_reason"] = result.reason


def decode_http(http: dict, max_len: int = MAX_DECODED) -> dict:
    """Nhóm "decoded" cho một event HTTP."""
    out: dict = {}

    request = http.get("request")
    if request:
        _put(out, "uri", percent_decode(request["uri"], max_len))
        _, sep, query = request["uri"].partition("?")
        if sep:
            _put(out, "query", decode_form(query, max_len))

    body = http.get("file_data")
    if body and FORM_CONTENT_TYPE in http.get("content_type", "").lower():
        _put(out, "form", decode_form(body, max_len))

    return out


def decode_event(event: dict, max_len: int = MAX_DECODED) -> None:
    """Thêm nhóm "decoded" vào event. Không bao giờ ném lỗi (mục 2 của đề)."""
    try:
        if "http" in event:
            decoded = decode_http(event["http"], max_len)
            if decoded:
                event["decoded"] = decoded
    except Exception as exc:
        event["decoded"] = {"status": ERROR, "reason": f"{type(exc).__name__}: {exc}"}
