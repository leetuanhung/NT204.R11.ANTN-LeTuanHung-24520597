"""Decoder: đưa dữ liệu đã mã hóa/biểu diễn khác đi về dạng đọc được (mục 3 của đề).

Nguyên tắc: KHÔNG đổi ý nghĩa logic và KHÔNG ghi đè dữ liệu gốc. Kết quả đặt riêng trong
nhóm "decoded" của event, các trường của Bài 1 giữ nguyên để còn đối chiếu.

Mỗi mục giải mã kèm trạng thái:
    ok       giải mã trọn vẹn
    partial  có phần không đọc được (byte hỏng, mã % sai, bị cắt vì quá dài)
    error    không giải mã được
"""

import codecs
import re
import urllib.parse
from typing import Any, NamedTuple

MAX_DECODED = 4096          # Số ký tự tối đa của một mục đã giải mã

OK, PARTIAL, ERROR = "ok", "partial", "error"

REPLACEMENT = "�"      # Ký tự U+FFFD mà bộ giải mã chèn vào chỗ byte hỏng

# Dấu % không theo sau bởi 2 chữ số hex: không phải percent-encoding hợp lệ
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

# Giao thức dạng chữ: payload của chúng nên là văn bản, đáng kiểm tra bảng mã.
# DNS là giao thức nhị phân nên không giải mã payload thành chữ.
TEXT_PROTOCOLS = {"HTTP", "SMTP"}


class Decoded(NamedTuple):
    value: Any
    status: str                 # OK, PARTIAL hoặc ERROR
    reason: str | None = None   # Lý do khi không phải OK


def _to_bytes(text: str) -> bytes:
    """Lấy lại byte gốc. Parser HTTP của Bài 1 decode header bằng latin-1 (1 byte -> 1 ký tự),
    nên encode ngược bằng latin-1 cho ra đúng byte ban đầu."""
    return text.encode("latin-1", "replace")


def _result(value: Any, reasons: list[str]) -> Decoded:
    return Decoded(value, PARTIAL if reasons else OK, "; ".join(reasons) or None)


def decode_text(data: bytes, charset: str = "utf-8", max_len: int = MAX_DECODED,
                complete: bool = True) -> Decoded:
    """Byte -> chuỗi theo bảng mã. Mặc định UTF-8; ASCII là tập con của UTF-8 nên cũng đọc được.

    Không bao giờ ném lỗi: byte hỏng được thay bằng U+FFFD, đánh dấu partial và ghi vị trí byte
    hỏng đầu tiên. complete=False khi dữ liệu đã bị cắt: chuỗi byte UTF-8 dở dang ở cuối là do
    bị cắt chứ không phải byte hỏng, nên bỏ qua thay vì báo lỗi.
    """
    reasons = []
    try:
        info = codecs.lookup(charset)
    except LookupError:
        info = None
    # Nhãn charset trong thư do người gửi tự ghi, có thể là "base64", "zlib" hay "rot13":
    # codecs nhận các tên đó nhưng chúng không phải bảng mã văn bản, kết quả không phải chuỗi.
    # bytes.decode cũng kiểm tra đúng cờ này, nhưng bỏ qua khi đầu vào rỗng nên không dùng thay được.
    if info is None or not getattr(info, "_is_text_encoding", True):
        codec = "utf-8"
        reasons.append(f"không biết bảng mã {charset!r}, dùng utf-8")
    else:
        codec = info.name

    try:
        value = codecs.getincrementaldecoder(codec)().decode(data, final=complete)
    except UnicodeDecodeError as exc:
        value = codecs.getincrementaldecoder(codec)("replace").decode(data, final=complete)
        reasons.append(f"byte không hợp lệ {codec} tại vị trí {exc.start}")

    if len(value) > max_len:
        value = value[:max_len]
        reasons.append(f"cắt còn {max_len} ký tự")
    return _result(value, reasons)


def percent_decode(text: str, max_len: int = MAX_DECODED) -> Decoded:
    """Giải percent-encoding: %27%20OR%201%3D1 -> ' OR 1=1

    Mã % sai được giữ nguyên thay vì bỏ đi, vì bỏ đi là đổi ý nghĩa dữ liệu.
    """
    reasons = []
    if _BAD_PERCENT.search(text):
        reasons.append("có dấu % không phải mã hợp lệ, giữ nguyên")

    text_result = decode_text(urllib.parse.unquote_to_bytes(_to_bytes(text)), max_len=max_len)
    if text_result.reason:
        reasons.append(text_result.reason)
    return _result(text_result.value, reasons)


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

    return _result(fields, reasons)


def decode_payload(payload_hex: str, truncated: bool = False,
                   max_len: int = MAX_DECODED) -> tuple[Decoded, str | None]:
    """Payload tầng transport (Bài 1 ghi dạng hex) -> (chuỗi, bảng mã nhận ra được).

    Bảng mã: "ascii" (mọi byte < 0x80), "utf-8" (UTF-8 hợp lệ), "binary" (không phải văn bản
    hợp lệ). Bài 1 chỉ ghi tối đa --max-payload byte đầu; khi đó truncated=True.
    """
    try:
        data = bytes.fromhex(payload_hex)
    except ValueError as exc:
        return Decoded("", ERROR, f"payload hex không hợp lệ: {exc}"), None

    result = decode_text(data, max_len=max_len, complete=not truncated)
    if data.isascii():
        charset = "ascii"
    else:
        charset = "utf-8" if result.status == OK else "binary"
    if truncated:
        reasons = [result.reason] if result.reason else []
        reasons.append(f"chỉ có {len(data)} byte đầu của payload")
        result = _result(result.value, reasons)
    return result, charset


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
        out: dict = {}
        if "http" in event:
            out.update(decode_http(event["http"], max_len))

        layer = event.get("tcp") or event.get("udp")
        if event.get("app_protocol") in TEXT_PROTOCOLS and layer and layer.get("payload"):
            # Payload bị xóa vì chứa mật khẩu (payload_redacted) thì rỗng, không vào đây
            result, charset = decode_payload(layer["payload"], layer.get("payload_truncated", False),
                                             max_len)
            _put(out, "payload", result)
            out["payload_charset"] = charset

        if out:
            event["decoded"] = out
    except Exception as exc:
        event["decoded"] = {"status": ERROR, "reason": f"{type(exc).__name__}: {exc}"}
