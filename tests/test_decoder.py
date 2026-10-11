"""Unit test cho ids/decoder.py (giải mã URL, form, HTML entity, MIME, bảng mã).

Chạy:  python -m unittest -v tests.test_decoder
"""

import base64
import random
import unittest

from scapy.all import IP, TCP, Ether

from ids.capture import RawPacket
from ids.decoder import (ERROR, OK, PARTIAL, decode_event, decode_form, decode_mail_headers,
                         decode_mime, decode_mime_header, decode_payload, decode_text,
                         html_unescape, percent_decode)
from ids.parsers.http import parse_http
from ids.parsers.smtp import parse_smtp
from ids.pipeline import Pipeline


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def http_event(raw: bytes, dport: int = 80) -> dict:
    """Chạy gói HTTP qua pipeline thật của Bài 1 rồi qua decoder."""
    # Ghi sẵn MAC: Ether() để trống thì Scapy gửi ARP để tìm MAC đích
    pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2")
           / TCP(sport=40000, dport=dport, flags="PA") / raw)
    event = Pipeline().process(RawPacket(1.0, bytes(pkt), 1, "test"))
    decode_event(event)
    return event


class PercentDecodeTest(unittest.TestCase):
    def test_example_from_assignment(self):
        self.assertEqual(percent_decode("%27%20OR%201%3D1"), ("' OR 1=1", OK, None))

    def test_utf8_multibyte(self):
        self.assertEqual(percent_decode("/t%C3%A9st").value, "/tést")

    def test_encoded_slash(self):
        self.assertEqual(percent_decode("/a%2fb").value, "/a/b")

    def test_plus_is_not_space_in_path(self):
        # Dấu + chỉ là dấu cách trong form, trong path là chữ + thật
        self.assertEqual(percent_decode("/a+b").value, "/a+b")

    def test_bad_percent_kept(self):
        for text in ("/100%", "/x%zz", "/%4"):
            with self.subTest(text=text):
                result = percent_decode(text)
                self.assertEqual(result.value, text)
                self.assertEqual(result.status, PARTIAL)

    def test_invalid_utf8_marked(self):
        result = percent_decode("/bad%C3%28")
        self.assertEqual(result.value, "/bad\ufffd(")
        self.assertEqual(result.status, PARTIAL)
        self.assertIn("vị trí 4", result.reason)

    def test_truncated(self):
        result = percent_decode("A" * 50, max_len=10)
        self.assertEqual(result.value, "A" * 10)
        self.assertEqual(result.status, PARTIAL)


class FormDecodeTest(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(decode_form("user=admin&pass=12%33").value,
                         {"user": ["admin"], "pass": ["123"]})

    def test_plus_is_space(self):
        self.assertEqual(decode_form("q=%27+OR+1%3D1").value, {"q": ["' OR 1=1"]})

    def test_duplicate_names_kept(self):
        # HTTP parameter pollution: phải giữ đủ cả hai giá trị
        self.assertEqual(decode_form("a=1&a=2").value, {"a": ["1", "2"]})

    def test_blank_values_kept(self):
        self.assertEqual(decode_form("blank=&x").value, {"blank": [""], "x": [""]})

    def test_invalid_utf8_marked(self):
        result = decode_form("a=%FF")
        self.assertEqual(result.value, {"a": ["\ufffd"]})
        self.assertEqual(result.status, PARTIAL)


class DecodeTextTest(unittest.TestCase):
    def test_ascii_and_utf8(self):
        self.assertEqual(decode_text(b"hello"), ("hello", OK, None))
        self.assertEqual(decode_text("xin chào".encode()).value, "xin chào")

    def test_invalid_bytes_do_not_crash(self):
        result = decode_text(b"ab\xffcd\xfe")
        self.assertEqual(result.value, "ab\ufffdcd\ufffd")
        self.assertEqual(result.status, PARTIAL)
        self.assertIn("vị trí 2", result.reason)

    def test_incomplete_tail_when_cut(self):
        # Dữ liệu bị cắt giữa ký tự nhiều byte: không phải byte hỏng
        self.assertEqual(decode_text(b"ok\xc3", complete=False), ("ok", OK, None))
        self.assertEqual(decode_text(b"ok\xc3").status, PARTIAL)

    def test_other_charset(self):
        self.assertEqual(decode_text("café".encode("latin-1"), "iso-8859-1").value, "café")

    def test_non_text_codecs_rejected(self):
        # Nhãn charset do người gửi tự ghi: không được dùng codec biến byte thành byte
        for charset in ("base64", "zlib", "rot13", "hex", "khong-ton-tai", ""):
            with self.subTest(charset=charset):
                result = decode_text(b"x", charset)
                self.assertEqual(result.value, "x")
                self.assertEqual(result.status, PARTIAL)


class PayloadTest(unittest.TestCase):
    def test_charsets(self):
        self.assertEqual(decode_payload(b"GET /".hex())[1], "ascii")
        self.assertEqual(decode_payload("xin chào".encode().hex())[1], "utf-8")
        result, charset = decode_payload("1603030070ff")
        self.assertEqual((result.status, charset), (PARTIAL, "binary"))

    def test_truncated_payload(self):
        result, charset = decode_payload("41c3", truncated=True)
        self.assertEqual((result.value, result.status, charset), ("A", PARTIAL, "utf-8"))

    def test_charset_not_affected_by_length_limit(self):
        # UTF-8 hợp lệ nhưng dài hơn max_len: bị cắt (partial) nhưng vẫn là utf-8, không phải binary
        result, charset = decode_payload(("xin chào " * 10).encode().hex(), max_len=20)
        self.assertEqual((result.status, charset), (PARTIAL, "utf-8"))

    def test_bad_hex(self):
        result, charset = decode_payload("zz")
        self.assertEqual((result.status, charset), (ERROR, None))


class HtmlEntityTest(unittest.TestCase):
    def test_example_from_assignment(self):
        self.assertEqual(html_unescape("&lt;script&gt;"), ("<script>", OK, None))

    def test_numeric_and_hex(self):
        self.assertEqual(html_unescape("&#60;img&#62;").value, "<img>")
        self.assertEqual(html_unescape("&#x3c;svg&#x3E;").value, "<svg>")

    def test_without_semicolon(self):
        # Trình duyệt vẫn hiểu &lt không có dấu chấm phẩy, kẻ tấn công dùng để né bộ lọc
        self.assertEqual(html_unescape("&ltscript&gt").value, "<script>")

    def test_decode_only_once(self):
        # Giải một lớp, không giải tiếp: giải hai lần là đổi ý nghĩa dữ liệu
        self.assertEqual(html_unescape("&amp;lt;b&amp;gt;").value, "&lt;b&gt;")

    def test_unknown_entity_kept(self):
        self.assertEqual(html_unescape("&khongcoten; &").value, "&khongcoten; &")

    def test_invalid_code_point(self):
        for text in ("&#0;", "&#xFFFFFFFF;"):
            with self.subTest(text=text):
                result = html_unescape(text)
                self.assertEqual((result.value, result.status), ("\ufffd", PARTIAL))
                self.assertIsNotNone(result.reason)


class MimeBodyTest(unittest.TestCase):
    def test_base64(self):
        body, parts = decode_mime("Content-Type: text/plain; charset=utf-8\n"
                                  f"Content-Transfer-Encoding: base64\n\n{b64('Xin chào')}")
        self.assertEqual((body.value, body.status), ("Xin chào", OK))
        self.assertEqual(parts[0]["encoding"], "base64")
        self.assertEqual(parts[0]["decode_status"], OK)

    def test_quoted_printable_with_soft_break(self):
        body, _ = decode_mime("Content-Type: text/plain; charset=utf-8\n"
                              "Content-Transfer-Encoding: quoted-printable\n\n"
                              "Xin ch=C3=A0o, r=\nat dai =3D ok")
        self.assertEqual((body.value, body.status), ("Xin chào, rat dai = ok", OK))

    def test_bad_quoted_printable(self):
        body, parts = decode_mime("Content-Transfer-Encoding: quoted-printable\n\nloi =ZZ")
        self.assertEqual((body.value, body.status), ("loi =ZZ", PARTIAL))
        self.assertEqual(parts[0]["decode_status"], PARTIAL)

    def test_bad_base64(self):
        body, parts = decode_mime("Content-Transfer-Encoding: base64\n\nSGVsbG8@@@gd29y")
        self.assertEqual(body.status, PARTIAL)
        self.assertIn("InvalidBase64CharactersDefect", parts[0]["reason"])
        self.assertEqual(body.reason.count("InvalidBase64CharactersDefect"), 1)

    def test_8bit_utf8(self):
        body, _ = decode_mime("Content-Type: text/plain; charset=utf-8\n"
                              "Content-Transfer-Encoding: 8bit\n\nTiếng Việt")
        self.assertEqual((body.value, body.status), ("Tiếng Việt", OK))

    def test_unknown_encoding_kept(self):
        body, _ = decode_mime("Content-Transfer-Encoding: x-khong-co\n\nabc")
        self.assertEqual((body.value, body.status), ("abc", PARTIAL))

    def test_no_header_returns_none(self):
        # Gói ở giữa thư: không có header nên không biết encoding
        self.assertIsNone(decode_mime("SGVsbG8gd29ybGQ=\nZm9v"))

    def test_multipart_with_attachment(self):
        message = ("MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XYZ\n\n--XYZ\n"
                   "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n"
                   "Ph=E1=BA=A7n 1\n--XYZ\n"
                   "Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=x.exe\n"
                   "Content-Transfer-Encoding: base64\n\nTVqQAAMAAAAEAAAA\n--XYZ--")
        body, parts = decode_mime(message)
        self.assertEqual((body.value, body.status), ("Phần 1", OK))
        self.assertEqual([p["content_type"] for p in parts], ["text/plain", "application/octet-stream"])
        self.assertEqual(parts[1]["filename"], "x.exe")
        self.assertNotIn("charset", parts[1])

    def test_truncated_multipart(self):
        message = ("Content-Type: multipart/mixed; boundary=XYZ\n\n--XYZ\n"
                   "Content-Transfer-Encoding: base64\n\n" + b64("Hello world") + "\n--XYZ--")
        body, _ = decode_mime(message[:70], truncated=True)
        self.assertEqual(body.status, PARTIAL)
        self.assertIn("cắt bớt", body.reason)


class MimeHeaderTest(unittest.TestCase):
    def test_base64_and_q(self):
        self.assertEqual(decode_mime_header("=?UTF-8?B?SMOzYSDEkcahbg==?="), ("Hóa đơn", OK, None))
        self.assertEqual(decode_mime_header("=?utf-8?Q?H=C3=B3a_=C4=91=C6=A1n?=").value, "Hóa đơn")

    def test_space_between_words_dropped(self):
        value = f"Re: =?utf-8?B?{b64('Hóa ')}?= =?utf-8?B?{b64('đơn')}?="
        self.assertEqual(decode_mime_header(value).value, "Re: Hóa đơn")

    def test_unencoded_text_kept(self):
        value = f"Tiếng =?utf-8?B?{b64('Việt')}?= C:\\users"
        self.assertEqual(decode_mime_header(value).value, "Tiếng Việt C:\\users")

    def test_language_suffix(self):
        self.assertEqual(decode_mime_header(f"=?utf-8*vi?B?{b64('ngữ')}?=").value, "ngữ")

    def test_missing_padding(self):
        self.assertEqual(decode_mime_header("=?utf-8?B?SGVsbG8?=").value, "Hello")

    def test_bad_word_kept(self):
        self.assertEqual(decode_mime_header("=?utf-8?B?!!!?=").value, "=?utf-8?B?!!!?=")
        self.assertEqual(decode_mime_header("=?utf-8?B?!!!?=").status, PARTIAL)

    def test_mail_headers_status(self):
        result = decode_mail_headers({"subject": "=?utf-8?B?/w==?=", "to": "b@y.com"})
        self.assertEqual(result.value["to"], "b@y.com")
        self.assertEqual(result.status, PARTIAL)
        self.assertTrue(result.reason.startswith("subject:"))


class DecodeEventTest(unittest.TestCase):
    def test_http_request_raw_uri_kept(self):
        event = http_event(b"GET /s?q=%27%20OR%201%3D1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(event["decoded"]["uri"], "/s?q=' OR 1=1")
        self.assertEqual(event["decoded"]["query"], {"q": ["' OR 1=1"]})
        self.assertEqual(event["http"]["request"]["uri"], "/s?q=%27%20OR%201%3D1")

    def test_http_form_body(self):
        body = b"user=admin&cmd=%3Bid"
        event = http_event(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded"
                           b"\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        self.assertEqual(event["decoded"]["form"], {"user": ["admin"], "cmd": [";id"]})

    def test_http_html_body(self):
        body = b"<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"
        event = http_event(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s"
                           % (len(body), body))
        self.assertEqual(event["decoded"]["body_text"], "<p><script>alert(1)</script></p>")

    def test_non_text_body_not_unescaped(self):
        body = b'{"x":"&lt;b&gt;"}'
        event = http_event(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d"
                           b"\r\n\r\n%s" % (len(body), body))
        self.assertNotIn("body_text", event["decoded"])

    def test_invalid_utf8_payload_marked(self):
        event = http_event(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: \xff\xfe\r\n\r\n")
        self.assertEqual(event["decoded"]["payload_status"], PARTIAL)
        self.assertEqual(event["decoded"]["payload_charset"], "binary")

    def test_redacted_payload_not_decoded(self):
        # Gói có mật khẩu đã bị xóa payload ở Bài 1, decoder không được làm lộ lại
        event = http_event(b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n", dport=25)
        self.assertNotIn("decoded", event)

    def test_smtp_mail(self):
        raw = ("Subject: =?utf-8?Q?T=C3=A0i_kho=E1=BA=A3n?=\r\nContent-Type: text/plain; charset=utf-8\r\n"
               f"Content-Transfer-Encoding: base64\r\n\r\n{b64('Mở file ngay')}\r\n.\r\n").encode()
        event = {"smtp": parse_smtp(raw)}
        decode_event(event)
        self.assertEqual(event["decoded"]["mail_body"], "Mở file ngay")
        self.assertEqual(event["decoded"]["mail_body_status"], OK)
        self.assertEqual(event["decoded"]["mail_headers"]["subject"], "Tài khoản")

    def test_event_without_app_data(self):
        event = {"packet_id": 1, "app_protocol": None}
        decode_event(event)
        self.assertNotIn("decoded", event)

    def test_broken_event_does_not_raise(self):
        # Event đọc từ file có thể sai kiểu dữ liệu; decoder vẫn không được ném lỗi
        event = {"http": {"request": {"uri": 123}}}
        decode_event(event)
        self.assertEqual(event["decoded"]["status"], ERROR)


class RobustnessTest(unittest.TestCase):
    def test_random_bytes_never_raise(self):
        rng = random.Random(2)
        for _ in range(2000):
            data = rng.randbytes(rng.randrange(0, 200))
            text = data.decode("latin-1")
            for func in (percent_decode, decode_form, html_unescape, decode_mime_header):
                self.assertIsInstance(func(text).status, str)
            self.assertIsInstance(decode_text(data).value, str)
            mime = decode_mime("Content-Transfer-Encoding: base64\n\n" + text)
            self.assertTrue(mime is None or isinstance(mime[0].value, str))
            decode_payload(data.hex())

    def test_http_parser_output_never_raises(self):
        rng = random.Random(3)
        for _ in range(500):
            payload = b"POST /" + rng.randbytes(rng.randrange(0, 120)) + b" HTTP/1.1\r\nContent-Type: text/html\r\n\r\n"
            event = {"http": parse_http(payload + rng.randbytes(50))}
            decode_event(event)
            self.assertNotEqual(event.get("decoded", {}).get("status"), ERROR)


if __name__ == "__main__":
    unittest.main()
