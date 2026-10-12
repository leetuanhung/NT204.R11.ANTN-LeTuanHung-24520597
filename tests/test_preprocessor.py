"""Unit test cho ids/preprocessor.py (kiểm tra, chuẩn hóa event và chính sách bỏ qua).

Chạy:  python -m unittest -v tests.test_preprocessor
"""

import glob
import random
import time
import unittest

from ids.decoder import decode_event
from ids.output import read_jsonl
from ids.preprocessor import (ACCEPT, INVALID, MARK, NORM_FIELDS, PARTIAL, SKIP, VALID,
                              PreprocessConfig, _uri_path, preprocess_event)

BASE = {"packet_id": 1, "timestamp": 1790400000.0, "time": "2026-09-26T05:20:00+00:00",
        "source": "test", "frame_len": 60,
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000, "dst_port": 80,
        "network": "IPv4", "transport": "TCP", "app_protocol": "HTTP", "app_detected_by": "payload+port",
        "malformed": False, "truncated": False, "errors": []}


def run(cfg: PreprocessConfig | None = None, **changes) -> dict:
    return preprocess_event({**BASE, **changes}, cfg)


def case_events(number: str) -> list[dict]:
    """Event thật do main.py của Bài 1 ghi ra cho test case <number>."""
    return list(read_jsonl(glob.glob(f"TEST/cases/{number}_*/output.jsonl")[0]))


class ValidationTest(unittest.TestCase):
    def test_complete_event_is_valid(self):
        event = run()
        self.assertEqual((event["preprocess_status"], event["reason"]), (VALID, []))

    def test_bad_ports(self):
        for value in (70000, -1, True, "http", 80.5):
            with self.subTest(value=value):
                event = run(dst_port=value)
                self.assertEqual(event["preprocess_status"], INVALID)
                self.assertIn("dst_port không hợp lệ", event["reason"][0])

    def test_missing_vs_wrong_field(self):
        self.assertEqual(run(src_ip=None)["reason"], ["thiếu src_ip"])
        self.assertEqual(run(src_ip="999.1.1.1")["reason"], ["src_ip không hợp lệ: '999.1.1.1'"])

    def test_bad_timestamps(self):
        for value in ("hom qua", float("nan"), float("inf"), 0, -5, True, 10**400,
                      time.time() + 10**7):
            with self.subTest(value=value):
                self.assertEqual(run(timestamp=value)["preprocess_status"], INVALID)
        # Thiếu cả timestamp lẫn time thì không còn cách nào biết thời điểm
        self.assertEqual(run(timestamp=None, time=None)["reason"], ["thiếu timestamp"])

    def test_clock_skew_configurable(self):
        future = time.time() + 3600
        self.assertEqual(run(timestamp=future)["preprocess_status"], VALID)
        self.assertEqual(run(PreprocessConfig(max_clock_skew=60), timestamp=future)["preprocess_status"],
                         INVALID)

    def test_unknown_network_name(self):
        self.assertEqual(run(network="IPX")["preprocess_status"], INVALID)

    def test_unknown_app_protocol(self):
        event = run(app_protocol="QUIC")
        self.assertEqual(event["preprocess_status"], PARTIAL)
        self.assertIsNone(event["norm"]["app_protocol"])

    def test_no_payload_app_protocol_none_is_valid(self):
        # Gói SYN/ACK không có payload: Bài 1 ghi app_protocol = None, không phải lỗi
        self.assertEqual(run(app_protocol=None, app_detected_by=None)["preprocess_status"], VALID)

    def test_unsupported_protocols_from_assignment_1(self):
        statuses = [(e["network"], e["transport"], preprocess_event(e)["preprocess_status"])
                    for e in case_events("11")]
        self.assertEqual(statuses[:4], [("UNKNOWN", None, PARTIAL), ("UNKNOWN", None, PARTIAL),
                                        ("UNKNOWN", None, PARTIAL), ("IPv4", "ICMP", PARTIAL)])
        self.assertEqual([s for _, _, s in statuses[4:]], [VALID, VALID])

    def test_malformed_events_from_assignment_1(self):
        events = [preprocess_event(e) for e in case_events("12")]
        # Hỏng ở tầng 2-4: không còn đủ 5-tuple -> invalid
        self.assertEqual([e["preprocess_status"] for e in events[:5]], [INVALID] * 5)
        # DNS hỏng nhưng 5-tuple đủ -> partial
        self.assertEqual([e["preprocess_status"] for e in events[5:7]], [PARTIAL, PARTIAL])
        self.assertTrue(events[5]["reason"][0].startswith("Bài 1 báo gói hỏng: DNS"))
        # Gói bị cắt cụt trong file
        self.assertIn("gói bị cắt, thiếu phần cuối", events[8]["reason"])

    def test_long_bad_value_shortened(self):
        reason = run(src_ip="A" * 10**6)["reason"][0]
        self.assertLess(len(reason), 100)
        self.assertTrue(reason.endswith("..."))


class NormalizationTest(unittest.TestCase):
    def test_same_meaning_same_norm(self):
        """T05: cùng một nội dung, nhiều cách viết -> norm giống nhau."""
        variants = [
            {"http": {"host": "www.example.com"}},
            {"network": "ipv4", "transport": "tcp", "app_protocol": "http",
             "http": {"host": "WWW.Example.COM."}},
            {"network": " IPV4 ", "transport": 6, "app_protocol": "Http", "src_port": "40000",
             "dst_port": " 80", "http": {"host": "www.EXAMPLE.com:80"}},
            {"timestamp": "2026-09-26T12:20:00+07:00", "dst_ip": "::ffff:10.0.0.2",
             "http": {"host": " www.example.com "}},
        ]
        norms = [run(**v)["norm"] for v in variants]
        for norm in norms[1:]:
            self.assertEqual(norm, norms[0])
        self.assertEqual(norms[0]["domain"], "www.example.com")

    def test_ip_forms(self):
        self.assertEqual(run(src_ip="2001:DB8:0:0::1")["norm"]["src_ip"], "2001:db8::1")
        self.assertEqual(run(src_ip="::ffff:10.0.0.1")["norm"]["src_ip"], "10.0.0.1")
        event = run(src_ip="010.000.000.001")
        self.assertEqual((event["norm"]["src_ip"], event["preprocess_status"]), ("10.0.0.1", PARTIAL))

    def test_protocol_number(self):
        self.assertEqual(run(transport=17)["norm"]["transport"], "UDP")

    def test_domain_from_host(self):
        for host, domain in (("Example.COM:8080", "example.com"), ("1.2.3.4:80", None),
                             ("[::1]:80", None), (42, None)):
            with self.subTest(host=host):
                self.assertEqual(run(http={"host": host})["norm"]["domain"], domain)

    def test_domain_from_dns(self):
        self.assertEqual(run(app_protocol="DNS", dns={"qry": [{"name": "Mail.Example.org."}]})
                         ["norm"]["domain"], "mail.example.org")
        self.assertEqual(run(dns={"qry": [{"name": "<Root>"}]})["norm"]["domain"], ".")
        self.assertIsNone(run(dns={"qry": "x"})["norm"]["domain"])

    def test_uri_path(self):
        cases = {
            "/index.html": "/index.html",
            "/a//b/./c/../d?x=1": "/a/b/d",
            "/../../etc/passwd": "/etc/passwd",      # Không vượt lên trên thư mục gốc
            "/a/b/..": "/a/",
            "/Admin/Panel": "/Admin/Panel",           # Không đổi hoa/thường
            "/a#frag": "/a",
            "http://proxy.example/x/../y?q": "/y",
            "*": None,
            "example.com:443": None,
        }
        for uri, path in cases.items():
            with self.subTest(uri=uri):
                self.assertEqual(_uri_path(uri), path)

    def test_encoded_traversal_normalized(self):
        event = {**BASE, "http": {"request": {"method": "GET", "uri": "/img/%2e%2e/%2e%2e/etc/passwd",
                                              "version": "HTTP/1.1"}}}
        self.assertEqual(preprocess_event(dict(event))["norm"]["uri_path"], "/etc/passwd")
        decode_event(event)                       # Có decoded.uri thì dùng luôn
        self.assertEqual(preprocess_event(event)["norm"]["uri_path"], "/etc/passwd")
        self.assertEqual(event["http"]["request"]["uri"], "/img/%2e%2e/%2e%2e/etc/passwd")

    def test_http_header_names(self):
        headers = run(http={"headers": {"Host": "x", " User-Agent ": "curl"}})["norm"]["http_headers"]
        self.assertEqual(headers, {"host": "x", "user-agent": "curl"})

    def test_timestamp_forms(self):
        for value in (1790400000, "1790400000", " 1790400000.000 ", "2026-09-26T05:20:00Z",
                      "2026-09-26T12:20:00+07:00"):
            with self.subTest(value=value):
                event = run(timestamp=value)
                self.assertEqual(event["preprocess_status"], VALID)
                self.assertEqual((event["norm"]["timestamp"], event["norm"]["time"]),
                                 (1790400000.0, "2026-09-26T05:20:00+00:00"))

    def test_timestamp_without_timezone(self):
        event = run(timestamp="2026-09-26T05:20:00")
        self.assertEqual((event["norm"]["timestamp"], event["preprocess_status"]), (1790400000.0, PARTIAL))

    def test_timestamp_from_time_field(self):
        event = run(timestamp=None)
        self.assertEqual(event["norm"]["timestamp"], 1790400000.0)
        self.assertEqual(event["reason"], ["thiếu timestamp, lấy từ trường time"])

    def test_assignment_1_events_unchanged_in_norm(self):
        for number in ("01", "04", "08", "10"):
            for event in case_events(number):
                original = dict(event)
                preprocess_event(event)
                with self.subTest(case=number, packet=event["packet_id"]):
                    self.assertEqual(event["preprocess_status"], VALID)
                    for field in ("timestamp", "time", "src_ip", "dst_ip", "src_port", "dst_port",
                                  "network", "transport", "app_protocol"):
                        self.assertEqual(event["norm"][field], original[field])
                    self.assertEqual({k: event[k] for k in original}, original)  # Không ghi đè gốc


class MissingDataTest(unittest.TestCase):
    def test_optional_fields_filled(self):
        """T06: thiếu trường không bắt buộc -> null/[] nhất quán, không exception."""
        event = {k: BASE[k] for k in ("timestamp", "network", "src_ip", "dst_ip", "transport",
                                      "src_port", "dst_port")}
        preprocess_event(event)
        for field in ("packet_id", "time", "source", "frame_len", "app_protocol", "app_detected_by"):
            self.assertIsNone(event[field])
        self.assertEqual((event["malformed"], event["truncated"], event["errors"]), (False, False, []))
        self.assertEqual(event["preprocess_status"], PARTIAL)
        self.assertTrue(event["reason"][0].startswith("thiếu trường không bắt buộc"))

    def test_defaults_not_shared_between_events(self):
        first, second = preprocess_event({}), preprocess_event({})
        first["errors"].append("x")
        self.assertEqual(second["errors"], [])

    def test_errors_not_a_list(self):
        event = run(malformed=True, errors="hỏng")
        self.assertEqual(event["errors"], ["hỏng"])

    def test_norm_always_has_every_key(self):
        for event in ({}, {"network": "UNKNOWN"}, BASE, "abc", 5, None, [1, 2]):
            with self.subTest(event=event):
                self.assertEqual(tuple(preprocess_event(event)["norm"]), NORM_FIELDS)

    def test_non_dict_input(self):
        event = preprocess_event([1, 2])
        self.assertEqual((event["raw_event"], event["preprocess_status"]), ([1, 2], INVALID))


class ActionTest(unittest.TestCase):
    def test_default_actions(self):
        self.assertEqual(run()["processing_action"], ACCEPT)
        self.assertEqual(run(truncated=True)["processing_action"], MARK)
        self.assertEqual(run(src_port=None)["processing_action"], MARK)

    def test_skip_invalid(self):
        cfg = PreprocessConfig(skip_invalid=True)
        self.assertEqual(run(cfg, src_port=None)["processing_action"], SKIP)
        self.assertEqual(run(cfg, truncated=True)["processing_action"], MARK)

    def test_skip_unsupported(self):
        cfg = PreprocessConfig(skip_unsupported=True)
        arp = {**BASE, "network": "UNKNOWN", "ethertype_name": "ARP", "src_ip": None, "dst_ip": None,
               "transport": None, "src_port": None, "dst_port": None, "app_protocol": None}
        self.assertEqual(preprocess_event(arp, cfg)["processing_action"], SKIP)
        self.assertEqual(run(cfg, transport="ICMP", src_port=None, dst_port=None)["processing_action"], SKIP)
        self.assertEqual(run(cfg, src_port=None)["processing_action"], MARK)   # Invalid, không phải unsupported
        self.assertEqual(preprocess_event(arp)["processing_action"], MARK)


class RobustnessTest(unittest.TestCase):
    VALUES = [None, True, 0, -1, 1.5, float("nan"), 10**30, "", "x", "TCP", "1.2.3.4", "80",
              [], [1], {}, {"a": 1}, "2026-09-26T05:20:00Z"]

    def test_random_events_never_raise(self):
        rng = random.Random(4)
        keys = list(BASE) + ["http", "dns", "decoded", "ethertype_name"]
        for _ in range(3000):
            event = {k: rng.choice(self.VALUES) for k in rng.sample(keys, rng.randrange(len(keys)))}
            result = preprocess_event(event)
            self.assertIn(result["preprocess_status"], (VALID, PARTIAL, INVALID))
            self.assertIn(result["processing_action"], (ACCEPT, MARK, SKIP))
            self.assertNotIn("lỗi nội bộ", " ".join(result["reason"]))

    def test_all_assignment_1_cases(self):
        for path in sorted(glob.glob("TEST/cases/*/output.jsonl")):
            for event in read_jsonl(path):
                result = preprocess_event(event)
                with self.subTest(path=path, packet=event["packet_id"]):
                    self.assertNotIn("lỗi nội bộ", " ".join(result["reason"]))


if __name__ == "__main__":
    unittest.main()
