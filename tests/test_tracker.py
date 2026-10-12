"""Unit test cho ids/tracker.py (gom flow hai chiều, trạng thái TCP, timeout, thống kê).

Chạy:  python -m unittest -v tests.test_tracker
"""

import glob
import math
import random
import unittest

from ids.output import read_jsonl
from ids.preprocessor import preprocess_event
from ids.tracker import (BACKWARD, CLOSED, CONNECTION_CLOSED, END_OF_INPUT, ESTABLISHED, FORWARD,
                         HANDSHAKE, IDLE_TIMEOUT, NEW, PORT_REUSED, RESET, TABLE_FULL, FlowTracker,
                         TrackerConfig, flow_key, make_flow_id)

T0 = 1790400000.0
CLIENT, SERVER = ("10.0.0.1", 40000), ("10.0.0.2", 80)
DNS_CLIENT, DNS_SERVER = ("10.0.0.1", 53001), ("8.8.8.8", 53)


def event(t: float, src: tuple, dst: tuple, flags: str = "", proto: str = "TCP", size: int = 60,
          app: str | None = None) -> dict:
    """Event giống Bài 1 ghi ra, đã qua Preprocessor. flags: chuỗi gồm S, A, F, R, P."""
    tcp = {"flags": {"syn": "S" in flags, "ack": "A" in flags, "fin": "F" in flags,
                     "reset": "R" in flags, "push": "P" in flags}} if proto == "TCP" else None
    return preprocess_event({"timestamp": T0 + t, "network": "IPv4", "transport": proto,
                             "src_ip": src[0], "src_port": src[1], "dst_ip": dst[0], "dst_port": dst[1],
                             "tcp": tcp, "frame_len": size, "app_protocol": app})


def run(steps: list, cfg: TrackerConfig | None = None) -> tuple[FlowTracker, list[dict], list]:
    """Chạy lần lượt các event qua tracker. Trả về (tracker, event, flow đã kết thúc)."""
    tracker = FlowTracker(cfg)
    events, finished = [], []
    for step in steps:
        ev = event(*step) if isinstance(step, tuple) else step
        finished += tracker.process(ev)
        events.append(ev)
    return tracker, events, finished


def handshake(t: float = 0.0) -> list:
    return [(t, CLIENT, SERVER, "S"), (t + 0.1, SERVER, CLIENT, "SA"), (t + 0.2, CLIENT, SERVER, "A")]


class FlowKeyTest(unittest.TestCase):
    def test_both_directions_same_key(self):
        self.assertEqual(flow_key("TCP", CLIENT, SERVER), flow_key("TCP", SERVER, CLIENT))

    def test_numeric_ip_order(self):
        # 10.0.0.9 đứng trước 10.0.0.10 theo giá trị số, không theo thứ tự chữ
        key = flow_key("UDP", ("10.0.0.10", 1), ("10.0.0.9", 2))
        self.assertEqual(key, ("UDP", ("10.0.0.9", 2), ("10.0.0.10", 1)))

    def test_flow_id_format(self):
        key = flow_key("TCP", CLIENT, SERVER)
        self.assertEqual(make_flow_id(key, T0), "TCP-10.0.0.1:40000-10.0.0.2:80@1790400000.000000")
        key6 = flow_key("UDP", ("2001:db8::1", 53), ("2001:db8::2", 5000))
        self.assertEqual(make_flow_id(key6, T0), "UDP-[2001:db8::1]:53-[2001:db8::2]:5000@1790400000.000000")

    def test_bidirectional_same_flow(self):
        """T08: A->B và B->A cùng 5-tuple đảo chiều -> cùng flow_id, đúng direction."""
        tracker, events, _ = run(handshake())
        self.assertEqual(len({e["flow_id"] for e in events}), 1)
        self.assertEqual([e["flow_direction"] for e in events], [FORWARD, BACKWARD, FORWARD])
        self.assertEqual(len(tracker.flows), 1)

    def test_flow_id_stable_across_runs(self):
        ids_1 = [e["flow_id"] for e in run(handshake())[1]]
        ids_2 = [e["flow_id"] for e in run(handshake())[1]]
        self.assertEqual(ids_1, ids_2)

    def test_concurrent_flows_not_merged(self):
        """T11: các flow khác endpoint hoặc port không bị gộp nhầm."""
        other_port = ("10.0.0.1", 40001)
        other_host = ("10.0.0.3", 40000)
        steps = [(0, CLIENT, SERVER, "S"), (0.1, other_port, SERVER, "S"), (0.2, other_host, SERVER, "S"),
                 (0.3, SERVER, other_port, "SA"), (0.4, DNS_CLIENT, DNS_SERVER, "", "UDP"),
                 (0.5, ("10.0.0.1", 40000), ("10.0.0.2", 80), "", "UDP")]  # Cùng IP/port nhưng UDP
        tracker, events, _ = run(steps)
        self.assertEqual(len(tracker.flows), 5)
        self.assertEqual(events[1]["flow_id"], events[3]["flow_id"])
        self.assertEqual(len({e["flow_id"] for e in events}), 5)

    def test_events_without_flow(self):
        arp = preprocess_event({"timestamp": T0, "network": "UNKNOWN", "ethertype_name": "ARP"})
        icmp = preprocess_event({"timestamp": T0, "network": "IPv4", "transport": "ICMP",
                                 "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
        bad = preprocess_event({"timestamp": T0, "network": "IPv4", "transport": "TCP",
                                "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})          # Thiếu port
        tracker, events, _ = run([arp, icmp, bad])
        self.assertEqual([e["flow_id"] for e in events], [None, None, None])
        self.assertEqual(tracker.flows, {})


class InitiatorTest(unittest.TestCase):
    def test_first_packet_sender(self):
        flow = run([(0, CLIENT, SERVER, "S")])[0].flush()[0]
        self.assertEqual((flow.endpoint_a, flow.endpoint_b), (CLIENT, SERVER))

    def test_capture_starts_at_syn_ack(self):
        tracker, events, _ = run([(0, SERVER, CLIENT, "SA"), (0.1, CLIENT, SERVER, "A")])
        self.assertEqual(tracker.flush()[0].endpoint_a, CLIENT)
        self.assertEqual([e["flow_direction"] for e in events], [BACKWARD, FORWARD])

    def test_capture_starts_at_server_reply(self):
        # Gói đầu đi từ port dịch vụ 53 sang port tạm: client là phía đích
        flow = run([(0, DNS_SERVER, DNS_CLIENT, "", "UDP")])[0].flush()[0]
        self.assertEqual(flow.endpoint_a, DNS_CLIENT)


class TcpStateTest(unittest.TestCase):
    def states(self, steps: list) -> list:
        return [e["flow_state"] for e in run(steps)[1]]

    def test_three_way_handshake(self):
        """T07: SYN -> SYN/ACK -> ACK: 1 flow, ESTABLISHED."""
        tracker, events, _ = run(handshake())
        self.assertEqual([e["flow_state"] for e in events], [HANDSHAKE, HANDSHAKE, ESTABLISHED])
        self.assertEqual(len(tracker.flows), 1)

    def test_fin_close(self):
        """T09: FIN/ACK hai phía -> CLOSED; ACK cuối không mở lại kết nối."""
        steps = handshake() + [(1, CLIENT, SERVER, "FA"), (1.1, SERVER, CLIENT, "FA"), (1.2, CLIENT, SERVER, "A")]
        self.assertEqual(self.states(steps)[3:], ["CLOSING", CLOSED, CLOSED])

    def test_reset(self):
        """T09: RST -> RESET."""
        steps = handshake() + [(1, SERVER, CLIENT, "RA"), (1.1, CLIENT, SERVER, "A")]
        self.assertEqual(self.states(steps)[3:], [RESET, RESET])

    def test_scans(self):
        self.assertEqual(self.states([(0, CLIENT, SERVER, "S"), (0.1, SERVER, CLIENT, "SA"),
                                      (0.2, CLIENT, SERVER, "R")])[-1], RESET)     # SYN scan
        self.assertEqual(self.states([(0, CLIENT, SERVER, "S"), (0.1, SERVER, CLIENT, "RA")])[-1],
                         RESET)                                                   # Port đóng
        self.assertEqual(self.states([(0, CLIENT, SERVER, "")]), [NEW])           # NULL scan
        self.assertEqual(self.states([(0, CLIENT, SERVER, "F")]), ["CLOSING"])    # FIN scan

    def test_handshake_ack_must_come_from_client(self):
        # ACK của server trong lúc bắt tay không hoàn tất bắt tay
        steps = [(0, CLIENT, SERVER, "S"), (0.1, SERVER, CLIENT, "SA"), (0.2, SERVER, CLIENT, "A")]
        self.assertEqual(self.states(steps)[-1], HANDSHAKE)

    def test_midstream_capture(self):
        self.assertEqual(self.states([(0, CLIENT, SERVER, "PA"), (0.1, SERVER, CLIENT, "A")]),
                         [ESTABLISHED, ESTABLISHED])

    def test_port_reuse_starts_new_flow(self):
        steps = handshake() + [(1, CLIENT, SERVER, "FA"), (1.1, SERVER, CLIENT, "FA"),
                               (2, CLIENT, SERVER, "S")]
        _, events, finished = run(steps)
        self.assertNotEqual(events[0]["flow_id"], events[-1]["flow_id"])
        self.assertEqual([(f.end_reason, f.state, f.packet_count) for f in finished],
                         [(PORT_REUSED, CLOSED, 5)])
        self.assertEqual(events[-1]["flow_state"], HANDSHAKE)


class UdpTest(unittest.TestCase):
    def test_dns_query_response(self):
        """T10: DNS UDP hai chiều -> 1 flow, packet/byte count đúng."""
        steps = [(0, DNS_CLIENT, DNS_SERVER, "", "UDP", 74, "DNS"),
                 (0.02, DNS_SERVER, DNS_CLIENT, "", "UDP", 90, "DNS")]
        tracker, events, _ = run(steps)
        self.assertEqual(events[0]["flow_id"], events[1]["flow_id"])
        flow = tracker.flush()[0].to_dict()
        self.assertEqual((flow["packet_count"], flow["byte_count"]), (2, 164))
        self.assertEqual((flow["forward_packet_count"], flow["forward_byte_count"]), (1, 74))
        self.assertEqual((flow["backward_packet_count"], flow["backward_byte_count"]), (1, 90))
        self.assertEqual((flow["protocol"], flow["application_protocol"], flow["state"]), ("UDP", "DNS", None))

    def test_udp_has_no_tcp_counters(self):
        flow = run([(0, DNS_CLIENT, DNS_SERVER, "", "UDP")])[0].flush()[0].to_dict()
        self.assertEqual([flow[k] for k in ("SYN_count", "ACK_count", "FIN_count", "RST_count")],
                         [None] * 4)


class TimeoutTest(unittest.TestCase):
    def test_idle_timeout(self):
        """T12: flow không có gói mới quá timeout -> hết hạn và bị loại khỏi active table."""
        cfg = TrackerConfig(udp_timeout=10)
        tracker, _, finished = run([(0, DNS_CLIENT, DNS_SERVER, "", "UDP"),
                                    (5, DNS_SERVER, DNS_CLIENT, "", "UDP")], cfg)
        self.assertEqual((finished, len(tracker.flows)), ([], 1))
        late = tracker.process(event(16, DNS_CLIENT, DNS_SERVER, "", "UDP"))   # 11s sau gói cuối
        self.assertEqual([(f.end_reason, f.packet_count) for f in late], [(IDLE_TIMEOUT, 2)])
        self.assertEqual(len(tracker.flows), 1)                       # Gói muộn mở flow mới
        self.assertNotEqual(late[0].flow_id, next(iter(tracker.flows.values())).flow_id)

    def test_exactly_at_timeout_still_active(self):
        tracker, _, finished = run([(0, DNS_CLIENT, DNS_SERVER, "", "UDP"),
                                    (10, DNS_CLIENT, DNS_SERVER, "", "UDP")], TrackerConfig(udp_timeout=10))
        self.assertEqual((finished, len(tracker.flows)), ([], 1))

    def test_timeouts_per_protocol(self):
        tracker, _, _ = run(handshake() + [(0, DNS_CLIENT, DNS_SERVER, "", "UDP")])
        def clock(t: float) -> list:
            """Gói không thuộc flow nào, chỉ để đẩy đồng hồ tới thời điểm t."""
            done = tracker.process(preprocess_event({"timestamp": T0 + t, "network": "UNKNOWN"}))
            return [(f.protocol, f.end_reason) for f in done]

        self.assertEqual(clock(50), [])
        self.assertEqual(clock(61), [("UDP", IDLE_TIMEOUT)])      # UDP: 60 giây
        self.assertEqual(clock(200), [])
        self.assertEqual(clock(301), [("TCP", IDLE_TIMEOUT)])     # TCP: 300 giây
        self.assertEqual(tracker.flows, {})

    def test_closed_flow_kept_briefly(self):
        steps = handshake() + [(1, CLIENT, SERVER, "FA"), (1.1, SERVER, CLIENT, "FA"),
                               (5, CLIENT, SERVER, "A")]               # ACK cuối đến sau 4 giây
        tracker, events, finished = run(steps)
        self.assertEqual((finished, events[-1]["flow_state"]), ([], CLOSED))
        done = tracker.process(preprocess_event({"timestamp": T0 + 16, "network": "UNKNOWN"}))
        self.assertEqual([(f.end_reason, f.packet_count) for f in done], [(CONNECTION_CLOSED, 6)])

    def test_non_flow_packets_advance_clock(self):
        tracker, _, _ = run([(0, DNS_CLIENT, DNS_SERVER, "", "UDP")], TrackerConfig(udp_timeout=10))
        arp = preprocess_event({"timestamp": T0 + 60, "network": "UNKNOWN", "ethertype_name": "ARP"})
        self.assertEqual([f.end_reason for f in tracker.process(arp)], [IDLE_TIMEOUT])

    def test_late_packet_does_not_move_time_back(self):
        tracker, _, _ = run([(10, CLIENT, SERVER, "S"), (5, SERVER, CLIENT, "SA")])
        flow = tracker.flush()[0]
        self.assertEqual((flow.start_time, flow.last_seen), (T0 + 10, T0 + 10))

    def test_flush(self):
        tracker, _, _ = run(handshake() + [(0, DNS_CLIENT, DNS_SERVER, "", "UDP")])
        flows = tracker.flush()
        self.assertEqual(sorted(f.end_reason for f in flows), [END_OF_INPUT] * 2)
        self.assertEqual((tracker.flows, [len(q) for q in tracker._queues.values()]), ({}, [0, 0, 0]))


class TableLimitTest(unittest.TestCase):
    def test_least_recently_seen_evicted(self):
        cfg = TrackerConfig(max_flows=3)
        steps = [(i, ("10.0.0.1", 1000 + i), SERVER, "S") for i in range(3)]
        steps.append((3, ("10.0.0.1", 1000), SERVER, "A"))            # Flow 1000 vừa có gói
        tracker, _, finished = run(steps + [(4, ("10.0.0.1", 1003), SERVER, "S")], cfg)
        self.assertEqual([(f.endpoint_a[1], f.end_reason) for f in finished], [(1001, TABLE_FULL)])
        self.assertEqual(len(tracker.flows), 3)

    def test_eviction_across_queues(self):
        tracker, _, finished = run([(0, DNS_CLIENT, DNS_SERVER, "", "UDP"), (1, CLIENT, SERVER, "S"),
                                    (2, ("10.0.0.1", 40001), SERVER, "S")], TrackerConfig(max_flows=2))
        self.assertEqual([f.protocol for f in finished], ["UDP"])

    def test_zero_limit_does_not_hang(self):
        tracker, _, _ = run([(0, CLIENT, SERVER, "S"), (1, ("10.0.0.1", 1), SERVER, "S")],
                            TrackerConfig(max_flows=0))
        self.assertEqual(len(tracker.flows), 1)


class StatisticsTest(unittest.TestCase):
    def test_full_http_session(self):
        """T13: nhiều gói hai chiều -> packet/byte/flag counter và duration đúng."""
        steps = [(0.0, CLIENT, SERVER, "S", "TCP", 74), (0.1, SERVER, CLIENT, "SA", "TCP", 74),
                 (0.2, CLIENT, SERVER, "A", "TCP", 66), (0.3, CLIENT, SERVER, "PA", "TCP", 200, "HTTP"),
                 (0.4, SERVER, CLIENT, "A", "TCP", 66), (0.5, SERVER, CLIENT, "PA", "TCP", 1000, "HTTP"),
                 (0.6, CLIENT, SERVER, "A", "TCP", 66), (0.7, CLIENT, SERVER, "FA", "TCP", 66),
                 (0.8, SERVER, CLIENT, "FA", "TCP", 66), (0.9, CLIENT, SERVER, "A", "TCP", 66)]
        flow = run(steps)[0].flush()[0].to_dict()
        self.assertEqual(flow, {
            "flow_id": "TCP-10.0.0.1:40000-10.0.0.2:80@1790400000.000000",
            "protocol": "TCP", "application_protocol": "HTTP",
            "endpoint_a": {"ip": "10.0.0.1", "port": 40000}, "endpoint_b": {"ip": "10.0.0.2", "port": 80},
            "start_time": T0, "last_seen": T0 + 0.9, "duration": 0.9,
            "packet_count": 10, "byte_count": 1744,
            "forward_packet_count": 6, "forward_byte_count": 538,
            "backward_packet_count": 4, "backward_byte_count": 1206,
            "SYN_count": 2, "ACK_count": 9, "FIN_count": 2, "RST_count": 0,
            "state": CLOSED, "end_reason": END_OF_INPUT,
        })

    def test_first_known_app_protocol(self):
        steps = [(0, CLIENT, SERVER, "S"), (1, CLIENT, SERVER, "PA", "TCP", 60, "UNKNOWN"),
                 (2, CLIENT, SERVER, "PA", "TCP", 60, "HTTP"), (3, CLIENT, SERVER, "PA", "TCP", 60, "UNKNOWN")]
        self.assertEqual(run(steps)[0].flush()[0].application_protocol, "HTTP")

    def test_missing_frame_len_counts_zero_bytes(self):
        ev = event(0, CLIENT, SERVER, "S")
        ev["frame_len"] = None
        flow = run([ev])[0].flush()[0]
        self.assertEqual((flow.packet_count, flow.byte_count), (1, 0))


class RealDataTest(unittest.TestCase):
    def events(self, number: str) -> list[dict]:
        path = glob.glob(f"TEST/cases/{number}_*/output.jsonl")[0]
        return [preprocess_event(e) for e in read_jsonl(path)]

    def test_handshake_case_from_assignment_1(self):
        tracker, events, _ = run(self.events("01"))
        self.assertEqual([e["flow_state"] for e in events], [HANDSHAKE, HANDSHAKE, ESTABLISHED])
        self.assertEqual(len(tracker.flows), 1)

    def test_every_case_counts_every_tcp_udp_packet(self):
        for path in sorted(glob.glob("TEST/cases/*/output.jsonl")):
            events = [preprocess_event(e) for e in read_jsonl(path)]
            tracker, events, finished = run(events)
            flows = finished + tracker.flush()
            tracked = [e for e in events if e["flow_id"]]
            with self.subTest(path=path):
                self.assertEqual(sum(f.packet_count for f in flows), len(tracked))
                self.assertEqual(sum(f.byte_count for f in flows), sum(e["frame_len"] for e in tracked))
                self.assertFalse(any("flow_error" in e for e in events))


class RobustnessTest(unittest.TestCase):
    VALUES = [None, True, 0, 80, -1, 1.5, float("nan"), float("inf"), "x", "10.0.0.1", "::1", [], {},
              "TCP", "UDP", T0, 70000]

    def test_random_events_never_raise(self):
        rng = random.Random(5)
        tracker = FlowTracker()
        for _ in range(20000):
            norm = {k: rng.choice(self.VALUES)
                    for k in ("transport", "src_ip", "dst_ip", "src_port", "dst_port", "timestamp")}
            ev = {"norm": rng.choice([norm, norm, None, "x"]), "frame_len": rng.choice(self.VALUES),
                  "tcp": rng.choice([None, "x", {"flags": rng.choice([None, "x", {"syn": True}])}])}
            tracker.process(ev)
            self.assertNotIn("flow_error", ev)
        self.assertTrue(math.isfinite(tracker.now))

    def test_non_dict_event(self):
        self.assertEqual(FlowTracker().process("abc"), [])


if __name__ == "__main__":
    unittest.main()
