"""Flow/Connection Tracker: gom các gói cùng phiên giao tiếp thành một flow hai chiều (mục 5 của đề).

Flow được nhận diện bằng 5-tuple (protocol, IP và port hai đầu) không phân biệt chiều: gói A->B và
B->A thuộc cùng một flow. Đầu vào là event đã qua Preprocessor; tracker đọc 5-tuple trong "norm"
vì ở đó IP, port và tên giao thức đã ở dạng chuẩn.

Mỗi event được gắn thêm:
    flow_id          id của flow chứa gói, None nếu gói không thuộc flow nào (không phải TCP/UDP,
                     hoặc thiếu 5-tuple)
    flow_direction   "forward" (A -> B, A là bên khởi tạo) hoặc "backward"
"""

import ipaddress
from dataclasses import dataclass

FORWARD, BACKWARD = "forward", "backward"
TRACKED_PROTOCOLS = {"TCP", "UDP"}

Endpoint = tuple[str, int]          # (IP, port)
FlowKey = tuple[str, Endpoint, Endpoint]


@dataclass
class Flow:
    flow_id: str
    protocol: str
    endpoint_a: Endpoint            # Bên khởi tạo; chiều A -> B là forward
    endpoint_b: Endpoint
    start_time: float
    last_seen: float
    packet_count: int = 0


def _order(endpoint: Endpoint) -> tuple[int, int, int]:
    """Thứ tự để sắp xếp hai đầu: theo giá trị số của IP rồi đến port (10.0.0.9 trước 10.0.0.10)."""
    ip = ipaddress.ip_address(endpoint[0])
    return ip.version, int(ip), endpoint[1]


def flow_key(protocol: str, src: Endpoint, dst: Endpoint) -> FlowKey:
    """Khóa không phân biệt chiều: sắp xếp hai đầu nên A->B và B->A ra cùng một khóa."""
    low, high = sorted((src, dst), key=_order)
    return protocol, low, high


def _endpoint_text(endpoint: Endpoint) -> str:
    ip, port = endpoint
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def make_flow_id(key: FlowKey, start_time: float) -> str:
    """flow_id ổn định: chạy lại cùng dữ liệu luôn ra cùng id.

    Gồm 5-tuple đã sắp xếp và thời điểm bắt đầu. Thời điểm bắt đầu phân biệt hai phiên dùng lại
    cùng 5-tuple (kết nối cũ đã đóng, sau đó mở kết nối mới cùng port).
    Ví dụ: TCP-10.0.0.1:40000-10.0.0.2:80@1790400000.000000
    """
    protocol, low, high = key
    return f"{protocol}-{_endpoint_text(low)}-{_endpoint_text(high)}@{start_time:.6f}"


def _initiator(event: dict, src: Endpoint, dst: Endpoint) -> tuple[Endpoint, Endpoint]:
    """Chọn (A, B) cho flow mới, A là bên khởi tạo kết nối.

    Mặc định A là bên gửi gói đầu tiên. Hai trường hợp đảo lại, khi việc bắt gói bắt đầu giữa phiên:
      - gói đầu là SYN/ACK: đây là trả lời của server, client ở phía đích
      - gói đầu đi từ port dịch vụ (< 1024) sang port tạm: thường là server trả lời client
    """
    tcp = event.get("tcp")
    flags = tcp.get("flags") if isinstance(tcp, dict) else None
    if isinstance(flags, dict) and flags.get("syn"):
        return (dst, src) if flags.get("ack") else (src, dst)
    if src[1] < 1024 <= dst[1]:
        return dst, src
    return src, dst


def _five_tuple(event: dict) -> tuple[str, Endpoint, Endpoint, float] | None:
    """(protocol, nguồn, đích, timestamp) lấy từ norm, hoặc None nếu gói không thuộc flow nào."""
    norm = event.get("norm")
    if not isinstance(norm, dict) or norm.get("transport") not in TRACKED_PROTOCOLS:
        return None
    src = (norm.get("src_ip"), norm.get("src_port"))
    dst = (norm.get("dst_ip"), norm.get("dst_port"))
    timestamp = norm.get("timestamp")
    if None in (*src, *dst, timestamp):
        return None
    return norm["transport"], src, dst, timestamp


class FlowTracker:
    """Bảng flow đang hoạt động. Mỗi event gọi process() một lần."""

    def __init__(self) -> None:
        self.flows: dict[FlowKey, Flow] = {}

    def process(self, event: dict) -> list[Flow]:
        """Gắn event vào flow có sẵn hoặc tạo flow mới; thêm flow_id và flow_direction vào event.

        Trả về các flow đã kết thúc trong lần gọi này để nơi gọi ghi ra.
        """
        event["flow_id"] = event["flow_direction"] = None
        five_tuple = _five_tuple(event)
        if five_tuple is None:
            return []
        protocol, src, dst, timestamp = five_tuple

        key = flow_key(protocol, src, dst)
        flow = self.flows.get(key)
        if flow is None:
            a, b = _initiator(event, src, dst)
            flow = Flow(make_flow_id(key, timestamp), protocol, a, b, timestamp, timestamp)
            self.flows[key] = flow

        flow.last_seen = max(flow.last_seen, timestamp)   # Gói đến trễ không kéo lùi thời gian
        flow.packet_count += 1
        event["flow_id"] = flow.flow_id
        event["flow_direction"] = FORWARD if src == flow.endpoint_a else BACKWARD
        return []

    def flush(self) -> list[Flow]:
        """Kết thúc mọi flow còn lại (hết dữ liệu đầu vào). Trả về các flow đó."""
        flows = list(self.flows.values())
        self.flows.clear()
        return flows
