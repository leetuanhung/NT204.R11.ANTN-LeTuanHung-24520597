"""Flow/Connection Tracker: gom các gói cùng phiên giao tiếp thành một flow hai chiều (mục 5 của đề).

Flow được nhận diện bằng 5-tuple (protocol, IP và port hai đầu) không phân biệt chiều: gói A->B và
B->A thuộc cùng một flow. Đầu vào là event đã qua Preprocessor; tracker đọc 5-tuple trong "norm"
vì ở đó IP, port và tên giao thức đã ở dạng chuẩn.

Mỗi event được gắn thêm:
    flow_id          id của flow chứa gói, None nếu gói không thuộc flow nào (không phải TCP/UDP,
                     hoặc thiếu 5-tuple)
    flow_direction   "forward" (A -> B, A là bên khởi tạo) hoặc "backward"
    flow_state       trạng thái kết nối TCP sau gói này; None với UDP (không có kết nối)

Trạng thái TCP (mục 5.2), cập nhật theo cờ SYN, ACK, FIN, RST:
    NEW          vừa thấy gói đầu, chưa rõ (ví dụ gói không bật cờ nào của NULL scan)
    HANDSHAKE    đã thấy SYN, đang bắt tay ba bước
    ESTABLISHED  bắt tay xong (SYN -> SYN/ACK -> ACK), hoặc bắt gói từ giữa phiên đang chạy
    CLOSING      một phía đã gửi FIN
    CLOSED       cả hai phía đã gửi FIN
    RESET        có RST

Idle timeout (mục 5.3): flow không có gói mới quá thời gian quy định thì được kết thúc, xuất ra
và xóa khỏi bảng flow đang hoạt động. Đồng hồ là timestamp của gói chứ không phải giờ máy, nên
đọc lại một file PCAP cho đúng kết quả như lúc bắt gói thật.
"""

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass

FORWARD, BACKWARD = "forward", "backward"
TRACKED_PROTOCOLS = {"TCP", "UDP"}

NEW, HANDSHAKE, ESTABLISHED = "NEW", "HANDSHAKE", "ESTABLISHED"
CLOSING, CLOSED, RESET = "CLOSING", "CLOSED", "RESET"
TERMINAL_STATES = {CLOSED, RESET}

# Lý do flow kết thúc
IDLE_TIMEOUT = "idle_timeout"            # Quá thời gian không có gói mới
CONNECTION_CLOSED = "connection_closed"  # TCP đã CLOSED/RESET và hết thời gian chờ gói cuối
PORT_REUSED = "port_reused"              # SYN mới trên 5-tuple của kết nối đã đóng
END_OF_INPUT = "end_of_input"            # Hết dữ liệu đầu vào (hết file, dừng bắt gói)
TABLE_FULL = "table_full"                # Bảng flow đầy, nhường chỗ cho flow mới

TCP_TIMEOUT = 300.0     # Giây
UDP_TIMEOUT = 60.0
CLOSED_TIMEOUT = 10.0   # Giữ thêm flow đã đóng để ACK cuối, gói gửi lại không tạo nhầm flow mới
# Số flow đang hoạt động tối đa. SYN flood hay port scan tạo rất nhiều flow; không giới hạn thì
# kẻ tấn công làm IDS hết bộ nhớ.
MAX_FLOWS = 65536


@dataclass
class TrackerConfig:
    tcp_timeout: float = TCP_TIMEOUT
    udp_timeout: float = UDP_TIMEOUT
    closed_timeout: float = CLOSED_TIMEOUT
    max_flows: int = MAX_FLOWS

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
    state: str | None = None        # Trạng thái TCP; None với UDP
    syn_ack_seen: bool = False      # Server đã trả lời SYN/ACK
    fin_forward: bool = False       # A đã gửi FIN
    fin_backward: bool = False      # B đã gửi FIN
    end_reason: str | None = None   # Lý do kết thúc, None khi flow còn hoạt động


def _queue_name(flow: Flow) -> str:
    """Hàng đợi theo mức timeout: TCP, UDP, hoặc TCP đã đóng."""
    return "closed" if flow.state in TERMINAL_STATES else flow.protocol.lower()


def _tcp_flags(event: dict) -> dict:
    tcp = event.get("tcp")
    flags = tcp.get("flags") if isinstance(tcp, dict) else None
    return flags if isinstance(flags, dict) else {}


def update_tcp_state(flow: Flow, flags: dict, direction: str) -> None:
    """Cập nhật trạng thái TCP của flow theo cờ của một gói (kể cả gói không có payload)."""
    if flow.state in TERMINAL_STATES:
        return                      # ACK cuối, gói gửi lại sau khi đóng: không mở lại kết nối
    syn, ack = bool(flags.get("syn")), bool(flags.get("ack"))
    if flags.get("reset"):
        flow.state = RESET
    elif flags.get("fin"):
        if direction == FORWARD:
            flow.fin_forward = True
        else:
            flow.fin_backward = True
        flow.state = CLOSED if flow.fin_forward and flow.fin_backward else CLOSING
    elif flow.state == CLOSING:
        return                      # Dữ liệu và ACK còn lại trong lúc đóng
    elif syn:
        if ack:
            flow.syn_ack_seen = True
        if flow.state == NEW:
            flow.state = HANDSHAKE
    elif ack:
        if flow.state == NEW:
            flow.state = ESTABLISHED      # Bắt gói từ giữa phiên: không thấy bắt tay nhưng đang trao đổi
        elif flow.state == HANDSHAKE and flow.syn_ack_seen and direction == FORWARD:
            flow.state = ESTABLISHED


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
    flags = _tcp_flags(event)
    if flags.get("syn"):
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
    """Bảng flow đang hoạt động. Mỗi event gọi process() một lần; hết dữ liệu thì gọi flush()."""

    def __init__(self, cfg: TrackerConfig | None = None) -> None:
        self.cfg = cfg or TrackerConfig()
        self.flows: dict[FlowKey, Flow] = {}
        # Mỗi hàng đợi giữ khóa flow theo thứ tự lần cuối có gói, flow lâu không hoạt động nhất ở đầu.
        # Mỗi hàng có một mức timeout nên quét hết hạn chỉ cần xem từ đầu hàng, không duyệt cả bảng.
        self._queues: dict[str, OrderedDict[FlowKey, None]] = {
            "tcp": OrderedDict(), "udp": OrderedDict(), "closed": OrderedDict()}
        self.now = 0.0          # Timestamp lớn nhất đã thấy: đồng hồ của tracker

    def _end(self, key: FlowKey, reason: str) -> Flow:
        """Xóa flow khỏi bảng đang hoạt động và ghi lý do kết thúc."""
        flow = self.flows.pop(key)
        self._queues[_queue_name(flow)].pop(key, None)
        flow.end_reason = reason
        return flow

    def _evict_oldest(self) -> Flow:
        """Bảng đầy: kết thúc flow lâu không có gói nhất. Flow đó nằm đầu một trong ba hàng đợi."""
        fronts = [next(iter(queue)) for queue in self._queues.values() if queue]
        key = min(fronts, key=lambda k: self.flows[k].last_seen)
        return self._end(key, TABLE_FULL)

    def expire(self, now: float) -> list[Flow]:
        """Kết thúc các flow không có gói mới quá timeout, tính đến thời điểm now."""
        self.now = max(self.now, now)
        timeouts = {"tcp": self.cfg.tcp_timeout, "udp": self.cfg.udp_timeout,
                    "closed": self.cfg.closed_timeout}
        finished = []
        for name, timeout in timeouts.items():
            queue = self._queues[name]
            while queue:
                key = next(iter(queue))
                if self.now - self.flows[key].last_seen <= timeout:
                    break
                finished.append(self._end(key, CONNECTION_CLOSED if name == "closed" else IDLE_TIMEOUT))
        return finished

    def process(self, event: dict) -> list[Flow]:
        """Gắn event vào flow có sẵn hoặc tạo flow mới; thêm flow_id, flow_direction, flow_state.

        Trả về các flow đã kết thúc trong lần gọi này (hết hạn, dùng lại port) để nơi gọi ghi ra.
        """
        event["flow_id"] = event["flow_direction"] = event["flow_state"] = None
        # Mọi gói có thời gian hợp lệ đều đẩy đồng hồ, kể cả gói không thuộc flow nào (ARP, ICMP)
        norm = event.get("norm")
        timestamp = norm.get("timestamp") if isinstance(norm, dict) else None
        finished = self.expire(timestamp) if isinstance(timestamp, (int, float)) else []

        five_tuple = _five_tuple(event)
        if five_tuple is None:
            return finished
        protocol, src, dst, timestamp = five_tuple
        flags = _tcp_flags(event) if protocol == "TCP" else {}

        key = flow_key(protocol, src, dst)
        flow = self.flows.get(key)
        if flow and flow.state in TERMINAL_STATES and flags.get("syn") and not flags.get("ack"):
            # SYN mới trên 5-tuple đã đóng: phiên mới dùng lại port, kết thúc flow cũ
            finished.append(self._end(key, PORT_REUSED))
            flow = None
        if flow is None:
            while len(self.flows) >= max(self.cfg.max_flows, 1):
                finished.append(self._evict_oldest())
            a, b = _initiator(event, src, dst)
            flow = Flow(make_flow_id(key, timestamp), protocol, a, b, timestamp, timestamp)
            if protocol == "TCP":
                flow.state = NEW
            self.flows[key] = flow
        else:
            self._queues[_queue_name(flow)].pop(key)

        direction = FORWARD if src == flow.endpoint_a else BACKWARD
        flow.last_seen = max(flow.last_seen, timestamp)   # Gói đến trễ không kéo lùi thời gian
        flow.packet_count += 1
        if protocol == "TCP":
            update_tcp_state(flow, flags, direction)
        # Xếp lại cuối hàng; trạng thái mới có thể chuyển flow sang hàng "closed"
        self._queues[_queue_name(flow)][key] = None

        event["flow_id"] = flow.flow_id
        event["flow_direction"] = direction
        event["flow_state"] = flow.state
        return finished

    def flush(self) -> list[Flow]:
        """Kết thúc mọi flow còn lại khi hết dữ liệu đầu vào. Trả về các flow đó."""
        return [self._end(key, END_OF_INPUT) for key in list(self.flows)]
