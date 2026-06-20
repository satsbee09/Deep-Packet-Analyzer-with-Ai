import math
from scapy.all import rdpcap, TCP, UDP, IP, Raw

TCP_FLAGS = {
    'F': 0x01,
    'S': 0x02,
    'R': 0x04,
    'P': 0x08,
    'A': 0x10,
    'U': 0x20,
    'E': 0x40,
    'C': 0x80,
}


def payload_entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    freq = {}
    for byte in payload:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(payload)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_packet_features(packet) -> dict:
    features = {
        'packet_len': len(packet),
        'payload_len': 0,
        'src_port': 0,
        'dst_port': 0,
        'protocol': 0,
        'tcp_flags': 0,
        'payload_entropy': 0.0,
        'http_method': 0,
        'url_length': 0,
        'dns_query_length': 0,
    }

    if packet.haslayer(IP):
        features['protocol'] = packet[IP].proto

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        features['src_port'] = tcp.sport
        features['dst_port'] = tcp.dport
        flags = str(tcp.flags)
        features['tcp_flags'] = sum(TCP_FLAGS.get(ch, 0) for ch in flags)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            features['payload_len'] = len(payload)
            features['payload_entropy'] = payload_entropy(payload)
            lower = payload.lower()
            if lower.startswith(b'get ') or lower.startswith(b'post ') or lower.startswith(b'put ') or lower.startswith(b'delete '):
                features['http_method'] = 1
                parts = payload.split(b' ', 2)
                if len(parts) >= 2:
                    features['url_length'] = len(parts[1])
            if b'host:' in lower:
                features['http_method'] = 1
            if b'www.' in lower or b'http://' in lower or b'https://' in lower:
                features['url_length'] = len(lower)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        features['src_port'] = udp.sport
        features['dst_port'] = udp.dport
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            features['payload_len'] = len(payload)
            features['payload_entropy'] = payload_entropy(payload)
            lower = payload.lower()
            if b'www.' in lower:
                features['url_length'] = len(lower)
            if b'query' in lower or b'www.' in lower:
                features['dns_query_length'] = len(lower)

    return features


def build_feature_dataframe(pcap_path, label=None):
    packets = rdpcap(str(pcap_path))
    rows = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        row = extract_packet_features(packet)
        if label is not None:
            row['label'] = label
        rows.append(row)
    return rows
