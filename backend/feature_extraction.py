
import pyshark
import asyncio
import pandas as pd
from collections import defaultdict

def aggregate_sessions(pcap_file):
    # Create an event loop manually
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    capture = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
    session_data = defaultdict(list)

    # Process each packet in the capture
    for packet in capture:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            src_port = getattr(packet[packet.transport_layer], 'srcport', None)
            dst_port = getattr(packet[packet.transport_layer], 'dstport', None)
            time = float(packet.sniff_time.timestamp())
            bytes_sent = int(packet.length)
            session_key = (src_ip, dst_ip, protocol, src_port, dst_port)

            session_data[session_key].append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'bytes_sent': bytes_sent,
                'time': time
            })
        except AttributeError:
            continue
    
    capture.close()

    session_features = []
    for session_key, packets in session_data.items():
        src_ip, dst_ip, protocol, src_port, dst_port = session_key
        session_count = len(packets)
        srv_count = sum(1 for pkt in packets if pkt['dst_ip'] == dst_ip)
        same_srv_rate = srv_count / session_count if session_count > 0 else 0
        total_bytes = sum(p['bytes_sent'] for p in packets)
        duration = packets[-1]['time'] - packets[0]['time'] if session_count > 1 else 0
        src_bytes = sum(pkt['bytes_sent'] for pkt in packets if pkt['src_ip'] == src_ip)
        dst_bytes = sum(pkt['bytes_sent'] for pkt in packets if pkt['dst_ip'] == src_ip)
        diff_srv_rate = len(set([pkt['dst_ip'] for pkt in packets])) / session_count if session_count > 0 else 0
        srv_serror_rate = 0  # SYN/RST flag-based rate (can be calculated similarly to serror_rate)
        srv_diff_host_rate = len(set([pkt['src_ip'] for pkt in packets])) / srv_count if srv_count > 0 else 0

        # Create a dictionary of session-level features
        features = {
            'duration': duration,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': 0,
            'wrong_fragment': 0,
            'su_attempted': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'count': session_count,
            'srv_count': srv_count,
            'serror_rate': 0,
            'srv_serror_rate': srv_serror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': srv_diff_host_rate,
            
        }

        session_features.append(features)
        # print(pd.DataFrame([features]))

    # Return the DataFrame with aggregated session features
    return pd.DataFrame(session_features)
# import pyshark
# import asyncio
# import pandas as pd
# from collections import defaultdict

# def aggregate_sessions(pcap_file):
#     loop = asyncio.new_event_loop()
#     asyncio.set_event_loop(loop)
    
#     capture = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
#     session_data = defaultdict(list)

#     for packet in capture:
#         try:
#             # Safe protocol detection
#             protocol = packet.transport_layer or 'UDP'
#             if not hasattr(packet, 'ip'):
#                 continue  # Skip non-IP packets

#             src_ip = packet.ip.src
#             dst_ip = packet.ip.dst
#             src_port = getattr(packet[protocol.lower()], 'srcport', '0')
#             dst_port = getattr(packet[protocol.lower()], 'dstport', '0')
#             time = float(packet.sniff_time.timestamp())
#             bytes_sent = int(packet.length)

#             session_key = (src_ip, dst_ip, protocol, src_port, dst_port)
#             session_data[session_key].append({
#                 'src_ip': src_ip,
#                 'dst_ip': dst_ip,
#                 'bytes_sent': bytes_sent,
#                 'time': time
#             })
#         except Exception as e:
#             print(f"Skipped a packet due to: {e}")
#             continue

#     capture.close()

#     session_features = []

#     for session_key, packets in session_data.items():
#         src_ip, dst_ip, protocol, src_port, dst_port = session_key
#         session_count = len(packets)
#         srv_count = sum(1 for pkt in packets if pkt['dst_ip'] == dst_ip)
#         same_srv_rate = srv_count / session_count if session_count > 0 else 0
#         total_bytes = sum(p['bytes_sent'] for p in packets)
#         duration = packets[-1]['time'] - packets[0]['time'] if session_count > 1 else 0
#         src_bytes = sum(pkt['bytes_sent'] for pkt in packets if pkt['src_ip'] == src_ip)
#         dst_bytes = sum(pkt['bytes_sent'] for pkt in packets if pkt['dst_ip'] == src_ip)
#         diff_srv_rate = len(set([pkt['dst_ip'] for pkt in packets])) / session_count if session_count > 0 else 0
#         srv_diff_host_rate = len(set([pkt['src_ip'] for pkt in packets])) / srv_count if srv_count > 0 else 0
#         land = 1 if src_ip == dst_ip and src_port == dst_port else 0

#         # Protocol mapping (same as KDD)
#         proto_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
#         proto_val = proto_map.get(protocol.lower(), 1)

#         features = {
#             'duration': duration,
#             'protocol_type': proto_val,
#             'src_bytes': src_bytes,
#             'dst_bytes': dst_bytes,
#             'land': land,
#             'wrong_fragment': 0,
#             'urgent': 0,
#             'hot': 0,
#             'num_failed_logins': 0,
#             'logged_in': 0,
#             'num_compromised': 0,
#             'root_shell': 0,
#             'su_attempted': 0,
#             'num_root': 0,
#             'num_file_creations': 0,
#             'num_shells': 0,
#             'num_access_files': 0,
#             'num_outbound_cmds': 0,
#             'is_host_login': 0,
#             'is_guest_login': 0,
#             'count': session_count,
#             'srv_count': srv_count,
#             'serror_rate': 0,         # TCP-only flag calc can be added
#             'srv_serror_rate': 0,
#             'rerror_rate': 0,
#             'srv_rerror_rate': 0,
#             'same_srv_rate': same_srv_rate,
#             'diff_srv_rate': diff_srv_rate,
#             'srv_diff_host_rate': srv_diff_host_rate,
#             'dst_host_count': 0,
#             'dst_host_srv_count': 0,
#             'dst_host_same_srv_rate': 0,
#             'dst_host_diff_srv_rate': 0,
#             'dst_host_same_src_port_rate': 0,
#             'dst_host_srv_diff_host_rate': 0,
#             'dst_host_serror_rate': 0,
#             'dst_host_srv_serror_rate': 0,
#             'dst_host_rerror_rate': 0,
#             'dst_host_srv_rerror_rate': 0
#         }

#         session_features.append(features)

#     df = pd.DataFrame(session_features)
#     print(f"[INFO] Extracted {len(df)} session(s) from: {pcap_file}")
#     return df
