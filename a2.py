import struct

f = open("sample-capture-file.cap", "rb")
global_header = f.read(24)

magic_number = global_header[:4].hex()
print("magic number:", magic_number)

if magic_number == "d4c3b2a1":
    endian = "<"   # little endian
    print("Little endian")
elif magic_number == "a1b2c3d4":
    endian = ">"   # big endian
    print("Big endian")
else:
    raise ValueError("Unknown file format")

fields = struct.unpack(endian + "IHHiIII", global_header)

(
    magic_number,
    version_major,
    version_minor,
    thiszone,
    sigfigs,
    snaplen,
    network
) = fields


packet_count = 0

first_connection = None
conn_data = {
    "syn": 0, 
    "fin": 0,
    "rst": False, 
    "start_time": None, 
    "end_time": None,
    "packets_src_dst": 0,
    "packets_dst_src": 0,
    "bytes_src_dst": 0,
    "bytes_dst_src": 0
}

while True:
    packet_count += 1

    packet_header_bytes = f.read(16)

    if len(packet_header_bytes) < 16:
        break

    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+"IIII", packet_header_bytes)

    packet_data = f.read(incl_len)

    eth_type = struct.unpack(">H", packet_data[12:14])[0]
    if eth_type != 0x0800:
        continue

    protocol = packet_data[23]
    if protocol != 6:
        continue

    src_ip = ".".join(map(str, packet_data[26:30]))
    dst_ip = ".".join(map(str, packet_data[30:34]))

    ip_header_len = (packet_data[14] & 0x0F) * 4
    tcp_start = 14 + ip_header_len

    flags = packet_data[tcp_start + 13]
    fin = flags & 0x01
    syn = flags & 0x02
    rst = flags & 0x04

    src_port = struct.unpack(">H", packet_data[tcp_start:tcp_start+2])[0]
    dst_port = struct.unpack(">H", packet_data[tcp_start+2:tcp_start+4])[0]

    if first_connection is None:
        first_connection = (src_ip, src_port, dst_ip, dst_port)
        conn_data["start_time"] = ts_sec + ts_usec/1_000_000

    src0, sport0, dst0, dport0 = first_connection

    if (src_ip, src_port, dst_ip, dst_port) == first_connection:
        direction = "src_dst"
    elif (src_ip, src_port, dst_ip, dst_port) == (dst0, dport0, src0, sport0):
        direction = "dst_src"
    else:
        continue

    if direction == "src_dst":
        conn_data["packets_src_dst"] += 1
    else:
        conn_data["packets_dst_src"] += 1

    if syn:
        conn_data["syn"] += 1
    if fin:
        conn_data["fin"] += 1
    if rst:
        print(packet_count)
        conn_data["rst"] = True

    conn_data["end_time"] = ts_sec + ts_usec/1_000_000

    tcp_header_len = ((packet_data[tcp_start + 12]>>4)& 0xF) * 4

    payload_start = tcp_start + tcp_header_len
    payload_size = len(packet_data) - payload_start

    if payload_size > 0:
        if direction=="src_dst":
            conn_data["bytes_src_dst"] += payload_size
        else:
            conn_data["bytes_dst_src"] += payload_size    
    


total_packets = conn_data["packets_src_dst"]+conn_data["packets_dst_src"]
total_bytes = conn_data["bytes_src_dst"] + conn_data["bytes_dst_src"]

if conn_data["rst"]:
    status = "R"
else:
    status = "S"+str(conn_data["syn"])+"F"+str(conn_data["fin"])

print("\nConnection summary")
print("---------------")
print("src address:", src0)
print("dest address:", dst0)
print("src port:", sport0)
print("dest port:", dport0)
print("status:", status)

if status=="COMPLETE":
    duration = conn_data["end_time"] - conn_data["start_time"]

    print("start time:", conn_data["start_time"])
    print("end time:", conn_data["end_time"])
    print("duration:", duration)

f.close()