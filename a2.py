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


connections = {}


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


    src_port = struct.unpack(">H", packet_data[tcp_start:tcp_start+2])[0]
    dst_port = struct.unpack(">H", packet_data[tcp_start+2:tcp_start+4])[0]

    if (src_ip, dst_ip, src_port, dst_port) in connections.keys():
        cur_connection = (src_ip, dst_ip, src_port, dst_port)
    elif (dst_ip, src_ip, dst_port, src_port) in connections.keys():
        cur_connection = (dst_ip, src_ip, dst_port, src_port)
    else: 
        cur_connection = (src_ip, dst_ip, src_port, dst_port) # create new key

    # create new entry in connections
    if cur_connection not in connections.keys():
        connections[cur_connection] = {
                                       "start_time": ts_sec+ts_usec/1_000_000,
                                       "packets_src_dst": 0,
                                       "packets_dst_src": 0,
                                       "total_packets": 0,
                                       "bytes_src_dst": 0,
                                       "bytes_dst_src": 0,
                                       "total_bytes": 0, 
                                       "rst": False,
                                       "syn": 0,
                                       "fin": 0,
                                       "sender_window_size": 0,
                                       "receiver_window_size": 0
                                       }
        
    connection = connections[cur_connection]
    connection["total_packets"] += 1

    src_0, dst_0, sport_0, dport_0 = cur_connection

    if (src_0, dst_0, sport_0, dport_0) == (src_ip, dst_ip, src_port, dst_port):
        direction = "src_dst"
    else: 
        direction = "dst_src"

    
    if direction == "src_dst":
        connection["packets_src_dst"] +=1
    else: 
        connection["packets_dst_src"] +=1
        

    flags = packet_data[tcp_start + 13]
    fin = flags & 0x01
    syn = flags & 0x02
    rst = flags & 0x04

    if syn:
        connection["syn"] += 1
    if fin:
        connection["fin"] += 1
    if rst:
        connection["rst"] = True

    connection["end_time"] = ts_sec + ts_usec/1_000_000

    tcp_header_len = ((packet_data[tcp_start + 12]>>4)& 0xF) * 4

    payload_start = tcp_start + tcp_header_len
    payload_size = len(packet_data) - payload_start

    if payload_size > 0:
        if direction=="src_dst":
            connection["bytes_src_dst"] += payload_size
        else:
            connection["bytes_dst_src"] += payload_size    

    connection["total_bytes"] += payload_size
    
f.close()


print("total connections: ", len(connections))

# reset_count = 0
# for key in connections.keys():
#     if connections[key]["rst"] == True:
#         reset_count+=1

# print(reset_count)


for connection in connections:
    print(connection)