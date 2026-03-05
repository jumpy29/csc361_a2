import struct

def read_global_header(f):
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

    return endian


def process_packets(f, endian, connections):
    first_packet_time = None
    packet_count = 0

    while True:
        packet_count += 1

        packet_header_bytes = f.read(16)

        if len(packet_header_bytes) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+"IIII", packet_header_bytes)


        current_time = ts_sec + ts_usec / 1_000_000

        if first_packet_time is None:
            first_packet_time = current_time

        relative_time = current_time - first_packet_time

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

        # handling duplicate entries for same connection
        if (src_ip, dst_ip, src_port, dst_port) in connections.keys():
            cur_connection = (src_ip, dst_ip, src_port, dst_port)
        elif (dst_ip, src_ip, dst_port, src_port) in connections.keys():
            cur_connection = (dst_ip, src_ip, dst_port, src_port)
        else: 
            cur_connection = (src_ip, dst_ip, src_port, dst_port)

        flags = packet_data[tcp_start + 13]
        fin = flags & 0x01
        syn = flags & 0x02
        rst = flags & 0x04

        if cur_connection not in connections.keys():
            connections[cur_connection] = {
                "start_time": current_time,
                "packets_src_dst": 0,
                "packets_dst_src": 0,
                "bytes_src_dst": 0,
                "bytes_dst_src": 0,
                "rst": False,
                "syn": 0,
                "fin": 0,
                "sender_window_size": 0,
                "receiver_window_size": 0,
                "last_flags": 0,
                "first_flags": flags
            }
        
        connection = connections[cur_connection]

        src_0, dst_0, sport_0, dport_0 = cur_connection

        if (src_0, dst_0, sport_0, dport_0) == (src_ip, dst_ip, src_port, dst_port):
            direction = "src_dst"
        else: 
            direction = "dst_src"

        if direction == "src_dst":
            connection["packets_src_dst"] +=1
        else: 
            connection["packets_dst_src"] +=1

        if syn:
            connection["syn"] += 1
        if fin:
            connection["fin"] += 1
        if rst:
            connection["rst"] = True

        connection["last_flags"] = flags
        
        connection["end_time"] = relative_time

        tcp_header_len = ((packet_data[tcp_start + 12]>>4)& 0xF) * 4

        payload_start = tcp_start + tcp_header_len
        payload_size = len(packet_data) - payload_start

        if payload_size > 0:
            if direction=="src_dst":
                connection["bytes_src_dst"] += payload_size
            else:
                connection["bytes_dst_src"] += payload_size    



def analyze_connections(connections):

    reset_count = 0
    complete_count = 0
    open_count = 0
    established_before_capture = 0

    complete_connections = []

    for conn_key, conn in connections.items():
        if conn["rst"]:
            reset_count+=1
        
        if conn["syn"] >=1 and conn["fin"] >=1:
            complete_count+=1
            complete_connections.append(conn_key)

        first_syn = conn["first_flags"] & 0x02
        if not first_syn:
            established_before_capture += 1

        last_fin = conn["last_flags"] & 0x01
        if not last_fin:
            open_count += 1

    print("Reset connections:", reset_count)
    print("Complete connections:", complete_count)
    print("Open connections:", open_count)
    print("Established before capture:", established_before_capture)

    return complete_connections, complete_count, reset_count, open_count, established_before_capture


def print_connection_details(connections, complete_connections):
    print("Connections' details:\n")

    for i, (conn_key, conn) in enumerate(connections.items(), 1):
        src_ip, dst_ip, src_port, dst_port = conn_key

        if conn["rst"]:
            status = "R"
        else:
            status = "S" + str(conn['syn']) + "F" + str(conn["fin"])

        print(f"Connection {i}:")
        print("Source Address:", src_ip)
        print("Destination Address:", dst_ip)
        print("Source Port:", src_port)
        print("Destination Port:", dst_port)
        print("Status:", status)

        if conn_key in complete_connections:
            start = conn["start_time"]
            end = conn["end_time"]
            duration = end-start

            packets_src_dst = conn["packets_src_dst"]
            packets_dst_src = conn["packets_dst_src"]
            total_packets = packets_src_dst + packets_dst_src

            bytes_src_dst = conn["bytes_src_dst"]
            bytes_dst_src = conn["bytes_dst_src"]
            total_bytes = bytes_src_dst + bytes_dst_src

            print("Start Time:", start)
            print("End Time:", end)
            print("Duration:", duration)

            print("Number of packets sent from Source to Destination:", packets_src_dst)
            print("Number of packets sent from Destination to Source:", packets_dst_src)
            print("Total number of packets:", total_packets)

            print("Number of data bytes from Source to Destination:", bytes_src_dst)
            print("Number of data bytes from Destination to Source:", bytes_dst_src)
            print("Total number of data bytes:", total_bytes)

        print("END")
        print("++++++++++++++++++++++++++++")




def main():

    f = open("sample-capture-file.cap", "rb")

    endian = read_global_header(f)

    connections = {}

    process_packets(f, endian, connections)

    f.close()

    print("total connections: ", len(connections))

    complete_connections, complete_count, reset_count, open_count, established_before_capture = analyze_connections(connections)

    print_connection_details(connections, complete_connections)
    

main()