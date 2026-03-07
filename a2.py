import struct

def read_global_header(f):
    global_header = f.read(24)

    magic_number = global_header[:4].hex()

    if magic_number == "d4c3b2a1":
        endian = "<"   # little endian

    elif magic_number == "a1b2c3d4":
        endian = ">"   # big endian

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
        if (src_ip, dst_ip, src_port, dst_port) in connections:
            cur_connection = (src_ip, dst_ip, src_port, dst_port)
        elif (dst_ip, src_ip, dst_port, src_port) in connections:
            cur_connection = (dst_ip, src_ip, dst_port, src_port)
        else: 
            cur_connection = (src_ip, dst_ip, src_port, dst_port)

        flags = packet_data[tcp_start + 13]
        fin = flags & 0x01
        syn = flags & 0x02
        rst = flags & 0x04

        if cur_connection not in connections:
            connections[cur_connection] = {
                "start_time": relative_time,
                "packets_src_dst": 0,
                "packets_dst_src": 0,
                "bytes_src_dst": 0,
                "bytes_dst_src": 0,
                "rst": False,
                "syn": 0,
                "fin": 0,
                "last_flags": 0,
                "first_flags": flags,

                # for window size stats calculation
                "window_src_min": float("inf"),
                "window_src_max": 0,
                "window_src_sum": 0,
                "window_src_count": 0,
                "window_dst_min": float("inf"),
                "window_dst_max": 0,
                "window_dst_sum": 0,
                "window_dst_count": 0,

                # RTT caclulation
                "rtts": [],
                "pending_rtts": {}

            }
        
        connection = connections[cur_connection]

        src_0, dst_0, sport_0, dport_0 = cur_connection

        seq_num = struct.unpack(">I", packet_data[tcp_start+4:tcp_start+8])[0]
        ack_num = struct.unpack(">I", packet_data[tcp_start+8:tcp_start+12])[0]

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

        if payload_size > 0 or syn or fin:
            expected_ack = seq_num + payload_size

            if syn:
                expected_ack += 1
            if fin:
                expected_ack += 1

            connection["pending_rtts"].setdefault(expected_ack, []).append(relative_time)

            if direction=="src_dst":
                connection["bytes_src_dst"] += payload_size
            else:
                connection["bytes_dst_src"] += payload_size    

        # RTT
        if ack_num in connection["pending_rtts"]:
            sent_time = connection["pending_rtts"][ack_num].pop(0)
            rtt = relative_time - sent_time
            connection["rtts"].append(rtt)

            if not connection["pending_rtts"][ack_num]:
                del connection["pending_rtts"][ack_num]


        # window size update
        window_size = struct.unpack(">H", packet_data[tcp_start+14:tcp_start+16])[0]

        if direction == "src_dst":
            connection["window_src_min"] = min(connection["window_src_min"], window_size)
            connection["window_src_max"] = max(connection["window_src_max"], window_size)
            connection["window_src_sum"] += window_size
            connection["window_src_count"] += 1

        else:
            connection["window_dst_min"] = min(connection["window_dst_min"], window_size)
            connection["window_dst_max"] = max(connection["window_dst_max"], window_size)
            connection["window_dst_sum"] += window_size
            connection["window_dst_count"] += 1
        


def analyze_connections(connections):

    reset_count = 0
    complete_count = 0
    open_count = 0
    established_before_capture = 0

    src_pkt_min = float("inf")
    src_pkt_max = 0
    src_pkt_sum = 0

    dst_pkt_min = float("inf")
    dst_pkt_max = 0
    dst_pkt_sum = 0

    duration_min = float("inf")
    duration_max = 0
    duration_sum = 0

    rtt_min = float("inf")
    rtt_max = 0
    rtt_sum = 0
    rtt_count = 0

    win_src_min = float("inf")
    win_src_max = 0
    win_src_sum = 0
    win_src_count = 0
    win_dst_min = float("inf")
    win_dst_max = 0
    win_dst_sum = 0
    win_dst_count = 0

    complete_connections = []

    for conn_key, conn in connections.items():
        if conn["rst"]:
            reset_count+=1
        
        if conn["syn"] >=1 and conn["fin"] >=1:
            complete_count+=1
            complete_connections.append(conn_key)

            # packet stats 
            src_pkts = conn["packets_src_dst"]
            dst_pkts = conn["packets_dst_src"]

            src_pkt_min = min(src_pkt_min, src_pkts)
            src_pkt_max = max(src_pkt_max, src_pkts)
            src_pkt_sum += src_pkts
        
            dst_pkt_min = min(dst_pkt_min, dst_pkts)
            dst_pkt_max = max(dst_pkt_max, dst_pkts)
            dst_pkt_sum += dst_pkts



            # duration stats
            duration = conn["end_time"] - conn["start_time"]
            duration_min = min(duration_min, duration)
            duration_max = max(duration_max, duration)
            duration_sum += duration

            

            # RTT stats
            if conn["rtts"]:
                conn_min = min(conn["rtts"])
                conn_max = max(conn["rtts"])
                conn_sum = sum(conn["rtts"])
                conn_count = len(conn["rtts"])

                rtt_min = min(rtt_min, conn_min)
                rtt_max = max(rtt_max, conn_max)

                rtt_sum += conn_sum
                rtt_count += conn_count

            

            # receiver window stats
            if conn["window_src_count"]>0:
                win_src_min = min(win_src_min, conn["window_src_min"])
                win_src_max = max(win_src_max, conn["window_src_max"])
                win_src_sum += conn["window_src_sum"]
                win_src_count += conn["window_src_count"]

            if conn["window_dst_count"]>0:
                win_dst_min = min(win_dst_min, conn["window_dst_min"])
                win_dst_max = max(win_dst_max, conn["window_dst_max"])
                win_dst_sum += conn["window_dst_sum"]
                win_dst_count += conn["window_dst_count"]

        first_syn = conn["first_flags"] & 0x02
        if not first_syn:
            established_before_capture += 1

        last_fin = conn["last_flags"] & 0x01
        if not last_fin:
            open_count += 1

    # mean packet calculation
    src_pkt_mean = src_pkt_sum/complete_count if complete_count else 0
    dst_pkt_mean = dst_pkt_sum/complete_count if complete_count else 0

    # duration mean calc
    duration_mean = duration_sum/complete_count if complete_count else 0

    # RTT mean calc
    rtt_mean = rtt_sum/rtt_count if rtt_count else 0

    # receiver window mean calc
    win_src_mean = win_src_sum/win_src_count if win_src_count else 0
    win_dst_mean = win_dst_sum/win_dst_count if win_dst_count else 0

    return (complete_connections, 
            complete_count,
            reset_count, 
            open_count, 
            established_before_capture,
            src_pkt_min, 
            src_pkt_max,
            src_pkt_mean,
            dst_pkt_min,
            dst_pkt_max,
            dst_pkt_mean,
            duration_min,
            duration_max,
            duration_mean, 
            rtt_min,
            rtt_max, 
            rtt_mean,
            win_src_min,
            win_src_max,
            win_src_mean,
            win_dst_min,
            win_dst_max,
            win_dst_mean
            )


def print_connection_details(connections, complete_connections):
    print("\nB)Connections' details:\n")

    for i, (conn_key, conn) in enumerate(connections.items(), 1):
        if (i!=1):
            print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
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

            print("Start Time:", start, "seconds")
            print("End Time:", end, "seconds")
            print("Duration:", duration, "seconds")

            print("Number of packets sent from Source to Destination:", packets_src_dst)
            print("Number of packets sent from Destination to Source:", packets_dst_src)
            print("Total number of packets:", total_packets)

            print("Number of data bytes from Source to Destination:", bytes_src_dst)
            print("Number of data bytes from Destination to Source:", bytes_dst_src)
            print("Total number of data bytes:", total_bytes)

        print("END")
    print("___________________________________________________________")

def print_connection_counts(complete_count, reset_count, open_count, established_before_capture):
    print("\nC) General\n")
    print("The total number of complete TCP connections:", complete_count)
    print("The number of reset TCP connections:", reset_count)
    print("The number of TCP connections that were still open when the trace capture ended:", open_count)
    print("The number of TCP connections established before the capture started:", established_before_capture)
    print("_______________________________________________________________")

def print_total_connections(num_conns):
    print("A) Total number of connections:", num_conns)
    print("________________________________________________________________")

def print_tcp_complete_conns_details(
            src_pkts_min,
            src_pkts_max,
            src_pkts_mean,
            dst_pkts_min,
            dst_pkts_max,
            dst_pkts_mean,
            duration_min,
            duration_max,
            duration_mean,
            rtt_min,
            rtt_max,
            rtt_mean,
            win_src_min,
            win_src_max,
            win_src_mean,
            win_dst_min,
            win_dst_max,
            win_dst_mean
        ):
    print("D) Complete TCP connections:\n")

    print("Minimum time duration:", duration_min)
    print("Maximum time duration:", duration_max)
    print("Mean time duration:", duration_mean)

    print()

    print("Minimum RTT value:", rtt_min)
    print("Maximum RTT value:", rtt_max)
    print("Mean RTT value:", rtt_mean)
    
    print()

    print("Minimum number of packets sent:", src_pkts_min)
    print("Maximum number of packets sent:", src_pkts_max)
    print("Mean number of packets sent:", src_pkts_mean)
    
    print()

    print("Minimum number of packets received:", dst_pkts_min)
    print("Maximum number of packets received:", dst_pkts_max)
    print("Mean number of packets received:", dst_pkts_mean)

    print()

    print("Minimum receive window size (sender side):", win_src_min)
    print("Maximum receive window size (sender side):", win_src_max)
    print("Mean receive window size (sender side):", win_src_mean)

    print()

    print("Minimum receiver window size (receiver side):", win_dst_min)
    print("Maximum receiver window size (receiver side):", win_dst_max)
    print("Mean receiver window size (receiver side):", win_dst_mean)

def main():

    f = open("sample-capture-file.cap", "rb")

    endian = read_global_header(f)

    connections = {}

    process_packets(f, endian, connections)

    f.close()

    (
        complete_connections,
        complete_count, 
        reset_count, 
        open_count,
        established_before_capture,
        src_pkts_min,
        src_pkts_max,
        src_pkts_mean,
        dst_pkts_min,
        dst_pkts_max,
        dst_pkts_mean,
        duration_min,
        duration_max,
        duration_mean,
        rtt_min,
        rtt_max,
        rtt_mean,
        win_src_min,
        win_src_max,
        win_src_mean,
        win_dst_min,
        win_dst_max,
        win_dst_mean
    ) = analyze_connections(connections)

    
    print_total_connections(len(connections))
    print_connection_details(connections, complete_connections)
    print_connection_counts(complete_count, reset_count, open_count, established_before_capture)
    print_tcp_complete_conns_details(
            src_pkts_min,
            src_pkts_max,
            src_pkts_mean,
            dst_pkts_min,
            dst_pkts_max,
            dst_pkts_mean,
            duration_min,
            duration_max,
            duration_mean,
            rtt_min,
            rtt_max,
            rtt_mean,
            win_src_min,
            win_src_max,
            win_src_mean,
            win_dst_min,
            win_dst_max,
            win_dst_mean
        )

main()