import socket
import struct
import time
import requests

def create_DNS_Payload(domain):
    # Can be a random number
    transaction_id = 0x1234

    # Standard recursive query  
    flags = 0x0100

    # One question  
    question_count = 1  
    ans_count = 0
    auth_count = 0
    add_count = 0
    header = struct.pack('>HHHHHH', transaction_id, flags, question_count, ans_count, auth_count, add_count)

    query = b''
    for part in domain.split('.'):
        query += struct.pack('B', len(part)) + part.encode('utf-8')
    # End of string
    query += struct.pack('B', 0)  
    # Type A query, class IN
    query += struct.pack('>HH', 1, 1)  

    payload = header + query
    return payload, query

def send_DNS_payload(payload, server, port=53, use_tcp=False, timeout=10):
    if use_tcp:
        # Handle DNS over TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server, port))
            # Prefix payload with its length
            tcp_payload = struct.pack('!H', len(payload)) + payload
            sock.sendall(tcp_payload)
            # Receive the response
            response = b''
            while True:
                segment = sock.recv(512)
                if not segment:
                    break
                response += segment
            return response
    else:
        # Handle DNS over UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (server, port))
            response, _ = sock.recvfrom(512)
            return response

def unpack_dns_response(response, query):
    # Unpack the header
    header = response[:12]
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', header)

    current_pos = 12 + len(query)  # Skip header and question section

    # Skip the Answer section if present
    for _ in range(ancount):
        _, current_pos = unpack_name(response, current_pos)
        current_pos += 10

    # Process the authoritative record
    type_ns = []
    type_a = []
    for _ in range(nscount):
        name, current_pos = unpack_name(response, current_pos)
        type_, class_, ttl, data_length = struct.unpack_from('>HHIH', response, current_pos)
        current_pos += 10  # Skip the record header

        if type_ == 2 and class_ == 1:  # Type NS, Class IN
            ns_domain_name, _ = unpack_name(response, current_pos)
            print(f"Authority Record - {name.decode('utf-8')}: NS Record = {ns_domain_name.decode('utf-8')}")
            print("data length:", data_length)

    # Process the Additional section
    for _ in range(arcount):
        name, current_pos = unpack_name(response, current_pos)
        type_, class_, ttl, data_length = struct.unpack_from('>HHIH', response, current_pos)
        current_pos += 10  # Skip the record header

        if type_ == 1 and class_ == 1:  # Type A, Class IN
            ip_address = struct.unpack('!BBBB', response[current_pos:current_pos + 4])
            print(f"Additional Record - {name.decode('utf-8')}: IP Address = {'.'.join(map(str, ip_address))}")
            type_a.append('.'.join(map(str, ip_address)))
        elif type_ == 2 and class_ == 1:  # Type NS, Class IN
            ns_domain_name, _ = unpack_name(response, current_pos)
            print(f"Additional Record - {name.decode('utf-8')}: NS Record = {ns_domain_name.decode('utf-8')}")
            type_ns.append(ns_domain_name.decode('utf-8'))
        current_pos += data_length

    if len(type_ns) == 0:
        return type_a[:-1]
    else:
        return type_ns[:-1]

def unpack_name(response, pos):
    name_parts = []
    jumped = False  # Flag to check if we have jumped to a pointer
    initial_pos = pos  # Remember the initial position

    while True:
        length = response[pos]

        if length & 0xC0 == 0xC0:  # Check for pointer
            if not jumped:
                initial_pos = pos + 2  # Adjust initial_pos if this is the first jump
            jumped = True

            pointer = ((length & 0x3F) << 8) | response[pos + 1]
            pos = pointer  # Jump to the pointer location
        elif length == 0:
            break
        else:
            if jumped:
                # If we have jumped, don't increment pos beyond the initial jump
                pos = initial_pos
                jumped = False
            else:
                pos += 1
                name_parts.append(response[pos:pos + length])
                pos += length

    return b'.'.join(name_parts), pos if not jumped else initial_pos

def measure_RTT_with_socket(url, target_ip):
    # Parse the URL to get the path
    path = url.split('/', 3)[-1]

    try:
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the connection
            s.settimeout(10)

            # Connect to the target IP on port 80 (HTTP)
            s.connect((target_ip, 80))

            # Construct the HTTP GET request
            http_request = f"GET /{path} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"

            # Measure the time before sending the request
            start_time = time.time()

            # Send the HTTP request
            s.sendall(http_request.encode('utf-8'))

            # Receive the HTTP response
            response = b''
            while True:
                data = s.recv(1024)
                if not data:
                    break
                response += data

            # Measure the time after receiving the response
            end_time = time.time()

            # Calculate the RTT
            rtt = end_time - start_time

        return rtt, response.decode('utf-8')

    except socket.timeout:
        print("Socket connection timed out.")
        return None, None

    except Exception as e:
        print(f"Error during socket connection: {e}")
        return None, None

if __name__ == "__main__":
    root_servers = ["198.41.0.4",
                   "199.9.14.201",
                   "192.33.4.12",
                   "199.7.91.13",
                   "192.203.230.10",
                   "192.5.5.241",
                   "192.112.36.4",
                   "198.97.190.53",
                   "192.36.148.17",
                   "192.58.128.30",
                   "193.0.14.129", 
                   "199.7.83.42", 
                   "202.12.27.33"]
    # request to root server
    payload, query = create_DNS_Payload("tmz.com")
    start_time_dns = time.time()
    dns_response = send_DNS_payload(payload, "202.12.27.33", 53, False)
    tld_server = unpack_dns_response(dns_response, query)
    end_time_dns = time.time()
    rtt_dns = end_time_dns - start_time_dns
    print("tld server: ",tld_server)
    print("DNS request to root server: ",rtt_dns)

    #request to TLD server
    payload, query = create_DNS_Payload("tmz.com")
    start_time = time.time()
    dns_response = send_DNS_payload(payload, tld_server, 53, False)
    auth_server = unpack_dns_response(dns_response, query)
    print(auth_server)
    end_time = time.time()
    rtt_tld = end_time - start_time
    print("auth server: ",auth_server)
    print("Request to TLD server: ",rtt_tld)

    # Use a specific IP address for HTTP request
    # target_ip = "192.41.162.30"

    # Measure RTT for HTTP request
    # url = "https://www.tmz.com/"  # Replace with your desired URL
    # rtt_http, http_response = measure_RTT_with_socket(url, target_ip)

    # print("HTTP request RTT: ", rtt_http)
    # print("HTTP Response:\n", http_response)



