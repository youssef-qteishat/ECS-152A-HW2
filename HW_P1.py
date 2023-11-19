import socket
import struct

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

def send_DNS_payload(payload, server, port=53, use_tcp=False):
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
            sock.settimeout(10)
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
        _, current_pos = unpack_name(response, current_pos)  # Skip name
        current_pos += 10  # Skip type, class, ttl, data length

    # Skip the Authority section
    for _ in range(nscount):
        _, current_pos = unpack_name(response, current_pos)  # Skip name
        current_pos += 10  # Skip type, class, ttl, data length

    # Process the Additional section
    for _ in range(arcount):
        name, current_pos = unpack_name(response, current_pos)
        type_, class_, ttl, data_length = struct.unpack_from('>HHIH', response, current_pos)
        current_pos += 10  # Skip the record header

        if type_ == 1 and class_ == 1:  # Type A, Class IN
            ip_address = struct.unpack('!BBBB', response[current_pos:current_pos+4])
            print(f"Additional Record - {name}: IP Address = {'.'.join(map(str, ip_address))}")
        current_pos += data_length  # Skip to the next record
        
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
                name_parts.append(response[pos:pos + length].decode('utf-8'))
                pos += length

    return '.'.join(name_parts), pos if not jumped else initial_pos



    #shoot me in the head please right now 
    #bang (x_x)
if __name__ == "__main__":
    payload, query = create_DNS_Payload("tmz.com")

    dns_response = send_DNS_payload(payload, "202.12.27.33", 53, False)
    print(unpack_dns_response(dns_response, query))




# Example usage

# def recieve_payload(response):
#     header = response[:12]
#     id, flags, q_num, ans_num, aut_num, add_num = struct.unpack('!6H', header)

#     # Skip the Question section
#     curr_pos = 12
#     for _ in range(q_num):
#         while response[curr_pos] != 0:
#             curr_pos += 1
#         curr_pos += 5  # Skip the null byte, QTYPE (2 bytes), and QCLASS (2 bytes)
#     print("Done with question")
#     print(ans_num)
#     # Process the Answer section
#     print("Going into answers!")
#     ip_address = None
#     for _ in range(ans_num):
#         # Handle name field (could be a pointer)
#         print("in answers!")
#         print(curr_pos,"   ",len(response))
#         if response[curr_pos] & 0xC0 == 0xC0:
#             curr_pos += 2  # Skip the pointer
#         else:
#             while response[curr_pos] != 0:
#                 curr_pos += 1
#             curr_pos += 1  # Skip the null byte

#         # Check for sufficient buffer length
#         if curr_pos + 10 > len(response):
#             print("Insufficient data to unpack record.")
#             break

#         record_type, record_class, ttl, data_length = struct.unpack('!2H2H', response[curr_pos:curr_pos + 10])
#         curr_pos += 10

#         # Ensure there's enough data for the IP address
#         if curr_pos + data_length > len(response):
#             print("Insufficient data for IP address.")
#             break

#         # Process IPv4 or IPv6 records
#         if record_type == 1 and record_class == 1:  # A record
#             if data_length == 4:  # IPv4 address should be 4 bytes
#                 ip_address = socket.inet_ntoa(response[curr_pos:curr_pos + 4])
#                 print(f"A Record: IP Address = {ip_address}")
#             else:
#                 print("Unexpected data length for A record.")
#         elif record_type == 28 and record_class == 1:  # AAAA record
#             if data_length == 16:  # IPv6 address should be 16 bytes
#                 ip_address = socket.inet_ntop(socket.AF_INET6, response[curr_pos:curr_pos + 16])
#                 print(f"AAAA Record: IP Address = {ip_address}")
#             else:
#                 print("Unexpected data length for AAAA record.")

#         curr_pos += data_length

#     return ip_address




    # def parse_dns_response(response):
#     # Parse the DNS header
#     transaction_id, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', response[:12])

#     # Extract information from the DNS header
#     print(f"Transaction ID: {transaction_id}")
#     print(f"Flags: {flags}")
#     print(f"Number of Questions: {questions}")
#     print(f"Number of Answers: {answers}")

#     # Parse the question section
#     offset = 12
#     qname, offset = parse_domain(response, offset)
#     qtype, qclass = struct.unpack('!HH', response[offset:offset + 4])

#     # Extract information from the question section
#     print("Question Section:")
#     print(f"QNAME: {qname}")
#     print(f"QTYPE: {qtype}")
#     print(f"QCLASS: {qclass}")

#     # Parse the answer section (for simplicity, only the first answer is considered)
#     offset = parse_answers(response, answers, offset)

# def parse_domain(response, offset):
#     labels = []
#     while True:
#         label_length = response[offset]
#         offset += 1
#         if label_length == 0:
#             break
#         label = response[offset:offset + label_length]
#         labels.append(label.decode())
#         offset += label_length
#     return '.'.join(labels), offset

# def parse_answers(response, num_answers, offset):
#     for _ in range(num_answers):
#         name, offset = parse_domain(response, offset)
#         rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset + 10])

#         # Extract information from the answer section
#         print("\nAnswer Section:")
#         print(f"Name: {name}")
#         print(f"Type: {rtype}")
#         print(f"Class: {rclass}")
#         print(f"TTL: {ttl}")
#         print(f"RD Length: {rdlength}")

#         # Parse and extract resource data (for simplicity, handling A records only)
#         if rtype == 1 and rdlength == 4:
#             ip_address = '.'.join(map(str, response[offset + 10:offset + 14]))
#             print(f"IP Address (A Record): {ip_address}")
#         else:
#             print("Unsupported record type or length")

#         offset += 10 + rdlength

#     return offset


