import socket
import struct
import base64
import sys
import os

def receive_fragmented_payload():
    """
    Receive and reconstruct fragmented ICMP payloads
    """
    try:
        # Create raw socket to receive ICMP packets
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(10)  # 10-second timeout

        packet_responses = {}

        while True:
            try:
                # Receive packet
                recv_packet, addr = recv_socket.recvfrom(65565)
                
                # Extract ICMP header
                icmp_header = recv_packet[20:28]
                icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('bbHHh', icmp_header)
                
                # Check for Echo Request (type 8)
                if icmp_type == 8:
                    # Extract custom header and payload
                    custom_header = recv_packet[28:32]
                    sequence, total_packets = struct.unpack('HH', custom_header)
                    
                    base64_payload = recv_packet[32:].decode('utf-8').rstrip('\x00')
                    
                    if icmp_id not in packet_responses:
                        packet_responses[icmp_id] = []
                    
                    packet_responses[icmp_id].append({
                        'sequence': sequence,
                        'payload': base64_payload
                    })
                    
                    # Check if all packets for this ID are received
                    if len(packet_responses[icmp_id]) == total_packets:
                        # Sort and reconstruct payload
                        responses = sorted(packet_responses[icmp_id], key=lambda x: x['sequence'])
                        full_base64_payload = ''.join(resp['payload'] for resp in responses)
                        
                        # Decode payload
                        decoded_payload = base64.b64decode(full_base64_payload).decode('utf-8')
                        
                        # Save payload to file
                        save_payload(decoded_payload)
                        
                        # Send Echo Reply
                        send_echo_reply(recv_packet, addr[0])
                        
                        # Clear responses for this ID
                        del packet_responses[icmp_id]

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")

    except PermissionError:
        print("Error: You need root/admin privileges to receive raw packets.")
        sys.exit(1)

def send_echo_reply(original_packet, source_ip):
    """
    Send an ICMP Echo Reply packet
    """
    try:
        # Create raw socket for sending
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Extract original ICMP header
        icmp_header = original_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('bbHHh', icmp_header)
        
        # Create Echo Reply header (type 0)
        echo_reply_header = struct.pack('bbHHh', 0, 0, socket.htons(icmp_checksum), icmp_id, icmp_seq)
        
        # Add back the original payload
        echo_reply_packet = echo_reply_header + original_packet[28:]
        
        # Send Echo Reply
        send_socket.sendto(echo_reply_packet, (source_ip, 1))
        send_socket.close()

    except Exception as e:
        print(f"Error sending Echo Reply: {e}")

def save_payload(payload):
    """
    Save payload to /root/jasotakoa.txt
    """
    try:
        with open('/root/jasotakoa.txt', 'w') as f:
            f.write(payload)
        print(f"Payload saved to /root/jasotakoa.txt")
    except Exception as e:
        print(f"Error saving payload: {e}")

def main():
    print("Listening for packets...")
    receive_fragmented_payload()

if __name__ == "__main__":
    main()