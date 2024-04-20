import scapy.all as scapy
import argparse
import re
import base64
import hashlib

# Calculating sha256 checksum of data
def calculate_sha256(data):
    sha256_hash = hashlib.sha256(data)
    return sha256_hash.hexdigest()

# Unpads chunk from zero filling
def unpadding(data):
    return data.rstrip(b'\x00')

# Decrypting chunk of data using xor
def xor_decrypt(encrypted_chunk):
    key = encrypted_chunk[-256:]
    encrypted_bytes = encrypted_chunk[:-256]
    decrypted_bytes = bytes(encrypted_bytes[i] ^ key[i] for i in range(256))
    return decrypted_bytes

# Funkcja do deszyfrowania nagłówka authorization
def decrypt_authorization_header(packet):
    try:
        # Wyszukanie nagłówka authorization
        authorization_header = re.search(b'Authorization: (.*?)(\\r\\n|\\n)', packet[scapy.Raw].load)
        # print(authorization_header)
        if authorization_header:
            encrypted_data = authorization_header.group(1)
            # print(encrypted_data)
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Deszyfrowanie danych
            decrypted_bytes = xor_decrypt(encrypted_bytes)
            decrypted_bytes = unpadding(decrypted_bytes)
            
            # Return decrypted bytes
            return decrypted_bytes
            
    except Exception as e:
        print(f"Błąd podczas deszyfrowania pakietu {packet.summary()}: {e}")

# Funkcja główna
def main(pcap_file):
    data = b''
    packets = scapy.rdpcap(pcap_file)
    for packet in packets:
        if scapy.Raw in packet:
            tmp = decrypt_authorization_header(packet)
            if tmp:
                data += tmp
    # Compare Sofokles-Antygona.txt checksum with checksum calculated from decrypted data
    if 'ef3c692e25809e17861bdcd44897ceecfb6881b6d9f0c9afa4aa7936fa7ac203' == calculate_sha256(data):
        print("pcap is valid and contains ANTYGONA")
    else:
        print("pcap doesn't contain ANTYGONA")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send data via HTTP headers.')
    parser.add_argument('pcap_file', type=str, help='pcap file to analyze')
    args = parser.parse_args()
    main(args.pcap_file)