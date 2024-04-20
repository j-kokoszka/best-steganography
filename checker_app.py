import scapy.all as scapy
import argparse
import re
import base64

def unpadding(data):
    """
    Funkcja usuwa wypełnienie zerami z danych.

    :param data: Dane z wypełnieniem.
    :return: Dane bez wypełnienia.
    """
    return data.rstrip(b'\x00')

# Zaimportowanie funkcji XOR
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
            
            # Zapisanie zdeszyfrowanych danych do pliku binarnego
            with open("decrypted_data.txt", "ab") as file:
                file.write(decrypted_bytes)
            
            # print(f"Deszyfrowane dane dla pakietu {packet.summary()} zapisane do decrypted_data.bin")
    except Exception as e:
        print(f"Błąd podczas deszyfrowania pakietu {packet.summary()}: {e}")

# Funkcja główna
def main(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    for packet in packets:
        if scapy.Raw in packet:
            decrypt_authorization_header(packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send data via HTTP headers.')
    parser.add_argument('pcap_file', type=str, help='pcap file to analyze')
    args = parser.parse_args()
    main(args.pcap_file)