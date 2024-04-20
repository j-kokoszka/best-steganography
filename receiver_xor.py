from flask import Flask, request
import base64
import random

app = Flask(__name__)

def unpadding(data):
    """
    Funkcja usuwa wypełnienie zerami z danych.

    :param data: Dane z wypełnieniem.
    :return: Dane bez wypełnienia.
    """
    return data.rstrip(b'\x00')

def xor_decrypt(encrypted_chunk):
    """
    Funkcja wykonuje odwrotną operację XOR na podanym zaszyfrowanym ciągu bajtów i wyciąga klucz z końca ciągu.

    :param encrypted_chunk: Zaszyfrowany ciąg bajtów o długości 512.
    :return: Odszyfrowany ciąg bajtów o długości 256 oraz klucz (ciąg bajtów) o długości 256.
    """
    # Wyciągnięcie klucza z końca zaszyfrowanego ciągu
    key = encrypted_chunk[-256:]
    
    # Usunięcie klucza z ciągu bajtów
    encrypted_bytes = encrypted_chunk[:-256]

    # Wykonanie operacji XOR na każdym bajcie
    decrypted_bytes = bytes(encrypted_bytes[i] ^ key[i] for i in range(256))

    return decrypted_bytes, key

@app.route('/', methods=['GET'])
def receive_data():
    encoded_data = request.headers.get('Authorization')
    if encoded_data:
        
        decoded_data = base64.b64decode(encoded_data.encode())  # Decode the base64 encoded data
        decoded_data, key = xor_decrypt(decoded_data)
        decoded_data = unpadding(decoded_data)
        with open("received_data.txt", "ab") as file:  # Append in binary mode
            file.write(decoded_data)
        return "Data received successfully.", 200
    else:
        return "No data received.", 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)

