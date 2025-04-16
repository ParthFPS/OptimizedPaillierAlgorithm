import json
from gmpy2 import mpz, powmod

# Load public key
def load_public_key(filename="pubkey.json"):
    with open(filename, "r") as f:
        key = json.load(f)
    return mpz(key["n"]), mpz(key["g"]), mpz(key["n2"])

# Load private key
def load_private_key(filename="privkey.json"):
    with open(filename, "r") as f:
        key = json.load(f)
    return mpz(key["lambda"]), mpz(key["mu"])

# Decrypt a single number
def decrypt(cipher, public_key, private_key):
    n, g, n2 = public_key
    lambda_n, mu = private_key
    L = lambda x: (x - 1) // n
    padded_plain = (L(powmod(cipher, lambda_n, n2)) * mu) % n
    original_message = padded_plain // n
    return int(original_message)

# Decrypt an encrypted file
def decrypt_file(encrypted_file, output_file, public_key, private_key):
    with open(encrypted_file, "r") as f:
        encrypted_data = json.load(f)

    decrypted_lines = []
    for line in encrypted_data:
        decrypted_nums = [decrypt(mpz(num), public_key, private_key) for num in line]
        decrypted_lines.append(" ".join(map(str, decrypted_nums)))

    with open(output_file, "w") as f:
        f.write("\n".join(decrypted_lines))

    print(f"✅ Decrypted data written to '{output_file}'")

# ==================== MAIN ====================

# Customize these if needed
input_file = "file1x3.txt_encrypted.json"
output_file = "file1x3_decrypted.txt"

public_key = load_public_key()
private_key = load_private_key()
decrypt_file(input_file, output_file, public_key, private_key)
