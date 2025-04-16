import json
from gmpy2 import mpz, mul, f_mod

def load_json_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def save_json_file(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f)

def homomorphic_addition(cipher1, cipher2, n_squared):
    # Paillier addition: c1 * c2 mod n^2
    return [int(f_mod(mul(mpz(c1), mpz(c2)), mpz(n_squared))) for c1, c2 in zip(cipher1, cipher2)]

# Load public key
pubkey = load_json_file("pubkey.json")  # Format: {"n": <int>}
n = mpz(pubkey["n"])
n_squared = n * n

# Load encrypted inputs
ciphertext1 = load_json_file("file1.txt_encrypted.json")
ciphertext2 = load_json_file("file2.txt_encrypted.json")

# Perform homomorphic addition
result_ciphertext = homomorphic_addition(ciphertext1, ciphertext2, n_squared)

# Save result
save_json_file(result_ciphertext, "file12.txt_encrypted.json")

print("Homomorphic addition complete. Result saved in file12.txt_encrypted.json")
