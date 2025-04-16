import os
import json
import random
import gmpy2
import time
from gmpy2 import mpz, powmod, invert

# Generate large prime numbers for Paillier key generation
def generate_large_prime(bits):
    while True:
        prime = gmpy2.next_prime(random.getrandbits(bits))
        if gmpy2.is_prime(prime, 25):
            return prime

# Generate Paillier keys with time measurement
def generate_paillier_keys(bits=512):
    start_time = time.time()
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    n2 = n * n
    lambda_n = gmpy2.lcm(p-1, q-1)
    g = n + 1
    L = lambda x: (x - 1) // n
    mu = invert(L(powmod(g, lambda_n, n2)), n)
    public_key = (n, g, n2)
    private_key = (lambda_n, mu)
    end_time = time.time()
    keygen_time = end_time - start_time
    print(f"🔐 Key Generation Time: {keygen_time:.6f} seconds")
    return public_key, private_key, keygen_time

# Save public key to a JSON file
def save_public_key(public_key, filename="pubkey.json"):
    n, g, n2 = public_key
    with open(filename, "w") as f:
        json.dump({"n": str(n), "g": str(g), "n_squared": str(n2)}, f)
    print(f"✅ Public key saved to '{filename}'.")

# Save private key to a JSON file
def save_private_key(private_key, filename="privkey.json"):
    lambda_n, mu = private_key
    with open(filename, "w") as f:
        json.dump({"lambda": str(lambda_n), "mu": str(mu)}, f)
    print(f"✅ Private key saved to '{filename}'.")

# Encrypt a number using Paillier with padding
def encrypt(plain, public_key):
    n, g, n2 = public_key
    plain = mpz(plain)
    padding = random.randint(1, n // 2)
    padded_plain = plain * n + padding
    r = random.randint(1, n - 1)
    while gmpy2.gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    cipher = (powmod(g, padded_plain, n2) * powmod(r, n, n2)) % n2
    return int(cipher)

# Decrypt a number and remove padding
def decrypt(cipher, public_key, private_key):
    n, g, n2 = public_key
    lambda_n, mu = private_key
    L = lambda x: (x - 1) // n
    padded_plain = (L(powmod(cipher, lambda_n, n2)) * mu) % n
    original_message = padded_plain // n
    return int(original_message)

# Encrypt a single file
def encrypt_file(input_file, output_file, public_key):
    start_time = time.time()
    with open(input_file, "r") as f:
        content = f.read().splitlines()
    encrypted_data = []
    for line in content:
        numbers = line.split()
        encrypted_numbers = [encrypt(int(num), public_key) for num in numbers]
        encrypted_data.append(encrypted_numbers)
    with open(output_file, "w") as f:
        json.dump(encrypted_data, f)
    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"📦 File '{input_file}' encrypted and saved as '{output_file}'. Time taken: {encryption_time:.6f} seconds.")
    return encryption_time

# Encrypt all files in a folder
def encrypt_multiple_files(input_folder, output_folder, public_key):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    encryption_times = {}
    for filename in os.listdir(input_folder):
        input_file_path = os.path.join(input_folder, filename)
        output_file_path = os.path.join(output_folder, filename + "_encrypted.json")
        if os.path.isfile(input_file_path):
            encryption_time = encrypt_file(input_file_path, output_file_path, public_key)
            encryption_times[filename] = encryption_time
    return encryption_times

# ============================== Main Execution ==============================

print("\n🔐 Generating Paillier keys...")
pub_key, priv_key, keygen_time = generate_paillier_keys(512)
print("✅ Keys generated successfully!")

save_public_key(pub_key)   # Save public key
save_private_key(priv_key) # Save private key

print("\n📁 Encrypting files in 'data_files' folder...")
encryption_times = encrypt_multiple_files("data_files", "encrypted_files", pub_key)

print("\n✅ All files encrypted successfully!")

print("\n📊 Summary:")
print(f"🔐 Key Generation Time: {keygen_time:.6f} seconds")
for filename, enc_time in encryption_times.items():
    print(f"🕒 Encryption Time for '{filename}': {enc_time:.6f} seconds")
