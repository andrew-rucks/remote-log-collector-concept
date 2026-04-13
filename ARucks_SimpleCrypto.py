# Andrew Rucks
# 4/10/2026
# SIMPLE SYMMETRIC ENCRYPTION AND DECRYPTION MODULE

# I made this simple encryption module because I didn't want to install an external library.
# Combines substitution and transposition based on a user-provided key string, and for a user-provided number of iterations.
# Not extremely secure but it gets the job done.
# Longer key + more iterations = more secure.

import random
import hashlib

# ENCRYPTS TEXT DATA, RETURNS BYTES
def encrypt(data, key, iterations=1):

    while iterations > 0:

        # mutate the key
        key = hashlib.sha256(key.encode("utf-8")).hexdigest()

        # SHUFFLE
        rng = random.Random(key)
        #print(rng.randint(0, 255))
        data = list(data)  # make a copy
        n = len(data)
        
        # "Fisher-Yates shuffle"
        swaps = []
        for i in range(n - 1, 0, -1):
            j = rng.randint(0, i)
            swaps.append((i, j))
            data[i], data[j] = data[j], data[i]

        data = ''.join(data)

        # repeat the key until it matches the length of the text - AI helped with this
        repeated_key = (key * (len(data) // len(key) + 1))[:len(data)]

        # XOR bitwise operation on each character - AI helped with this
        data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, repeated_key))

        iterations -= 1

    return data.encode("utf-8")


# DECRYPTS BYTES, RETURNS TEXT DATA
def decrypt(data, key, iterations=1):

    data = data.decode("utf-8")

    key_arr = []
    i = iterations
    while i > 0:
        # pre calculate the key mutations
        key = hashlib.sha256(key.encode("utf-8")).hexdigest()
        key_arr.append(key)
        i -= 1

    while iterations > 0:

        key = key_arr[iterations - 1]

        # Repeat the key until it matches the length of the text
        repeated_key = (key * (len(data) // len(key) + 1))[:len(data)]

        # Perform XOR bitwise operation on each character
        data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, repeated_key))

        # UNSHUFFLE
        rng = random.Random(key)
        data = list(data)
        n = len(data)
        
        # recreate the same swaps
        swaps = []
        for i in range(n - 1, 0, -1):
            j = rng.randint(0, i)
            swaps.append((i, j))
        
        # reverse the swaps
        for i, j in reversed(swaps):
            data[i], data[j] = data[j], data[i]

        data = ''.join(data)

        iterations -= 1

    return data