import itertools
import numpy as np
import re
from collections import Counter

raw_text = """The artist is the creator of beautiful things. To reveal art 
and conceal the artist is art's aim. The critic is he who can translate 
into another manner or a new material his impression of beautiful things. 
The highest, as the lowest, form of criticism is a mode of autobiography. 
Those who find ugly meanings in beautiful things are corrupt without being 
charming. This is a fault. Those who find beautiful meanings in beautiful 
things are the cultivated. For these there is hope. They are the elect to 
whom beautiful things mean only Beauty. There is no such thing as a moral 
or an immoral book. Books are well written, or badly written. That is all. 
The nineteenth-century dislike of realism is the rage of Caliban seeing his 
own face in a glass. The nineteenth-century dislike of Romanticism is the 
rage of Caliban not seeing his own face in a glass. The moral life of man 
forms part of the subject matter of the artist, but the morality of art 
consists in the perfect use of an imperfect medium. No artist desires to 
prove anything. Even things that are true can be proved. No artist has 
ethical sympathies. An ethical sympathy in an artist is an unpardonable 
mannerism of style. No artist is ever morbid. The artist can express 
everything. Thought and language are to the artist instruments of an art. 
Vice and virtue are to the artist materials for an art. From the point 
of view of form, the type of all the arts is the art of the musician. 
From the point of view of feeling, the actor's craft is the type. All 
art is at once surface and symbol. Those who go beneath the surface 
do so at their peril. Those who read the symbol do so at their peril. 
It is the spectator, and not life, that art really mirrors. Diversity 
of opinion about a work of art shows that the work is new, complex, 
vital. When critics disagree the artist is in accord with himself. 
We can forgive a man for making a useful thing as long as he does not 
admire it. The only excuse for making a useless thing is that one 
admires it intensely. All art is quite useless.
"""

# Vigenère Cipher Implementation
def vigenere_encrypt(text, key):
    key = itertools.cycle(key)
    return ''.join(chr(((ord(t) - 65 + ord(next(key)) - 65) % 26) + 65) for t in text.upper() if t.isalpha())

def vigenere_decrypt(ciphertext, key):
    key = itertools.cycle(key)
    return ''.join(chr(((ord(c) - 65 - (ord(next(key)) - 65)) % 26) + 65) for c in ciphertext.upper() if c.isalpha())

# Kasiski Examination for finding repeated sequences
def kasiski_examination(ciphertext):
    ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
    sequences = {}
    for i in range(len(ciphertext) - 2):
        seq = ciphertext[i:i+3]
        if seq in sequences:
            sequences[seq].append(i)
        else:
            sequences[seq] = [i]
    distances = [j - i for seq in sequences.values() for i, j in zip(seq, seq[1:]) if len(seq) > 1]
    common_factors = Counter()
    for d in distances:
        for f in range(2, d + 1):
            if d % f == 0:
                common_factors[f] += 1
    return common_factors.most_common()

# Simple Transposition Cipher
def simple_transposition_encrypt(text, key):
    order = sorted(range(len(key)), key=lambda k: key[k])
    columns = [''] * len(key)
    for i, letter in enumerate(text):
        columns[i % len(key)] += letter
    return ''.join(columns[o] for o in order)

def simple_transposition_decrypt(ciphertext, key):
    order = sorted(range(len(key)), key=lambda k: key[k])
    num_rows = len(ciphertext) // len(key) + (len(ciphertext) % len(key) > 0)
    grid = [''] * len(key)
    start = 0
    for o in order:
        length = num_rows if o < len(ciphertext) % len(key) else num_rows - 1
        grid[o] = ciphertext[start:start+length]
        start += length
    return ''.join(''.join(row[i] for row in grid if i < len(row)) for i in range(num_rows))

# Double Transposition Cipher
def double_transposition_encrypt(text, key1, key2):
    first_pass = simple_transposition_encrypt(text, key1)
    return simple_transposition_encrypt(first_pass, key2)

def double_transposition_decrypt(ciphertext, key1, key2):
    first_pass = simple_transposition_decrypt(ciphertext, key2)
    return simple_transposition_decrypt(first_pass, key1)

# Table Cipher Implementation
def table_cipher_encrypt(text, key):
    size = len(key)
    padded_text = text.ljust((len(text) // size + 1) * size)  # Ensure grid is properly padded
    grid = np.array(list(padded_text))
    grid.shape = (-1, size)  # Dynamically adjust row size
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    return ''.join(grid[:, i].tobytes().decode('utf-8') for i in key_order)

def table_cipher_decrypt(ciphertext, key):
    size = len(key)
    num_rows = len(ciphertext) // size
    grid = np.array(list(ciphertext)).reshape(num_rows, size)
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    decrypted = [''] * num_rows * size
    for i, o in enumerate(key_order):
        decrypted[o::size] = grid[:, i]
    return ''.join(decrypted).strip()


# Combined Encryption (Vigenère -> Table Cipher)
def combined_encrypt(text, vigenere_key, table_key):
    encrypted_text = vigenere_encrypt(text, vigenere_key)
    return table_cipher_encrypt(encrypted_text, table_key)

def combined_decrypt(ciphertext, vigenere_key, table_key):
    decrypted_text = table_cipher_decrypt(ciphertext, table_key)
    return vigenere_decrypt(decrypted_text, vigenere_key)

# Vigenère Cipher Execution
encrypted = vigenere_encrypt(raw_text, "CRYPTOGRAPHY")
decrypted = vigenere_decrypt(raw_text, "CRYPTOGRAPHY")
print("Encrypted Vigenère Cipher:", encrypted)
print("Decrypted Vigenère Cipher:", decrypted)

# Applying Kasiski Examination
kasiski_result = kasiski_examination(encrypted)
print("Kasiski Examination Result:", kasiski_result)

# Simple Transposition Cipher Execution
encrypted = simple_transposition_encrypt(raw_text, "SECRET")
decrypted = simple_transposition_decrypt(raw_text, "SECRET")
print("Encrypted Simple Transposition Cipher:", encrypted)
print("Decrypted Simple Transposition Cipher:", decrypted)

# Double Transposition Cipher Execution
encrypted = double_transposition_encrypt(raw_text, "SECRET", "CRYPTO")
decrypted = double_transposition_decrypt(raw_text, "SECRET", "CRYPTO")
print("Encrypted Double Transposition Cipher:", encrypted)
print("Decrypted Double Transposition Cipher:", decrypted)

# Table Cipher Execution
encrypted = table_cipher_encrypt(raw_text, "MATRIX")
decrypted = table_cipher_decrypt(encrypted, "MATRIX")
print("Encrypted Table Cipher:", encrypted)
print("Decrypted Table Cipher:", decrypted)

# Double Transposition Cipher Execution
encrypted = combined_encrypt(raw_text, "CRYPTOGRAPHY", "MATRIX")
decrypted = combined_decrypt(encrypted, "CRYPTOGRAPHY", "MATRIX")
print("Encrypted Combined:", encrypted)
print("Decrypted Combined:", decrypted)

