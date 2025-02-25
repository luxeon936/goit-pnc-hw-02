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
def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_index = 0
    key = key.upper()

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                original_pos = ord(char) - ord('A')
                new_pos = (original_pos + shift) % 26
                new_char = chr(new_pos + ord('A'))
                ciphertext.append(new_char)
            else:
                original_pos = ord(char) - ord('a')
                new_pos = (original_pos + shift) % 26
                new_char = chr(new_pos + ord('a'))
                ciphertext.append(new_char)

            key_index += 1
        else:
            ciphertext.append(char)

    return "".join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key_index = 0
    key = key.upper()

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                original_pos = ord(char) - ord('A')
                new_pos = (original_pos - shift) % 26
                new_char = chr(new_pos + ord('A'))
                plaintext.append(new_char)
            else:
                original_pos = ord(char) - ord('a')
                new_pos = (original_pos - shift) % 26
                new_char = chr(new_pos + ord('a'))
                plaintext.append(new_char)

            key_index += 1
        else:
            plaintext.append(char)

    return "".join(plaintext)

def index_of_coincidence(ciphertext):
    filtered = [ch.upper() for ch in ciphertext if ch.isalpha()]
    N = len(filtered)
    if N < 2:
        return 0.0
    freq = {}
    for ch in filtered:
        freq[ch] = freq.get(ch, 0) + 1
    numerator = sum(count * (count - 1) for count in freq.values())
    denominator = N * (N - 1)
    return numerator / denominator if denominator else 0.0


def friedman_test(ciphertext):
    ic = index_of_coincidence(ciphertext)
    if ic <= 0 or (ic - 0.0385) == 0:
        return 1.0
    K_approx = 0.0279 / (ic - 0.0385) + 1
    return K_approx


def guess_vigenere_key(ciphertext, max_key_len=20):
    approx_len = int(round(friedman_test(ciphertext)))
    candidates = range(max(1, approx_len-2), min(max_key_len, approx_len+3))
    best_key = ""
    best_score = float('-inf')
    for length_candidate in candidates:
        columns = split_into_columns(ciphertext, length_candidate)

        shifts = [guess_shift_by_frequency(col) for col in columns]
        candidate_key = "".join(chr(s + ord('A')) for s in shifts)
        decrypted_candidate = vigenere_decrypt(ciphertext, candidate_key)
        score_val = compute_english_score(decrypted_candidate)
        if score_val > best_score:
            best_score = score_val
            best_key = candidate_key
    return best_key

def split_into_columns(ciphertext, key_length):
    filtered = [ch.upper() for ch in ciphertext if ch.isalpha()]
    columns = [[] for _ in range(key_length)]
    for i, ch in enumerate(filtered):
        columns[i % key_length].append(ch)
    return ["".join(col) for col in columns]

def guess_shift_by_frequency(column):
    best_shift = 0
    best_score = float('inf')

    for shift in range(26):
        decrypted_col = apply_shift(column, -shift)
        diff = compare_with_english_freq(decrypted_col)
        if diff < best_score:
            best_score = diff
            best_shift = shift

    return best_shift

def apply_shift(text, shift):
    res = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            new_ord = (ord(ch) - ord('A') + shift) % 26 + ord('A')
            res.append(chr(new_ord))
        else:
            res.append(ch)
    return "".join(res)

def compare_with_english_freq(text):
    english_freq = {
        'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
        'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
        'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
        'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
        'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
        'Z': 0.00074
    }
    length = len(text)
    if length == 0:
        return 9999.0
    freq = {ch: 0 for ch in english_freq.keys()}
    for ch in text:
        if ch in freq:
            freq[ch] += 1
    for ch in freq:
        freq[ch] = freq[ch] / length
    total_diff = 0.0
    for letter in english_freq:
        total_diff += abs(freq[letter] - english_freq[letter])

    return total_diff

def compute_english_score(decrypted_text):
    vowels = set("AEIOUaeiou")
    spaces = decrypted_text.count(' ')
    vowels_count = sum(ch in vowels for ch in decrypted_text)
    score = spaces + 0.5 * vowels_count
    return score

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
def get_key_order(key):
    return sorted(range(len(key)), key=lambda k: key[k])

# Табличний шифр (шифрування)
def table_cipher_encrypt(text, key):
    size = len(key)
    padded_text = text.ljust((len(text) // size + 1) * size)
    grid = np.array(list(padded_text)).reshape(-1, size)
    key_order = get_key_order(key)
    return ''.join(grid[:, i].tobytes().decode('utf-8') for i in key_order)

# Табличний шифр (дешифрування)
def table_cipher_decrypt(ciphertext, key):
    size = len(key)
    num_rows = len(ciphertext) // size
    key_order = get_key_order(key)
    grid = np.empty((num_rows, size), dtype=str)
    chunks = [ciphertext[i * num_rows:(i + 1) * num_rows] for i in range(size)]
    for i, col_idx in enumerate(key_order):
        grid[:, col_idx] = list(chunks[i])
    return ''.join(grid.flatten()).rstrip()

# Combined Encryption (Vigenère -> Table Cipher)
def combined_encrypt(text, vigenere_key, table_key):
    encrypted_text = vigenere_encrypt(text, vigenere_key)
    return table_cipher_encrypt(encrypted_text, table_key)

def combined_decrypt(ciphertext, vigenere_key, table_key):
    decrypted_text = table_cipher_decrypt(ciphertext, table_key)
    return vigenere_decrypt(decrypted_text, vigenere_key)

# Vigenère Cipher Execution
encrypted = vigenere_encrypt(raw_text, "CRYPTOGRAPHY")
decrypted = vigenere_decrypt(encrypted, "CRYPTOGRAPHY")
#print("Encrypted Vigenère Cipher:", encrypted)
#print("Decrypted Vigenère Cipher:", decrypted)

# Applying Kasiski Examination
print("Guessed key length", friedman_test(encrypted))

guessed_key = guess_vigenere_key(encrypted)
#print("Guessed key with Fridman", guessed_key)

# Simple Transposition Cipher Execution
encrypted = simple_transposition_encrypt(raw_text, "SECRET")
decrypted = simple_transposition_decrypt(encrypted, "SECRET")
#print("Encrypted Simple Transposition Cipher:", encrypted)
#print("Decrypted Simple Transposition Cipher:", decrypted)

# Double Transposition Cipher Execution
encrypted = double_transposition_encrypt(raw_text, "SECRET", "CRYPTO")
decrypted = double_transposition_decrypt(encrypted, "SECRET", "CRYPTO")
#print("Encrypted Double Transposition Cipher:", encrypted)
#print("Decrypted Double Transposition Cipher:", decrypted)

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