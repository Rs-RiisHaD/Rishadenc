import os
import marshal
import zlib
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from colorama import init

init(autoreset=True)

# রঙের কোডগুলো
biblack = "\033[1;90m"
bired = "\033[1;91m"
bigreen = "\033[1;92m"
biyellow = "\033[1;93m"
biblue = "\033[1;94m"
bipurple = "\033[1;95m"
bicyan = "\033[1;96m"
biehite = "\033[1;97m"
reset = "\033[0m"

colors = [bired, bigreen, biyellow, biblue, bipurple, bicyan]

def print_rishad_name(name):
    for i, ch in enumerate(name):
        print(colors[i % len(colors)] + ch, end='')
    print(reset)

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(bipurple + """
██████╗░██╗░██████╗██╗░░██╗░█████╗░██████╗░
██╔══██╗██║██╔════╝██║░░██║██╔══██╗██╔══██╗
██████╔╝██║╚█████╗░███████║███████║██║░░██║
██╔══██╗██║░╚═══██╗██╔══██║██╔══██║██║░░██║
██║░░██║██║██████╔╝██║░░██║██║░░██║██████╔╝
╚═╝░░╚═╝╚═╝╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░""" + reset)
    print(bipurple + "="*62 + reset)
    print(bigreen + "[+] AUTHOR       :  ", end='')
    print_rishad_name("RISHAD SOBUJ")
    print(bigreen + "[+] FACEBOOK     :  @AlpHaRisHaD.33" + reset)
    print(bigreen + "[+] GITHUB       :  github.com" + reset)
    print(bigreen + "[+] TEAM         :  null" + reset)
    print(bigreen + "[+] TOOLS        :  ENCRYPTOR TOOL" + reset)
    print(bipurple + "="*62 + reset + "\n")

def random_key(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)).encode()

def generate_loader_code(mode, data_str, key_hex=None, outname="output.py"):
    if mode == 1:
        loader = f"""import marshal
code = {data_str}
exec(marshal.loads(code))"""
    elif mode == 2:
        loader = f"""import marshal, zlib
data = {data_str}
exec(marshal.loads(zlib.decompress(data)))"""
    elif mode == 3:
        loader = f"""import marshal, zlib, base64
data = base64.b64decode({data_str})
exec(marshal.loads(zlib.decompress(data)))"""
    elif mode == 4:
        loader = f"""import base64, marshal, zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('{key_hex}')

def rot13_bytes(b):
    s = b.decode('latin1')
    trans = str.maketrans(
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    return s.translate(trans).encode('latin1')

def decrypt(data):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

enc = {data_str}
data = base64.b64decode(enc)
decrypted = decrypt(data)
decoded_rot = rot13_bytes(decrypted)
decompressed = zlib.decompress(decoded_rot)
exec(marshal.loads(decompressed))
"""
    else:
        raise ValueError("Invalid mode")

    with open(outname, "w", encoding="utf-8") as f:
        f.write(loader)

def show_footer():
    msg = "This Tools made by Rishad Sobuj 💚"
    styled = ""
    for i, ch in enumerate(msg):
        styled += colors[i % len(colors)] + ch
    print("\n" + styled + reset + "\n")

def main():
    while True:
        print_header()

        print(biyellow + "Choose encryption mode:")
        print(bired + "1." + bigreen + " Marshal only")
        print(bired + "2." + bigreen + " Marshal + zlib")
        print(bired + "3." + bigreen + " Marshal + zlib + base64")
        print(bired + "4." + bigreen + " Full mix (marshal + zlib + base64 + rot13 + AES)")
        print(bired + "0." + bigreen + " Exit\n")

        choice = input(biyellow + "Enter choice (0-4): " + biehite).strip()
        if choice == '0':
            print(bigreen + "\nExiting program. Goodbye!" + reset)
            break
        if choice not in ['1','2','3','4']:
            print(bired + "Invalid choice! Please try again." + reset)
            input("Press Enter to continue...")
            continue

        mode = int(choice)

        filepath = input(biyellow + "\nEnter your python file path (e.g. /sdcard/test.py): " + biehite).strip()
        if not os.path.isfile(filepath):
            print(bired + "File not found! Please try again." + reset)
            input("Press Enter to continue...")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()

        marshaled = marshal.dumps(compile(source, filepath, "exec"))

        if mode == 1:
            data_str = repr(marshaled)
            outname = f"marshal_{os.path.basename(filepath)}"
        elif mode == 2:
            compressed = zlib.compress(marshaled, 9)
            data_str = repr(compressed)
            outname = f"marshal_zlib_{os.path.basename(filepath)}"
        elif mode == 3:
            compressed = zlib.compress(marshaled, 9)
            b64data = base64.b64encode(compressed).decode()
            data_str = repr(b64data)
            outname = f"marshal_zlib_base64_{os.path.basename(filepath)}"
        else:  # mode 4
            compressed = zlib.compress(marshaled, 9)
            b85data = base64.b85encode(compressed)
            def rot13_bytes(b):
                s = b.decode('latin1')
                trans = str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
                return s.translate(trans).encode('latin1')
            rot_data = rot13_bytes(b85data)
            key = random_key(16)
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            cipher = AES.new(key, AES.MODE_CBC)
            ct = cipher.encrypt(pad(rot_data, AES.block_size))
            final_data = cipher.iv + ct
            b64_final = base64.b64encode(final_data).decode()
            data_str = repr(b64_final)
            outname = f"mixed_enc_{os.path.basename(filepath)}"

        key_hex = key.hex() if mode == 4 else None
        generate_loader_code(mode, data_str, key_hex, outname)
        print(bigreen + f"\n[✔] Encrypted file saved as: {outname}" + reset)

        show_footer()

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
