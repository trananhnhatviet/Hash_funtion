# Twin Keys

Chall này đưa ta 1 source code như sau:
```
import os
import random
from Crypto.Hash import MD5
from utils import listener

KEY_START = b"CryptoHack Secure Safe"
FLAG = b"crypto{????????????????????????????}"


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


class SecureSafe:
    def __init__(self):
        self.magic1 = os.urandom(16)
        self.magic2 = os.urandom(16)
        self.keys = {}

    def insert_key(self, key):
        if len(self.keys) >= 2:
            return {"error": "All keyholes are already occupied"}
        if key in self.keys:
            return {"error": "This key is already inserted"}

        self.keys[key] = 0
        if key.startswith(KEY_START):
            self.keys[key] = 1

        return {"msg": f"Key inserted"}

    def unlock(self):
        if len(self.keys) < 2:
            return {"error": "Missing keys"}

        if sum(self.keys.values()) != 1:
            return {"error": "Invalid keys"}

        hashes = []
        for k in self.keys.keys():
            hashes.append(MD5.new(k).digest())

        # Encrypting the hashes with secure quad-grade XOR encryption
        # Using different randomized magic numbers to prevent the hashes
        # from ever being equal
        h1 = hashes[0]
        h2 = hashes[1]
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)

        assert h1 != bytes(bytearray(16))

        if h1 == h2:
            return {"msg": f"The safe clicks and the door opens. Amongst its secrets you find a flag: {FLAG}"}
        return {"error": "The keys does not match"}


class Challenge():
    def __init__(self):
        self.securesafe = SecureSafe()
        self.before_input = "Can you help find our lost keys to unlock the safe?\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}
        elif your_input['option'] == 'insert_key':
            key = bytes.fromhex(your_input["key"])
            return self.securesafe.insert_key(key)
        elif your_input['option'] == 'unlock':
            return self.securesafe.unlock()
        else:
            return {"error": "Invalid option"}


listener.start_server(port=13397)
```

Nhìn vào code, thì ta sẽ phải tạo 1 collision từ 2 key, trong key phải có ``CryptoHack Secure Safe`` vì chỉ khi có KEY_START thì keys[key] mới lên được 1 và điều kiện ``sum(self.keys.values()) != 1:`` mới vượt qua được

Tiếp theo, ta thấy xor rất nhiều với magic, thế nhưng mình không cần quá quan tâm đến nó

Mục tiêu của ta là tạo collision mà bắt đầu là ``CryptoHack Secure Safe``

Ta sử dụng tool Hashclash để giải challenge này

Tạo 1 folder mới và dùng các câu lệnh như sauu
```
echo "CryptoHack Secure SafeX" > prefix.txt (để như này thì keys[key] mới lên 1 được)
../scripts/poc_no.sh prefix.txt
```
Sau khi chạy xong, thì mình sẽ thu được 2 file ``collision``, mở ra dưới dạng byte và chuyển về hexadecimal, ta thu được 2 đoạn hex như sau:
```
43727970746f4861636b205365637572652053616665580ab40eede6e039d78be17792b296bb255aa3b5a82b08f4a63f352b32fcc59dcb76b5ddbe4f6ea16e371ae0894263964fbe52f7a5361082d6ef31f8e711cf05d83b53a54be1d9a4d55c623b73b69a6742cdfcbe11a7449cfb1ada4c5b2dc9e3f2062e37c38b04d71745

43727970746f4861636c20536563757265205352b32fcc59dcb76b5ddbe4f6ea16e371ae0894263964fbe52f6a5361082d6ef31f8e711cf05d83b53a54be1d9a4d55c623b73b69a6742cdfcbe11a7449cfb1ada4c5b2dc9e3f2062e37c38b04d71745
```

Giờ gửi lên server thui <3
```
from pwn import*

io = remote('socket.cryptohack.org',13397)
io.recvuntil(b'Can you help find our lost keys to unlock the safe?\n')
io.sendline(b'{"option": "insert_key", "key": "43727970746f4861636b205365637572652053616665580ab40eede6e039d78be17792b296bb255aa3b5a82b08f4a63f352b32fcc59dcb76b5ddbe4f6ea16e371ae0894263964fbe52f7a5361082d6ef31f8e711cf05d83b53a54be1d9a4d55c623b73b69a6742cdfcbe11a7449cfb1ada4c5b2dc9e3f2062e37c38b04d71745"}')
io.recvuntil(b'{"msg": "Key inserted"}\n')
io.sendline(b'{"option": "insert_key", "key": "43727970746f4861636c205365637572652053616665580ab40eede6e039d78be17792b296bb255aa3b5a82b08f4a63f352b32fcc59dcb76b5ddbe4f6ea16e371ae0894263964fbe52f6a5361082d6ef31f8e711cf05d83b53a54be1d9a4d55c623b73b69a6742cdfcbe11a7449cfb1ada4c5b2dc9e3f2062e37c38b04d71745"}')
io.recvuntil(b'{"msg": "Key inserted"}\n')
io.sendline(b'{"option": "unlock"}')

io.interactive()
```

Flag của challenge này là: **crypto{MD5_15_0n_4_c0ll151On_c0uRz3}**