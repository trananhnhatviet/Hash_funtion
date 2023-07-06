# Hash Stuffing

<img width="1032" alt="image" src="https://github.com/trananhnhatviet/Hash_funtion/assets/92376163/fad0e05a-3b4d-4a10-b5b7-aa19f75bf6bd">


Chall đưa ta source code như sau:

```# 2^128 collision protection!
BLOCK_SIZE = 32

# Nothing up my sleeve numbers (ref: Dual_EC_DRBG P-256 coordinates)
W = [0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296]
X = [0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5]
Y = [0xc97445f4, 0x5cdef9f0, 0xd3e05e1e, 0x585fc297, 0x235b82b5, 0xbe8ff3ef, 0xca67c598, 0x52018192]
Z = [0xb28ef557, 0xba31dfcb, 0xdd21ac46, 0xe2a91e3c, 0x304f44cb, 0x87058ada, 0x2cb81515, 0x1e610046]

# Lets work with bytes instead!
W_bytes = b''.join([x.to_bytes(4,'big') for x in W])
X_bytes = b''.join([x.to_bytes(4,'big') for x in X])
Y_bytes = b''.join([x.to_bytes(4,'big') for x in Y])
Z_bytes = b''.join([x.to_bytes(4,'big') for x in Z])

def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)

def blocks(data):
    return [data[i:(i+BLOCK_SIZE)] for i in range(0,len(data),BLOCK_SIZE)]

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def rotate_left(data, x):
    x = x % BLOCK_SIZE
    return data[x:] + data[:x]

def rotate_right(data, x):
    x = x % BLOCK_SIZE
    return  data[-x:] + data[:-x]

def scramble_block(block):
    for _ in range(40):
        block = xor(W_bytes, block)
        block = rotate_left(block, 6)
        block = xor(X_bytes, block)
        block = rotate_right(block, 17)
    return block

def cryptohash(msg):
    initial_state = xor(Y_bytes, Z_bytes)
    msg_padded = pad(msg)
    msg_blocks = blocks(msg_padded)
    for i,b in enumerate(msg_blocks):
        mix_in = scramble_block(b)
        for _ in range(i):
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
        initial_state = xor(initial_state,mix_in)
    return initial_state.hex()

```

Chall này, khi ta nhập 2 đoạn msg khác nhau, chúng sẽ cryptohash lại và kiểm tra, nếu giống nhau thì sẽ lấy được flag

Nhìn thuật toán có vẻ khá phức tạp đúng không, là kiểm tra 2 msg trước khi pad, ta sẽ nhập 2 msg trước và sau khi pad vào

Giờ ta thử nhập 2 message khác nhau, message ``msg_1`` và ``msg_2`` (sau khi pad từ msg_1) thì sau khi hash sẽ thu được 2 đoạn giống hệt nhau

```
msg_1 = bytes.fromhex('aa'*31)
msg_2 = bytes.fromhex('aa'*31+'01')
print(pad(msg_1))
print(pad(msg_2))
```

Giờ ta sẽ gửi vào server 2 đoạn là ``'aa'*31`` và ``'aa'*31 + '01'`` là sẽ thu được flag thuii

```
from pwn import*

context.log_level = 'debug'

io = remote('socket.cryptohack.org',13405)

io.recvuntil(b'Please send two hex encoded messages m1, m2 formatted in JSON: ')

msg_1 = 'aa'*31
msg_2 = 'aa'*31+'01'

send = f'{{"m1":"{msg_1}","m2":"{msg_2}"}}'
io.sendline(send.encode())

io.interactive()
```

Flag của chall này là: **crypto{Always_add_padding_even_if_its_a_whole_block!!!}**
