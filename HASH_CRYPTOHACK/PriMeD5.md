# PriMeD5
Chall đưa ta source code như sau:
```
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import long_to_bytes, isPrime
import math
from utils import listener
# from secrets import N, E, D

FLAG = "crypto{??????????????????}"


key = RSA.construct((N, E, D))
sig_scheme = pkcs1_15.new(key)


class Challenge():
    def __init__(self):
        self.before_input = "Primality checking is expensive so I made a service that signs primes, allowing anyone to quickly check if a number is prime\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            p = int(msg["prime"])
            if p.bit_length() > 1024:
                return {"error": "The prime is too large."}
            if not isPrime(p):
                return {"error": "You must specify a prime."}

            hash = MD5.new(long_to_bytes(p))
            sig = sig_scheme.sign(hash)
            return {"signature": sig.hex()}

        elif msg["option"] == "check":
            p = int(msg["prime"])
            sig = bytes.fromhex(msg["signature"])
            hash = MD5.new(long_to_bytes(p))
            try:
                sig_scheme.verify(hash, sig)
            except ValueError:
                return {"error": "Invalid signature."}

            a = int(msg["a"])
            if a < 1:
                return {"error": "`a` value invalid"}
            if a >= p:
                return {"error": "`a` value too large"}
            g = math.gcd(a, p)
            flag_byte = FLAG[:g]
            return {"msg": f"Valid signature. First byte of flag: {flag_byte}"}

        else:
            return {"error": "Unknown option."}


listener.start_server(port=13392)

```
Ta thấy được 1 đoạn
```
key = RSA.construct((N, E, D))
sig_scheme = pkcs1_15.new(key)
```
Đây chính là 1 đối tượng chữ ký RSA, kết hợp khóa riêng tư và hàm băm để tạo ra 1 signature với 1 số đầu vào.

Nhìn vào code, ta thấy rằng khi ta nhập 1 số nguyên tố, server sẽ hash md5 số đó và ta sẽ thu được 1 signature tương ứng
```
hash = MD5.new(long_to_bytes(p))
sig = sig_scheme.sign(hash)
```
Sau đó, ``sig_scheme.verify(hash, sig)``, tức là ta cần nhập vào 1 số p và signature và kiểm tra, nếu giống nhau thì code tiếp tục chạy (ta cũng có thể nhập chính số nguyên tố ban nãy vào cũng được)

Thế nhưng, tiếp theo lại có 1 đoạn code
```
a = int(msg["a"])
if a < 1:
    return {"error": "`a` value invalid"}
if a >= p:
    return {"error": "`a` value too large"}
g = math.gcd(a, p)
flag_byte = FLAG[:g]
return {"msg": f"Valid signature. First byte of flag: {flag_byte}"}
```
Nếu ta nhập số nguyên tố vào thì sẽ không được, thế nên ta cần nhập vào 1 số không phải số nguyên tố mà có cùng mã hash md5 với số nguyên tố đã nhập, sau đó a sẽ là 1 ước lớn của số đó

Sau khi tìm hiểu, mình tìm được 1 [TRANG WEB](https://crypto.stackexchange.com/questions/105669/quickest-way-to-find-md5-collision) này

```
from Crypto.Util.number import isPrime, bytes_to_long, long_to_bytes
import hashlib

x = "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2"
y = "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2"

print("x : ", bytes_to_long(bytes.fromhex(x)))

print("md5(x) : ", hashlib.md5(bytes.fromhex(x)).hexdigest())
print("md5(y) : ", hashlib.md5(bytes.fromhex(y)).hexdigest())

z = 1

xx = 0
yy = 0

while True:
    # append 1s till prime
    xx = bytes_to_long(bytes.fromhex(x) + long_to_bytes(z))
    yy = bytes_to_long(bytes.fromhex(y) + long_to_bytes(z))
    if isPrime(xx) and not isPrime(yy):
        break
    z += 2

print("x+z :", xx)
print("y+z :", yy)

print("md5(x+z) : ", hashlib.md5(long_to_bytes(xx)).hexdigest())
print("md5(y+z) : ", hashlib.md5(long_to_bytes(yy)).hexdigest())
```
Đoạn code này cho ta được 2 số xx (số nguyên tố) và yy mà có cùng 1 mã hash md5

Ta sẽ lấy số xx là số đầu tiên để nhập vào server, sau đó ta sẽ nhập số yy cùng với signature ban nãy, cùng với 1 ước lớn của số yy nhờ factor thì sẽ thu được flag

```
from pwn import*
context.log_level = 'debug'
io = remote('socket.cryptohack.org',13392)
io.recvuntil(b'Primality checking is expensive so I made a service that signs primes, allowing anyone to quickly check if a number is prime\n')

send_1 = '{"option": "sign", "prime": "1042949915673747639548394979539773519387432406920217853474982925582324441002369106807062644005773384014539089496972340217284225886262811961269251256830829063"}'
io.sendline(send_1.encode())

data = io.recvuntil(b'"}\n',drop=True).decode()
sign = data.replace('{"signature": "','')

send_2 = '{"option": "check","prime": "1042949915673747639548394979539773519387432406920217853474982925582324441002369106807076447498466965142113959008696894268189128104207757197289383619865780743","signature":"'+ sign+'","a":"71"}'
io.sendline(send_2.encode())

io.interactive()
```
Flag của chall này là: **crypto{MD5_5uck5_p4rt_tw0}**