# MD0
![Alt text](image.png)

Chall này có đưa ta 1 source code:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
from utils import listener


FLAG = "crypto{???????????????}"


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash(data):
    data = pad(data, 16)
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out


class Challenge():
    def __init__(self):
        self.before_input = "You'll never forge my signatures!\n"
        self.key = os.urandom(16)

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            data = bytes.fromhex(msg["message"])
            if b"admin=True" in data:
                return {"error": "Unauthorized to sign message"}
            sig = hash(self.key + data)

            return {"signature": sig.hex()}

        elif msg["option"] == "get_flag":
            sent_sig = bytes.fromhex(msg["signature"])
            data = bytes.fromhex(msg["message"])
            real_sig = hash(self.key + data)

            if real_sig != sent_sig:
                return {"error": "Invalid signature"}

            if b"admin=True" in data:
                return {"flag": FLAG}
            else:
                return {"error": "Unauthorized to get flag"}

        else:
            return {"error": "Invalid option"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13388)

```
Ta thấy rằng đây không còn là hash function thông thường nữa, hash ở đây kết hợp AES và Xor, thế nhưng chall này cũng không quá thử thách đâu

Nếu đã học Hash length extension attack kỹ thì ta sẽ nhận ra được, chall này đã đưa ta function hash, giờ ta chỉ cần đưa signature cũ, thêm cùng với ``admin=True`` thì sẽ nhận được new signature

Ta lấy 1 ví dụ như sau:
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = b'1234567812345678'

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def hash(data):
    data = pad(data, 16)
    dem=0
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
        dem = dem+1
    return out
```

Ta thử nhập ``message = 'admin=False1234'``( len(message) == 15 vì nếu là 16 thì theo quy tắc PKCS7 thì sẽ thành 3 block) vào thì sẽ thu được 1 đoạn hexa là 'a82e897f54189aff3dbc9aeea7456d0e', đây chính là signature cũ nhaa

Tìm hiểu kỹ 1 tí thì ta thấy được khi ta nhập ``message = 'admin=False'`` thì sẽ có tổng cộng là 2 block, và sau khi padding sẽ được ``1234567812345678admin=False1234\x01``, thì thu được out, xong tiếp tục ta thêm 1 block nữa là b'admin=True' thì ta sẽ thu được out mới, đó sẽ chính là new signature
Và new_message sẽ là b'admin=False1234\x01admin=True12345' (không có 12345 thì phải sửa đi nha)

Bây giờ, ta sẽ lấy signature và block b'admin=True' vào hàm hash so sánh với key + new_message xem sao nhaa
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = b'1234567812345678'

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def hash(data):
    data = pad(data, 16)
    dem=0
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
        dem = dem+1
    return out

inp_adminFalse = '61646d696e3d46616c736531323334'
sign = bytes.fromhex('a82e897f54189aff3dbc9aeea7456d0e')

inp_adminTrue =  '61646d696e3d547275653132333435'
newstring = bytes.fromhex('61646d696e3d46616c7365313233340161646d696e3d547275653132333435')
blk = bytes.fromhex('61646d696e3d54727565313233343501')

out = sign
out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
print(out.hex())
print(hash(key+newstring).hex())


#Output1: 52165c70a77c5a605d439c4ceb01f640
#Output2: 52165c70a77c5a605d439c4ceb01f640
```
Yeee, giờ code lên server và lấy flag thuiii
```
from pwn import*
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# context.log_level = 'debug'

def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


io = remote('socket.cryptohack.org',13388)
io.recvuntil(b"You'll never forge my signatures!\n")
io.sendline(b'{"option": "sign", "message": "61646d696e3d46616c736531323334"}')
data = io.recvuntil(b'"}\n',drop=True)
data = data.decode()
sign = data.replace('{"signature": "','')


blk = bytes.fromhex('61646d696e3d54727565313233343501')
sign = bytes.fromhex(sign)
out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(sign), sign)
out = out.hex()

send = '{"option": "get_flag", "message": "61646d696e3d46616c7365313233340161646d696e3d547275653132333435", "signature": "'+ out+'"}'
io.sendline(send.encode())
io.interactive()
```
Flag của chall này là: ***crypto{l3ngth_3xT3nd3r}***