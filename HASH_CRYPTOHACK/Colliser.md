# COLLIDER

Chall có đưa ta 1 source code như sau:
```
import hashlib
from utils import listener


FLAG = "crypto{???????????????????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Give me a document to store\n"
        self.documents = {
            "508dcc4dbe9113b15a1f971639b335bd": b"Particle physics (also known as high energy physics) is a branch of physics that studies the nature of the particles that constitute matter and radiation. Although the word particle can refer to various types of very small objects (e.g. protons, gas particles, or even household dust), particle physics usually investigates the irreducibly smallest detectable particles and the fundamental interactions necessary to explain their behaviour.",
            "cb07ff7a5f043361b698c31046b8b0ab": b"The Large Hadron Collider (LHC) is the world's largest and highest-energy particle collider and the largest machine in the world. It was built by the European Organization for Nuclear Research (CERN) between 1998 and 2008 in collaboration with over 10,000 scientists and hundreds of universities and laboratories, as well as more than 100 countries.",
        }

    def challenge(self, msg):
        if "document" not in msg:
            self.exit = True
            return {"error": "You must send a document"}

        document = bytes.fromhex(msg["document"])
        document_hash = hashlib.md5(document).hexdigest()

        if document_hash in self.documents.keys():
            self.exit = True
            if self.documents[document_hash] == document:
                return {"error": "Document already exists in system"}
            else:
                return {"error": f"Document system crash, leaking flag: {FLAG}"}

        self.documents[document_hash] = document

        if len(self.documents) > 5:
            self.exit = True
            return {"error": "Too many documents in the system"}

        return {"success": f"Document {document_hash} added to system"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13389)

```
Có nghĩa là khi ta đưa 1 document vào server, thì server sẽ hash_md5(document) và lấy nó làm signature để sau này khi gọi mã hash đó thì sẽ trả về document tương ứng

Để lấy được flag của chall này, ta cần phải đưa vào 2 document sao cho nó cùng 1 signature, để server bị crack và sẽ trả lại flag cho ta

Lên gg tìm thì ta thấy md5 có một [Collision vulnerabilities](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities), có nghĩa là 2 string này sẽ có cùng 1 mã md5

```
from hashlib import md5

msg1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
msg2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
assert(md5(msg1).hexdigest() == md5(msg2).hexdigest())
print("TRUE")

```
Giờ ta gửi vào server thuiii

```
from pwn import*

context.log_level = 'debug'

io = remote('socket.cryptohack.org',13389)
io.recvuntil(b'Give me a document to store\n')
msg1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'
msg2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'

send_msg1 = f'{{"document": "{msg1}"}}'.encode()
io.sendline(send_msg1)

send_msg2 = f'{{"document": "{msg2}"}}'.encode()
io.sendline(send_msg2)
io.interactive()

```
Flag của chall này là: **crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}**