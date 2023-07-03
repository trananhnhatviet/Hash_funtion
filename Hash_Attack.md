Có rất nhiều loại tấn công như Birthday Attack, Preimage attack, Collision attack,... thế nhưng nó đều là các loại bruteforce mà đã giới hạn phạm vi lại nên là mình chỉ tìm hiểu về ``Hash length extension attack`` thui nhaa

Hash length extension attack là một loại tấn công nguy hiểm mà tấn công vào các thuật toán hash dựa trên việc mở rộng độ dài của một chuỗi đã biết và tính toán hash của chuỗi mới mà không cần biết giá trị gốc của chuỗi đầu vào ban đầu.

Giờ hầu hết, các Message Authentication Code(MAC), sau khi nhận data của người dùng, thì sẽ chèn thêm 1 Secret_Key ở trước data, rùi mới cho vào các hàm băm, do đó, ta rất khó để bruteforce được data mà người dùng nhập vào

Thế giờ ta muốn tấn công thì phải làm sao đây =((

Để tấn công, ta cần sử dụng Hash length extension attack
Bạn có thể xem 2 video này để hiểu rõ hơn về cách tấn công này
[Video_1](https://www.youtube.com/watch?v=9yOKVqayixM) [Video_2](https://www.youtube.com/watch?v=GnCTXf_avdo&t=192s)

Ta hãy nhìn cách mà Hash hoạt động


![image](https://github.com/trananhnhatviet/Hash_funtion/assets/92376163/e1aae9c0-5d4f-4abb-8f2e-8284e453c85a)



Lấy 1 ví dụ qua 1 chall như sau:
```
def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            data = bytes.fromhex(msg["message"])
            if b"admin=True" in data:
                return {"error": "Unauthorized to sign message"}
            sig = hash(self.key + data)

            return {"signature": sig}

        elif msg["option"] == "get_flag":
            sent_sig = bytes.fromhex(msg["signature"])
            data = bytes.fromhex(msg["message"])
            real_sig = hash(self.key + data)

            if real_sig != sent_sig.hex():
                return {"error": "Invalid signature"}

            if b"admin=True" in data:
                return {"flag": FLAG}
            else:
                return {"error": "Unauthorized to get flag"}

        else:
            return {"error": "Invalid option"}
```

-    Tức là khi ta chọn chế độ "sign", thì ta sẽ nhận được Hash(Secret_key + message), ví dụ message = ``admin=False``, thì sẽ thu được phần ``Sign = Hash(Secret_Key + admin=False)``, thế nhưng khi ta nhập ``admin=True`` thì sẽ không thu được gì
-    Nhưng mà khi ta muốn chọn chế độ "get_flag" thì ta cần phải có 1 MAC để chứng minh là Admin bằng cách kiểm chứng ``Hash(Secret_Key + Message)`` và ``MAC``, nếu giống nhau thì sẽ thu được Flag thui

-    Sơ đồ tấn công sẽ như sau:


![image](https://github.com/trananhnhatviet/Hash_funtion/assets/92376163/6c0ffe10-03bf-4864-9919-5fedf69c3666)


-    Hiện tại ta hãy sử dụng Hash MD5 và length của Secret_key là 16 đi ha
-    Ta sẽ padding bằng tay phần Message = ``admin=False`` theo như MD5 để cho tròn các block (sau khi cộng cả 16 vào), sau đó ta sẽ thêm phần ``admin=True`` vào sau để vẫn đủ điều kiện ``if b"admin=True" in data: return {"flag": FLAG}``
-    Sau đó, Mesage sẽ bằng: ``admin=False + padding_1 + admin=True + padding_2``. Rồi ta sẽ cho vào Hash(Secret_Key + Message) sẽ thu được ``real_sig``, 
-    Ta lấy phần ``Hash(Secret_Key + admin=False)`` rồi cho vào hàm F với phần block thừa đó, ta sẽ thu được ``sent_sig``
-    Và khi so sánh ``real_sig`` và ``sent_sig``, thì chúng hoàn toàn khớp với nhau và ta thu được Flag trong khi ta chỉ cần biết được độ dài của Secret_Key (cái này ta có thể bruteforce được)

Mình có sử dụng 1 tool đó là [Hash_extender](https://github.com/iagox86/hash_extender/tree/master), đây là tool hỗ trợ cho mình cách tấn công kiểu này, khi mình đưa data (tương tự với admin=False), đưa độ dài của Secret_Key, đưa phần thêm vào (tương tự như admin=True) và đưa phần sign (Hash(Secret_Key + admin=False)), thì ta sẽ thu được sign mới và message mới nhaa

Mình sẽ sử dụng nó vào ví dụ sau đây
```
from hashlib import*

def hasher(key,data):
    out = key + data
    return sha512(out).digest().hex()

key = b'1234567812345678'
first = b'tran_anh_nhat_viet_xau_trai'
if b'dep_trai' in first:
    exit
else:
    print(hasher(key,first))
    # Output: d944d35b1bab8a2f1a2a3a54f53dca239634af854588d253ac4e22593bc05004fcbf09a106e98cacae0dbcdb5648e10f033bea8aa515812e31ac40968044a99d
print('\n')
print('Nhap second dang hex: ')
second = input()
print('Nhap Mac: ')
mac = input()
second = bytes.fromhex(second)
if b'dep_trai' in second:
    out = (hasher(key,second))
    if out == mac:
        print("Welcome Tran Anh Nhat Viet <3")
```
-    Giả sử, ta không biết được key là gì đi nhaa
-    Ta cần ``dep_trai`` thì mới xác nhận bạn là ``Tran Anh Nhat Viet`` được, nhưng mà bạn không thể chèn vào first được, chỉ được nhập vào second thui, nhưng mà second thì cần Mac, đây chính là lúc bạn cần sử dụng Hash_extender
-    Ta gõ dòng lệnh như sau:
-    ``./hash_extender --data tran_anh_nhat_viet_xau_trai --secret 16 --append dep_trai --signature 37d7848f49b6bc13d313d0dcf3c33b8441e5164158a394c4baa639067410bdfb807dd244490c95d07f8c8776612e8495489d5073d0046f13a526e99e0d54304e --format sha512``
-    Sau khi nhập vào, ta sẽ thu được như sau:
```
Type: sha512
Secret length: 16
New signature: cd3b02e532782b068f0bdfc63a311c7a1e876d2701f4cc412e3ceb708f0003bee9ae0fe9c7a4ade7542c9548c6fffde53fc125a932de6765750b2771171e58d0
New string: 7472616e5f616e685f6e6861745f766965745f7861755f74726169800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001586465705f74726169
```
-    Thì New string sẽ là second cần nhập, và new sign sẽ là mac
-    Nhập vào thuii

![image](https://github.com/trananhnhatviet/Hash_funtion/assets/92376163/b613f73f-1c45-4598-8f34-670789f451cc)




Còn các loại tấn công khác, hầu như là bruteforce thế nên mình sẽ không đề cập tới nhaa
Nhưng mà nên xem video thì mới hiểu rõ được bản chất nhaa <3
