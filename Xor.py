from pwn import *
# from Crypto.Cipher import AES
# import os
# from Crypto.Util.number import *
# from Crypto.Util.Padding import pad, unpad

# iv = bytes.fromhex('391e95a15847cfd95ecee8f7fe7efd66')
# c =  bytes.fromhex('8473dcb86bc12c6b6087619c00b6657e')
# p1 = b'FIRE_NUKES_MELA!'
# p2 = b'SEND_NUDES_MELA!'

# f_iv = xor(xor(iv,p1),p2)
# print(f_iv.hex())

# from string import printable
# lst = ['0529242a631234122d2b36697f13272c207f2021283a6b0c7908', '2f28202a302029142c653f3c7f2a2636273e3f2d653e25217908', '322921780c3a235b3c2c3f207f372e21733a3a2b37263b313012', '2f6c363b2b312b1e64651b6537222e37377f2020242b6b2c2d5d', '283f652c2b31661426292b653a292c372a2f20212a316b283c09', '29232178373c270f682c216532263b2d3632353c2c3c2a293504', '613c37373531285b3c2a72273a67212a277f373a243c20203d5d', '243a202a633d205b3c2d3765342236653a2c7423202f3f652a18', '2239373d6f740a1e3c651f207f2c212a247f3d2e65262430791c', '263e203d63232f0f20653f207f332065262c3168313722367918', '2f2f372133202f142665212637222220733e383f2426386b']
# pri = ['Dear Fri', 'nderstoo', 'sed One ', 'n scheme', 'is the o', 'hod that', ' proven ', 'ever if ', 'cure, Le', 'gree wit', 'ncryptio']
# for j in printable:
#     s = ""
#     for i in lst: 
#         s = s+str(xor(bytes.fromhex(i),b'ALEXCTF{HERE_GOES_THE_KEY' + j.encode())[:26])
#     if 'sed One time pad encryptio' in s:
#         print(j)
#         for i in lst:        
#             print(xor(bytes.fromhex(i),b'ALEXCTF{HERE_GOES_THE_KEY}' + j.encode())[:26])
f = b'SHARK{One_time_pad_is_xor}'
lst = [b'Dear Friend, This time I u',
b'nderstood my mistake and u',
b'sed One time pad encryptio',
b'n scheme, I heard that it ',
b'is the only encryption met',
b'hod that is mathematically',
b' proven to be not cracked ',
b'ever if the key is kept se',
b'cure, Let Me know if you a',
b'gree with me to use this e',
b'ncryption scheme always.:v']
lst_hex = ['172d20206b3d3d07003110454d31371912442b001e3a58265208',
'3d2c2420380f2001017f19104d0836031505340c533e160b5208',
'202d257204152a4e1136190c4d153e144101310a0126081b1b12',
'3d683231231e220b497f3d4905003e0205442b01122b5806065d',
'3a3b6126231e6f010b330d49080b3c0218142b001c3158021709',
'3b2725723f132e1a4536074900042b1804093e1d1a3c19031e04',
'7338333d3d1e214e1130540b0845311f15443c1b123c130a165d',
'363e24206b12294e113711490600265008177f02162f0c4f0118',
'303d3337675b030b117f390c4d0e311f1644360f5326171a521c',
'343a24376b0c261a0d7f190c4d11305014173a490737111c5218',
'3d2b332b3b0f26010b7f070a050032154105331e12260b41480b']
for i in lst_hex:
    print(xor(bytes.fromhex(i),f))