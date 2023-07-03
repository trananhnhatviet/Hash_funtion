# Hash Function

### MD5
MD5(Message Digest 5) là một thuật toán mã hóa băm mật mã học, nhận đầu vào là một thông điệp bất kỳ độ dài và chuyển đổi thành một thông điệp có độ dài cố định là 16 byte. MD5 được phát triển nhằm cải tiến từ MD4(này cũ quá nên mình không tìm hiểu) với mục đích nâng cao tính bảo mật. Kết quả đầu ra của MD5 (kích thước Digest) luôn luôn là 128 bit. MD5 được phát triển vào năm 1991 bởi Ronald Rivest.
Thuật toán MD5 như sau:
-    Padding Bits
    -    Thêm các bit đệm (padding bits) vào thông điệp ban đầu để đưa chiều dài của thông điệp về một bội số chính xác của 512 bit. Trong bước này, ta thêm single bit 1 vào, sau đó ta chèn thêm các bit 0 cho đến khi độ dài cộng thêm 64 thì là bội của 512
    -    Sau đó được thêm 64 bit theo định dạng Little-Endian
    -    Ví dụ, ta có 1 message 1000 bit, ta thêm 1 bit 1 ở sau --> 1001, sau đó thêm 471 bit 0 vào sau, cuối cùng thêm 64 bit theo Little-Endian, thế là ta được 1536 bit, là bội của 512
-    Initialize MD buffer
    -    Vì output là 128 bits, sẽ được chia thành 4 buffer(A, B, C, D mỗi buffer 32 bits)
```
    A – 01234567
    B – 89abcdef
    C – fedcba98
    D – 76543210
```
-    Process Each 512-bit Block
    ![](https://hackmd.io/_uploads/H143cuB82.png)
    -    Sau khi padding input M, ta sẽ chia ra thành 4 round, mỗi round 128 bits. Mỗi round sẽ xử lý 4 buffer.
    -    Giờ mình sẽ nói về round 1, các round khác cũng sẽ tương tự như thế.
    ![](https://hackmd.io/_uploads/BkmhmtSU2.png)
        -    Ta sẽ lấy 3 buffer B, C, D vào 1 hàm F, sau đó sẽ cộng module với A, sau đó cộng modulo tiếp với M[i] (i:1->16), và cộng tiếp với các hằng số MD5 K[i] (i:1->16), sau đó sẽ dịch trái s bit(s là mấy bit thì mình cũng không biết, wiki cũng không nói. Sau đó cộng modulo với B và sẽ trả về buffer B, ``D --> A``, ``B --> C``, ``C --> D``
        -    Các round sau thì cũng như thế, nhưng mà chỉ thay đổi hàm F thành các hàm G, H, I. Cụ thể như sau:
        -    ![](https://hackmd.io/_uploads/rkDNpYr8n.png)
-    Bạn có thể tham khảo qua ví dụ [ở đây](https://www.comparitech.com/blog/information-security/md5-algorithm-with-examples/)

### SHA-1
SHA-1 (Secure Hash Algorithm 1) là một thuật toán băm mã hóa đơn giản và phổ biến. Nó thuộc họ thuật toán băm SHA (SHA-0, SHA-1, SHA-2, SHA-3) được thiết kế bởi Cục An ninh Quốc gia Hoa Kỳ (NIST) và được sử dụng rộng rãi trong quá khứ.    
Kích thước băm: SHA-1 tạo ra một giá trị băm có độ dài 160 bit, tức là chuỗi 160 bit duy nhất đại diện cho dữ liệu đầu vào. Kích thước băm này không thể điều chỉnh và không thể thay đổi.
Thuật toán SHA-1 như sau:
-    Padding bits:
    -    Tương tự như là MD5, nhưng mà 64 bits cuối lại theo định dạng big-endian nên là vẫn sẽ có khác với MD5
-    Initialize MD buffer
    -    ![](https://hackmd.io/_uploads/B1WcTTHLn.png)
    -    SHA-1 có 5 buffer, output là 160 bits, nên là mỗi buffer 32 bits

-    Quá trình băm:
    -    ![](https://hackmd.io/_uploads/SJsVaTHL2.png)
    -    SHA-1 có tổng cộng 80 round, mỗi round sẽ xử lý các bit khác nhau, ta sẽ lấy ví dụ round đầu tiên
    ![](https://hackmd.io/_uploads/SJDuxRBI2.png)
    -    Thêm 79 vòng như thế nữa nhưng mà hàm khác, ta sẽ được output 160 bits
-    Bạn có thể tham khảo thêm [tại đây](https://www.slideshare.net/shivaramdam/sha-1-algorithm)


### SHA-256
SHA-256 (Secure Hash Algorithm 256-bit) là một thuật toán băm mã hóa đối xử với các khối dữ liệu có kích thước 512 bit. Nó là một trong các thuật toán băm phổ biến trong họ thuật toán băm SHA-2, được phát triển bởi Cơ quan Tiêu chuẩn và Công nghệ Hoa Kỳ (NIST).
SHA-256 được sử dụng rộng rãi trong nhiều ứng dụng bảo mật như xác thực dữ liệu, chứng thực, chữ ký số, và bảo mật mật khẩu.
Thuật toán SHA-256 như sau:
-    ![](https://hackmd.io/_uploads/SkxtCCrIn.png)
-    Chia thành 8 buffer, mỗi buffer là 32 bit
-    Trong thuật toán SHA-256, Ch(e,f,g) và Maj(a,b,c) là các hàm logic được sử dụng để tính toán các giá trị trung gian trong quá trình băm
-    Hàm Ch(e,f,g) được sử dụng để tính toán giá trị của ``e xor (f and (not g))``. Hàm Maj(a,b,c) được sử dụng để tính toán giá trị của ``(a and b) xor (a and c) xor (b and c)``.
-    T0 và T1 là các hằng số được sử dụng trong thuật toán SHA-256 để tính toán các giá trị trung gian. Cụ thể, T0 được tính toán bằng cách lấy giá trị của hằng số 0x428a2f98 và dịch trái giá trị của e (biến đầu vào của hàm Ch) 6 bit, sau đó xor với giá trị của e dịch trái 11 bit và xor với giá trị của e dịch trái 25 bit. T1 được tính toán bằng cách lấy giá trị của hằng số 0x71374491 và xor với giá trị của a dịch trái 2 bit, sau đó xor với giá trị của a dịch trái 13 bit và xor với giá trị của a dịch trái 22 bit.
-    Đầu ra của SHA-256 chính là 1 đoạn 256 bit
