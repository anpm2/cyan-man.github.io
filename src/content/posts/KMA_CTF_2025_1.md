---
title: KMA CTF 2025 I
published: 2025-05-15
description: Write up KMA CTF 2025 lần 1
tags: [CTF, REV, KMASEC]
category: Write up
draft: false
---


## I. Mobius

### 1. Tổng quan
![image](https://hackmd.io/_uploads/rkbTifgbxx.png)
![image](https://hackmd.io/_uploads/HyfRifeWxg.png)

1 file `PE64`, nhìn vào icon mình đoán ngay challenge dùng **pyinstaller** đóng gói ứng dụng python thành 1 file thực thi để chạy.

Qua tìm hiểu thì mục đích của việc chuyển file python sang dạng thực thi và đóng gói là để có thể dễ dàng chạy ở các máy khác nhau mà không cần phải cài đặt môi trường python.

### 2. Phân tích
Dùng tool [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) để extract file và `uncompyle6` để uncompile:
![image](https://hackmd.io/_uploads/Skedymg-ex.png)
![image](https://hackmd.io/_uploads/SybPX7xWxg.png)

Quan sát file `proc.py` 1 chuỗi base64 được giải mã thành bytecode và thực thi.

Qua tìm hiểu ở **[đây](https://www.geeksforgeeks.org/marshal-internal-python-object-serialization/)** và **[đây](https://python-experiment.readthedocs.io/en/latest/library/marshal.html)** **marshal** là 1 module python tích hợp liên quan đến biên dịch và thực thi mã python.

`marshal.loads` trong challenge này sẽ giải tuần tự hóa chuỗi byte (binary) thành 1 đối tượng python (code object) với các thuộc tính như bytecode (lệnh thực thi), hằng số, tên hàm-biến, cấu trúc module, ...

Như vậy thay vì gọi `exec` để thực thi thì mình sẽ sửa code dùng thư viện `dis` để phân tích code object sau khi chuyển từ bytecode để quan sát:
```python
import dis
dis.dis(marshal.loads(_6d(globals()['__doc__'])))
```
bytecode sau khi phân tích thành [code_object](https://github.com/anpm2/CTFs/blob/main/KMACTF/2025/Mobius/code_object.txt).

Viết lại bằng [python](https://github.com/anpm2/CTFs/blob/main/KMACTF/2025/Mobius/deob_proc.py)

Tổng quan đây là 1 máy ảo **VM** với cấu trúc như sau:
* **S** (stack): `sh` (push), `p` (pop), `ud` (cập nhật kích thước).
* **R** (thanh ghi): `_1, _2, _3, _4` và cờ trạng thái `fs`
* Các tập lệnh **VM** gồm các hàm `m, sh, p, ...`
* **V** (xử lý flag): chứa stack, thanh ghi, kích thước lệnh `sz = 8` với mỗi lệnh sẽ là 8 ký tự hex.

Như 1 bài **VM** thông thường sẽ sử dụng 1 bảng lệnh opcode sau đó duyệt và thao tác biến đổi input để thỏa mãn 1 điều kiện bất kì.

**VM** này mô phỏng 1 **stack** yêu cầu nhập flag (51 ký tự) sao cho khi chạy qua hàm `V.x()` thì tổng giá trị của `v.r.fs` phải bằng **401**:
```python
        if ct == 401:
            print("\nCorrect!")
        else:
            print("\nWrong!")

ip = input("Enter Flag: ")
v = V()
try:
    v.x(ip)
except:
    exit(0)
```

Để ý ở hàm `V.x()` là nơi xử lý flag khi ghép từng 5 giá trị hex của flag vào list `cd` và thực thi lần lượt 8 byte / lệnh qua `ino` (chứa các hàm để thực thi):
```python
os = []
ct = 0
for i in range(0, len(cd), 8):
    os.append('0x' + cd[i:i+8])
for i in range(len(os)):
    o = int(os[i], 16)
    if o > 0 and o <= (16**v.sz - 1):
        op = o >> (v.sz - 1) * 4
        ino[op](v, o)
    else:
        exit(0)
    ct += v.r.fs
```

Với mỗi lệnh (8 byte) thì 4 bit đầu sẽ xác định hàm nào được call trong `ino`.
4 bit kế tiếp là thanh ghi đích `tg`  (`r0 - r3`)
4 bit tiếp theo xác định nguồn giá trị (`ir = 1` ->trực tiếp, `ir = 0` -> thanh ghi).
Với giá trị của thanh ghi nguồn thì:
* Nếu `ir = 0`: lấy 20 bit thấp nhất cho `mov, add, sub, cmp, xor` --> `ue`
* Nếu `ir = 1`: lấy 4 bit tiếp theo xác định thanh ghi nguồn --> `ix`

Có 2 cách để giải quyết với cách 1 là brute force, 2 là phân tích `cd` để xem **VM** nó thực thi như thế nào.

### 3. Solve
#### Stage 1: brute
Ở đây mình sẽ tập trung vào hàm `c`, hàm này thực hiện so sánh giá trị thanh ghi sau khi tính toán với hằng số được tách từ dải lệnh trong `cd` và đặt cờ `fs = 1` nếu bằng, ngược lại `fs = 0`.

Mình sẽ sửa lại 1 chút hàm `c` để in ra giá trị của cờ `fs` để tiện debug quan sát với flag nhập vào:
```python
def c(v, o):
    tg = (o >> (v.sz - 2) * 4) & 15
    ir = (o >> (v.sz - 3) * 4) & 15
    if ir == 0:
        ue = o & ((16 ** (v.sz - 3)) - 1)
    elif ir == 1:
        ix = (o >> (v.sz - 4) * 4) & 15
        ue = v.r.gt(ix)
    if v.r.gt(tg) == ue:
        v.r.sfz(True)
        print(1, end='')
    else:
        v.r.sfz(False)
        print(0, end='')
```
![image](https://hackmd.io/_uploads/H1B4ZBgZeg.png)

Có thể thấy với các ký tự `KCSC{` và`}` thì cờ `fs` được đặt thành 1, các giá trị sai còn lại là 0.

Từ đây mình rút ra có thể **brute force** từng ký tự của flag với điều kiện để kiểm tra chính là giá trị của cờ `fs` nếu ký tự nào thỏa mãn thì cờ `fs = 1`, ngược lại `fs = 0`. (`~ 3p`)

> brute.py
```python
from pwn import *
from string import *

charset = ascii_letters + digits + punctuation
flag = list('KCSC{') + ['a'] * 46
for i in range(5, 51):
    for c in charset:
        tmp = flag.copy()
        tmp[i] = c
        btmp = ''.join(tmp).encode()
        io = process(['python', './deob_proc.py'])
        io.recvuntil(b'Enter Flag: ')
        io.sendline(btmp)
        fs = io.recvall().decode().split('\n')[0]
        if fs[i] == '1':
            flag[i] = c
            io.close()
            break

print(''.join(flag))
```
![image](https://hackmd.io/_uploads/B1BeYFlWeg.png)


#### Stage 2: cd
Mô phỏng và phân tích cách **VM** thực thi:
> cd.py
```python
test = 'KCSC{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}'
hv = [hex(ord(i))[2:].zfill(5) for i in test]
cd = ''.join([
    '60100000000', hv[0],
    '6000001130000539600000164000000C600000005000057961110000010', hv[1],
    '6100001131000539610000164100000C610000015100059062120000020', hv[2],
    '6200001132000539620000164200000C620000025200056363130000030', hv[3],
    '6300001133000539630000164300000C630000035300059260100000000', hv[4],
    '6000001130000539600000164000000C60000004500005ad61110000010', hv[5],
    '6100001131000539610000164100000C610000055100055962120000020', hv[6],
    '6200001132000539620000164200000C620000065200059e63130000030', hv[7],
    '6300001133000539630000164300000C630000075300054660100000000', hv[8],
    '6000001130000539600000164000000C600000085000057661110000010', hv[9],
    '6100001131000539610000164100000C610000095100054862120000020', hv[10],
    '6200001132000539620000164200000C6200000a5200058f63130000030', hv[11],
    '6300001133000539630000164300000C6300000b5300054860100000000', hv[12],
    '6000001130000539600000164000000C6000000c5000058d61110000010', hv[13],
    '6100001131000539610000164100000C6100000d5100058862120000020', hv[14],
    '6200001132000539620000164200000C6200000e5200053263130000030', hv[15],
    '6300001133000539630000164300000C6300000f5300058a60100000000', hv[16],
    '6000001130000539600000164000000C600000105000057061110000010', hv[17],
    '6100001131000539610000164100000C61000011510005ba62120000020', hv[18],
    '6200001132000539620000164200000C620000125200056e63130000030', hv[19],
    '6300001133000539630000164300000C630000135300058b60100000000', hv[20],
    '6000001130000539600000164000000C600000145000055461110000010', hv[21],
    '6100001131000539610000164100000C61000015510005b762120000020', hv[22],
    '6200001132000539620000164200000C620000165200059363130000030', hv[23],
    '6300001133000539630000164300000C630000175300057660100000000', hv[24],
    '6000001130000539600000164000000C600000185000058c61110000010', hv[25],
    '6100001131000539610000164100000C610000195100055a62120000020', hv[26],
    '6200001132000539620000164200000C6200001a5200056663130000030', hv[27],
    '6300001133000539630000164300000C6300001b5300058360100000000', hv[28],
    '6000001130000539600000164000000C6000001c5000055d61110000010', hv[29],
    '6100001131000539610000164100000C6100001d5100056362120000020', hv[30],
    '6200001132000539620000164200000C6200001e5200052163130000030', hv[31],
    '6300001133000539630000164300000C6300001f5300059a60100000000', hv[32],
    '6000001130000539600000164000000C600000205000056361110000010', hv[33],
    '6100001131000539610000164100000C610000215100058362120000020', hv[34],
    '6200001132000539620000164200000C62000022520005a763130000030', hv[35],
    '6300001133000539630000164300000C630000235300051f60100000000', hv[36],
    '6000001130000539600000164000000C60000024500005a161110000010', hv[37],
    '6100001131000539610000164100000C61000025510005af62120000020', hv[38],
    '6200001132000539620000164200000C62000026520005bd63130000030', hv[39],
    '6300001133000539630000164300000C630000275300055960100000000', hv[40],
    '6000001130000539600000164000000C600000285000057461110000010', hv[41],
    '6100001131000539610000164100000C610000295100055662120000020', hv[42],
    '6200001132000539620000164200000C6200002a5200051663130000030', hv[43],
    '6300001133000539630000164300000C6300002b530005bf60100000000', hv[44],
    '6000001130000539600000164000000C6000002c500005a961110000010', hv[45],
    '6100001131000539610000164100000C6100002d5100057062120000020', hv[46],
    '6200001132000539620000164200000C6200002e5200056e63130000030', hv[47],
    '6300001133000539630000164300000C6300002f5300055160100000000', hv[48],
    '6000001130000539600000164000000C60000030500005a461110000010', hv[49],
    '6100001131000539610000164100000C61000031510005bd62120000020', hv[50],
    '6200001132000539620000164200000C6200003252000595'
])

os = []
ino = ('mov', 'push', 'pop', 'add', 'sub', 'cmp', 'xor', 'exit')

for i in range(0, len(cd), 8):
    os.append('0x' + cd[i:i+8])
# print(os)
for i in range(len(os)):
    o = int(os[i], 16)
    instr = (o >> 28) & 0xF
    if instr == 7:
        print(f'{i}\t{os[i]:10s}\t{ino[instr]}')
    else:
        tg = (o >> 24) & 0xF
        ir = (o >> 20) & 0xF
        if ir == 0:
            ue = o & 0xFFFFF
            print(f'{i}\t{os[i]:10s}\t{ino[instr]} r{tg}, 0x{ue:x}')
        else:
            ix = (o >> 16) & 0xF
            print(f'{i}\t{os[i]:10s}\t{ino[instr]} r{tg}, r{ix}')
```
![image](https://hackmd.io/_uploads/SJnbb1z-ex.png)

**VM** sẽ duyệt lần lượt 8 byte trong `cd` để thực thi với luồng `mov --> xor -> add --> xor --> sub --> xor --> cmp`

Để ý ở dòng `mov r0, 0x4b` chính là phần lưu flag nhập vào, sau đó qua các bước tính toán cuối cùng sẽ thực hiện so sánh với hằng số (`cmp r0, 0x579`).

Từ đó có thể giải ngược lại logic trên để tìm flag. `xor -> add --> xor --> sub --> xor`:
> solve.py
```python
test = 'KCSC{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}'
hv = [hex(ord(i))[2:].zfill(5) for i in test]
cd = ''.join([
    '60100000000', hv[0],
    '6000001130000539600000164000000C600000005000057961110000010', hv[1],
    '6100001131000539610000164100000C610000015100059062120000020', hv[2],
    '6200001132000539620000164200000C620000025200056363130000030', hv[3],
    '6300001133000539630000164300000C630000035300059260100000000', hv[4],
    '6000001130000539600000164000000C60000004500005ad61110000010', hv[5],
    '6100001131000539610000164100000C610000055100055962120000020', hv[6],
    '6200001132000539620000164200000C620000065200059e63130000030', hv[7],
    '6300001133000539630000164300000C630000075300054660100000000', hv[8],
    '6000001130000539600000164000000C600000085000057661110000010', hv[9],
    '6100001131000539610000164100000C610000095100054862120000020', hv[10],
    '6200001132000539620000164200000C6200000a5200058f63130000030', hv[11],
    '6300001133000539630000164300000C6300000b5300054860100000000', hv[12],
    '6000001130000539600000164000000C6000000c5000058d61110000010', hv[13],
    '6100001131000539610000164100000C6100000d5100058862120000020', hv[14],
    '6200001132000539620000164200000C6200000e5200053263130000030', hv[15],
    '6300001133000539630000164300000C6300000f5300058a60100000000', hv[16],
    '6000001130000539600000164000000C600000105000057061110000010', hv[17],
    '6100001131000539610000164100000C61000011510005ba62120000020', hv[18],
    '6200001132000539620000164200000C620000125200056e63130000030', hv[19],
    '6300001133000539630000164300000C630000135300058b60100000000', hv[20],
    '6000001130000539600000164000000C600000145000055461110000010', hv[21],
    '6100001131000539610000164100000C61000015510005b762120000020', hv[22],
    '6200001132000539620000164200000C620000165200059363130000030', hv[23],
    '6300001133000539630000164300000C630000175300057660100000000', hv[24],
    '6000001130000539600000164000000C600000185000058c61110000010', hv[25],
    '6100001131000539610000164100000C610000195100055a62120000020', hv[26],
    '6200001132000539620000164200000C6200001a5200056663130000030', hv[27],
    '6300001133000539630000164300000C6300001b5300058360100000000', hv[28],
    '6000001130000539600000164000000C6000001c5000055d61110000010', hv[29],
    '6100001131000539610000164100000C6100001d5100056362120000020', hv[30],
    '6200001132000539620000164200000C6200001e5200052163130000030', hv[31],
    '6300001133000539630000164300000C6300001f5300059a60100000000', hv[32],
    '6000001130000539600000164000000C600000205000056361110000010', hv[33],
    '6100001131000539610000164100000C610000215100058362120000020', hv[34],
    '6200001132000539620000164200000C62000022520005a763130000030', hv[35],
    '6300001133000539630000164300000C630000235300051f60100000000', hv[36],
    '6000001130000539600000164000000C60000024500005a161110000010', hv[37],
    '6100001131000539610000164100000C61000025510005af62120000020', hv[38],
    '6200001132000539620000164200000C62000026520005bd63130000030', hv[39],
    '6300001133000539630000164300000C630000275300055960100000000', hv[40],
    '6000001130000539600000164000000C600000285000057461110000010', hv[41],
    '6100001131000539610000164100000C610000295100055662120000020', hv[42],
    '6200001132000539620000164200000C6200002a5200051663130000030', hv[43],
    '6300001133000539630000164300000C6300002b530005bf60100000000', hv[44],
    '6000001130000539600000164000000C6000002c500005a961110000010', hv[45],
    '6100001131000539610000164100000C6100002d5100057062120000020', hv[46],
    '6200001132000539620000164200000C6200002e5200056e63130000030', hv[47],
    '6300001133000539630000164300000C6300002f5300055160100000000', hv[48],
    '6000001130000539600000164000000C60000030500005a461110000010', hv[49],
    '6100001131000539610000164100000C61000031510005bd62120000020', hv[50],
    '6200001132000539620000164200000C6200003252000595'
])

os = []
ino = ('mov', 'push', 'pop', 'add', 'sub', 'cmp', 'xor', 'exit')

for i in range(0, len(cd), 8):
    os.append('0x' + cd[i:i+8])
# print(os)
flag = []
ue = []
for i in range(len(os)):
    o = int(os[i], 16)
    instr = (o >> 28) & 0xF
    ir = (o >> 20) & 0xF
    tg = (o >> 24) & 0xF
    if ir == 0 and instr != 0:
        ue.append(o & 0xFFFFF)
        # print(f'{ino[instr]} r{tg}, 0x{o & 0xFFFFF:x}')
for i in range(len(ue)-1, -1, -6):
    r = (((ue[i] ^ ue[i-1]) + ue[i-2]) ^ ue[i-3]) - ue[i-4] ^ ue[i-5]
    flag.append(r & 0xff)
print(''.join([chr(i) for i in reversed(flag)]))
```

<details>
  <summary><strong>Flag</strong></summary>

  ```
  KCSC{Th3r3_1s_4_Pyth0n_Sl1th3r5_1n_4_VirTu4l_W0rlD}
  ```
</details>

![image](https://hackmd.io/_uploads/SyZRmlzWll.png)



## II. hẹ hẹ hẹ anh Hùng benj

Challenge này có 3 giai đoạn:
### Stage 1 hihi
#### 1. Tổng quan
![image](https://hackmd.io/_uploads/ry14W7G-xe.png)
![image](https://hackmd.io/_uploads/r16ufmzWgx.png)
![image](https://hackmd.io/_uploads/HyRNrEGZxl.png)
Yêu cầu giải mã chuỗi hex sau khi chạy file `chal.exe` để tìm flag.

#### 2. Phân tích
![image](https://hackmd.io/_uploads/ryuFmXz-gx.png)
Ý tưởng obfuscate giống với `Callfuscate` của KMACTF2023, đoạn dài rối đó sẽ tính toán địa chỉ của hàm cần gọi, ở đây cần gọi các hàm `ask_input, xor_kma, encrypt, print_result`.

Đặt breakpoint tại ở dòng jump cuối block để có thể quan sát được các hàm cần gọi:
![image](https://hackmd.io/_uploads/B1r_I7fblx.png)

##### 2.1 ask_input

![image](https://hackmd.io/_uploads/rJFQq7z-gl.png)

Hàm này chú ý chỗ đệm input sao cho độ dài là bội của 16.

##### 2.2 xor_kma

![image](https://hackmd.io/_uploads/BkKY97Mbgl.png)

Hàm này xor input với chuỗi `KMACTF2025_1 `

##### 2.3 encrypt

![image](https://hackmd.io/_uploads/Bkjn9XMZel.png)

Mã hóa lần lượt từng block với 16-byte.

**process_block**

![image](https://hackmd.io/_uploads/HJBSgEMWel.png)

xor input sau với `key = 'Cust0mS3rp3ntK3y'`, sau đó apply_sbox từng byte 1 rồi thực hiện xoay phải và gán lại cho input.

**apply_sbox**

![image](https://hackmd.io/_uploads/HJzdxVzbge.png)

**print_result**

![image](https://hackmd.io/_uploads/Bklj-VGbxg.png)

Định dạng thành hex và in ra màn hình.


Tóm lại luồng mã hóa như sau: đầu tiên nhập input và đệm thêm byte sao cho là bội của 16 --> xor input với chuỗi `KMACTF2025_1 ` --> mã hóa lần lượt 16-byte --> in ra chuỗi hex.

Mô phỏng lại luồng mã hóa:
<details>

  <summary>chall.py</summary>

  ```python
  kma = bytes.fromhex('4B4D41435446323032355F312000')
  serpent = bytearray(b"Cust0mS3rp3ntK3y")
  sbox = [
      0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
      0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
      0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
      0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
      0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
      0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
      0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
      0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
      0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
      0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
      0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
      0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
      0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
  ]

  def ROL1(b, n):
      return ((b << n) | (b >> (8 - n))) & 0xFF

  def ROR4(b, n):
      return ((b >> n) | (b << (32 - n))) & 0xFFFFFFFF

  def apply_sbox(b):
      v = sbox[ROL1(b, 2) ^ 0x2B]
      for i in range(22):
          v = sbox[((v >> 6) + 4 * (v & 0x3F)) ^ 0x2B]
      return v

  def process_bl(bl):
      bl = bytearray([bl[i] ^ serpent[i % len(serpent)] for i in range(len(bl))])

      for i in range(16):
          bl[i] = apply_sbox(bl[i])
      [print(hex(b), end=' ') for b in bl]
      print()
      rsi = [int.from_bytes(bl[i:i+4], 'little') for i in range(0, 16, 4)]

      eax = ROR4(rsi[0], 19)
      ecx = ROR4(rsi[2], 29)
      rsi[1] = ROR4(rsi[1] ^ eax ^ ecx, 31)
      rsi[3] = ROR4(((eax * 8) & 0xFFFFFFFF) ^ rsi[3] ^ ecx, 25)
      rsi[0] = ROR4(eax ^ rsi[1] ^ rsi[3], 27)
      rsi[2] = ROR4(((rsi[1] << 7) & 0xFFFFFFFF) ^ ecx ^ rsi[3], 10)

      return b''.join(val.to_bytes(4, 'little') for val in rsi)

  def encrypt(buf):
      buf = bytearray(buf)
      for i in range(0, len(buf), 16):
          buf[i:i+16] = process_bl(buf[i:i+16])
      return buf
          
  def xor_kmactf(buf):
      for i in range(len(buf)):
          buf[i] ^= kma[i % len(kma)]
      return buf

  test = bytearray(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
  test += b'\x10' * (16 - len(test) % 16)
  t = encrypt(xor_kmactf(test))
  print(t.hex()) # 843cb34c7428b5e827c79dbc0efb5fc4dace71c7e57d4111ab5912498f4da2bc8ae4f3e8863a9236101d86325e71fe88
  ```
</details>

![image](https://hackmd.io/_uploads/rkhbH4MWee.png)

Hoàn toàn khớp với chương trình khi debug với input là 32 ký tự `a`
![image](https://hackmd.io/_uploads/BkWH2mGblx.png)
![image](https://hackmd.io/_uploads/r1b8rNM-el.png)

#### 3. Solve
Khôi phục lại cần chú ý tạo ánh xạ ngược lại so với `apply_sbox` (`apply_sbox(i) = output, thì inv[output] = i`)

> solve1.py
```python
kma = bytes.fromhex('4B4D41435446323032355F312000')
serpent = bytearray(b"Cust0mS3rp3ntK3y")
sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
    0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
    0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
    0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

def ROL1(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF

def ROL4(b, n):
    return ((b << n) | (b >> (32 - n))) & 0xFFFFFFFF

def apply_sbox(b):
    v = sbox[ROL1(b, 2) ^ 0x2B]
    for i in range(22):
        v = sbox[((v >> 6) + 4 * (v & 0x3F)) ^ 0x2B]
    return v

def inv_sbox():
    inv = {}
    for i in range(256):
        output = apply_sbox(i)
        inv[output] = i
    return inv

def rev_process_bl(bl):
    rsi = [int.from_bytes(bl[i:i+4], 'little') for i in range(0, 16, 4)]
    en_rsi = rsi.copy()
    rsi[2] = ROL4(rsi[2], 10)
    rsi[0] = ROL4(rsi[0], 27)
    eax = rsi[0] ^ en_rsi[1] ^ en_rsi[3]
    ecx = rsi[2] ^ ((en_rsi[1] << 7) & 0xFFFFFFFF) ^ en_rsi[3]
    rsi[3] = ROL4(rsi[3], 25)
    rsi[1] = ROL4(rsi[1], 31)
    rsi[0] = ROL4(eax, 19)
    rsi[2] = ROL4(ecx, 29)
    rsi[3] = rsi[3] ^ ((eax * 8) & 0xFFFFFFFF) ^ ecx
    rsi[1] = rsi[1] ^ eax ^ ecx
    res = bytearray()
    for val in rsi:
        res.extend(val.to_bytes(4, 'little'))
    inv = inv_sbox()
    for i in range(16):
        res[i] = inv[res[i]]
    for i in range(16):
        res[i] ^= serpent[i % len(serpent)]
    return res

def decrypt(buf):
    buf = bytearray(buf)
    for i in range(0, len(buf), 16):
        if i + 16 <= len(buf):
            buf[i:i+16] = rev_process_bl(buf[i:i+16])
    return buf

def xor_kmactf(buf):
    buf = bytearray(buf)
    for i in range(len(buf)):
        buf[i] ^= kma[i % len(kma)]
    return buf


# enc = bytes.fromhex("843cb34c7428b5e827c79dbc0efb5fc4dace71c7e57d4111ab5912498f4da2bc8ae4f3e8863a9236101d86325e71fe88")
enc = bytes.fromhex('4A137B78476860B7D3BB4BEF617B1E8C21EBEC915969390122D557E3DF9554313A1C32B50BF54AC2673DD222181A9ADA6662676C7D3C5BBCF3CFC74395283C1B65D583C58D1DECA05EB94CE874A544F8145155396A696CD03899F0E3283B828D')
dec = decrypt(enc)
dec = xor_kmactf(dec)
print(dec.decode())
```
![image](https://hackmd.io/_uploads/B1_b44f-gl.png)
![image](https://hackmd.io/_uploads/rJSH4Vz-xe.png)

Vào link và tải file về.


### Stage 2 hehe
#### 1. Tổng quan
![image](https://hackmd.io/_uploads/r1ebIEGZle.png)
![image](https://hackmd.io/_uploads/B1BMDNM-ll.png)

Ở stage 2 thì cho biết các file trên máy nạn nhân đã bị mã hóa **Wanna Scream** và muốn khôi phục lại phải liên hệ với mail được cung cấp.

Folder `Data` chứa các file đã bị mã hóa, folder `SAMPLE` chứa thông tin mã độc mã hóa file.

![image](https://hackmd.io/_uploads/B1KRwEzbel.png)

Đây là con mã độc `PE32` đã thực hiện mã hóa file viết bằng `.NET`

#### 2. Phân tích
Mở bằng **dnSpy**:
![image](https://hackmd.io/_uploads/S1WxY4zbxl.png)

Đây là phần thực hiện mã hóa file.

Quan sát khá rõ ràng khi nó thực hiện dùng thuật toán **ISAAC CSPRNG** mã hóa lần lượt từng file trong hệ thống với bước đầu tiên sẽ trộn khóa con vào **ISAAC**, sau đó đọc và mã hóa theo block 512-byte và xor với key trong `csprng.rsl[]`.

Như vậy để khôi phục lại file đã bị mã hóa thì cần có key từ `csprng.rsl[]`.

Chú ý vào folder `Data` cho gợi ý để tìm key khi với file `VSCodeUserSetup-x64.exe.[B04883D6[decryptprof@mailfence.com].Sup.Sup` chính là file `VSCodeUserSetup-x64.exe` trước khi bị mã hóa.

File cài đặt ban đầu đó có thể dễ dàng tìm được trên google vì nó là file cài đặt thông thường của VSCode.

> Nhưng là phiên bản nào mới đúng?

Mò trong file `C.txt` ở folder `Data` có chứa thông tin dữ liệu của máy nạn nhân ban đầu chưa bị mã hóa:
![image](https://hackmd.io/_uploads/BySQn4Gbgg.png)

Như vậy phiên bản chính xác là [1.63.2](https://code.visualstudio.com/updates/v1_63), tải về và xor lại với bản bị mã hóa để lấy key.
> key.py
```python
pt = open('./VSCodeUserSetup-x64.exe.[B04883D6[decryptprof@mailfence.com].Sup.Sup', 'rb').read()
ct = open('./VSCodeUserSetup-x64-1.63.2.exe', 'rb').read()
with open('key.bin', 'wb') as f:
    for i in range(8827448):
        f.write(bytes([pt[i] ^ ct[i]]))
```
Ở đây hàm mã hóa này có điểm đặc biệt là nó mã hóa độc lập từng file 1 riêng biệt với cùng 1 key nên kích thước của file bao nhiêu thì sẽ xor với kích thước key (`csprng.rsl[]`) bấy nhiêu, mỗi lần mã hóa file mới sẽ reset duyệt lại `csprng.rsl[]` từ đầu vì thế mình chọn giá trị `8827448` mục đích là giúp xor nhanh hơn để tìm key giải mã các file liên quan còn lại quan trọng hơn file cài đặt VSCode đó.

#### 3. Solve
![image](https://hackmd.io/_uploads/rys1bHzbel.png)

Có key(`csprng.rsl[]`) rồi thì khôi phục lại 2 file như hint thôi:
> recovery.py
```python
hehe_enc = open('hehe.txt.[B04883D6[decryptprof@mailfence.com].Sup', 'rb').read()
huh_enc = open('huh.txt[B04883D6[decryptprof@mailfence.com].Sup', 'rb').read()

key = open('key.bin', 'rb').read()
with open('hehe.txt', 'w') as he, open('huh.txt', 'w') as huh:
    for i in range(len(hehe_enc)):
        he.write(chr((hehe_enc[i] ^ key[i]) & 0xFF))
    for j in range(len(huh_enc)):
        huh.write(chr((huh_enc[j] ^ key[j]) & 0xFF))
```
![image](https://hackmd.io/_uploads/SJZ_bHG-eg.png)
![image](https://hackmd.io/_uploads/S1WEGSzbxx.png)

Như vậy file `hehe.txt` chứa thông tin máy tính của nạn nhân, còn `huhu.txt` chứa chuỗi sha256 là pass giải nén file `find_the_pass.7z` cho stage 3.


### Stage 3 find the pass
#### 1. Tổng quan
![image](https://hackmd.io/_uploads/HJ18fBM-xl.png)
![image](https://hackmd.io/_uploads/H1WgHrzZex.png)

Stage 3 cho 1 file `PE64`.

#### 2. Phân tích
```cpp
// Hidden C++ exception states: #wind=1
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  const BYTE *iv[3]; // [rsp+28h] [rbp-51h] BYREF
  BYTE *key[3]; // [rsp+40h] [rbp-39h] BYREF
  __int64 flag_bin[3]; // [rsp+58h] [rbp-21h] BYREF
  BYTE *enc_flag[3]; // [rsp+70h] [rbp-9h] BYREF
  __int64 test_flag; // [rsp+88h] [rbp+Fh] BYREF
  int v10; // [rsp+90h] [rbp+17h]
  _DWORD v11[13]; // [rsp+94h] [rbp+1Bh] BYREF

  test_flag = 0x4A5A6B8DC2BFC37DLL;
  v10 = 2097848514;
  qmemcpy(v11, "    }GALKMACTF{THIS_IS_A_TEST_FLAG}    }", 40);
  v11[10] = 1514840074;
  v11[11] = 2113899883;
  memset(flag_bin, 0, sizeof(flag_bin));
  to_bin(flag_bin, (__int64)&test_flag);
  memset(key, 0, sizeof(key));
  sha256_name_computer(key);
  memset(iv, 0, sizeof(iv));
  serial_volume(iv);
  memset(enc_flag, 0, sizeof(enc_flag));
  AES_CBC_encrypt(enc_flag, (__int64)flag_bin, (__int128 **)key, iv);
  v3 = (_QWORD *)sub_140001410(&test_flag, enc_flag);
  cout(std::cout, v3);
  if ( *(_QWORD *)&v11[3] >= 0x10u )
    operator delete((void *)test_flag);
  if ( enc_flag[0] )
    operator delete(enc_flag[0]);
  if ( iv[0] )
    operator delete((void *)iv[0]);
  if ( key[0] )
    operator delete(key[0]);
  if ( flag_bin[0] )
    operator delete((void *)flag_bin[0]);
  return 0;
}
```
Debug và đổi tên được các hàm như trên.

Tổng quát thì nó chuyển flag sang binary --> lấy tên máy tính $SHA256$ làm `key` --> lấy serial của ổ C làm `iv` --> mã hóa $AES\_CBC$ sau đó in ra flag.

Trong file `hehe.txt` đã khôi phục có lưu thông tin máy tính nạn nhân chứa tên máy tính và serial ổ C dùng cho việc mã hóa:
```
Host Name:                 DESKTOP-NEU8R5D
Volume Serial Number: 	   6CCF-75D6
```

#### 3. Solve
Có đầy đủ dữ kiện rồi thì lụm flag thôi.
```python
from Crypto.Cipher import AES
from hashlib import sha256

hostname = b'DESKTOP-NEU8R5D'
serial = '6CCF-75D6'.split('-')
key = sha256(hostname).digest()[:32]
iv = bytes.fromhex(''.join(serial*4))
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = open('flag.txt', 'rb').read()
flag = cipher.decrypt(flag)
print(flag.decode())
```

<details>
  <summary><strong><code>Flag:</code></strong></summary>

  ```
  KMACTF{anh_hung`_benj_nun`_na'_na`_na_anh_tran_manh_hung`}
  ```
</details>



## packer
### 1. Tổng quan
![image](https://hackmd.io/_uploads/H19F_XmZxe.png)
![image](https://hackmd.io/_uploads/SJEuKmm-gx.png)

Challenge cho 1 file `PE64` sử dụng kỹ thuật pack, anti-analysis(anti-debug, anti-vm, ...)

### 2. Phân tích
#### execute_workflow
```cpp
// Hidden C++ exception states: #wind=1
void execute_workflow(void)
{
  Stage current_stage; // ebx
  __int32 v1; // ebx
  __int32 v2; // ebx
  __int32 v3; // ebx
  unsigned __int16 i; // bx
  _MINIMAL_IMAGE_SECTION_HEADER *v5; // r9
  int Characteristics; // eax
  DWORD v7; // r8d
  MinimalHeaders *minimal_headers; // rax
  std::vector<_MINIMAL_IMAGE_SECTION_HEADER> *p_sections; // rbx
  _MINIMAL_IMAGE_SECTION_HEADER *Myfirst; // r8
  unsigned __int64 v11; // rdx
  unsigned __int8 *v12; // rcx
  unsigned __int64 v13; // rdx
  std::ostream *v14; // rbx
  DWORD LastError; // eax
  std::ostream *v16; // rax
  std::ostream *(__fastcall *v17)(std::ostream *); // rdx
  unsigned __int8 *v18; // rdi
  __int64 v19; // rbx
  MinimalHeaders result; // [rsp+20h] [rbp-E0h] BYREF
  unsigned int flOldProtect[2]; // [rsp+F0h] [rbp-10h] BYREF
  ObfuscatedState state; // [rsp+100h] [rbp+0h] BYREF

  SetUnhandledExceptionFilter(CustomExceptionHandler);
  if ( is_running_in_vm() )
    return;
  state.image = 0;
  state.headers.dos.e_lfanew = 0;
  memset(state.headers.nt, 0, 228);
  current_stage = INIT;
  if ( is_running_in_vm() )
    goto LABEL_34;
  while ( 1 )
  {
    if ( current_stage == INIT )
    {
      minimal_headers = get_minimal_headers(&result);
      state.headers.dos.e_lfanew = minimal_headers->dos.e_lfanew;
      *(_OWORD *)state.headers.nt = *(_OWORD *)minimal_headers->nt;
      *(_OWORD *)&state.headers.nt[16] = *(_OWORD *)&minimal_headers->nt[16];
      *(_OWORD *)&state.headers.nt[32] = *(_OWORD *)&minimal_headers->nt[32];
      *(_OWORD *)&state.headers.nt[48] = *(_OWORD *)&minimal_headers->nt[48];
      *(_OWORD *)&state.headers.nt[64] = *(_OWORD *)&minimal_headers->nt[64];
      *(_OWORD *)&state.headers.nt[80] = *(_OWORD *)&minimal_headers->nt[80];
      *(_OWORD *)&state.headers.nt[96] = *(_OWORD *)&minimal_headers->nt[96];
      *(_OWORD *)&state.headers.nt[112] = *(_OWORD *)&minimal_headers->nt[112];
      *(_OWORD *)&state.headers.nt[128] = *(_OWORD *)&minimal_headers->nt[128];
      *(_OWORD *)&state.headers.nt[144] = *(_OWORD *)&minimal_headers->nt[144];
      *(_OWORD *)&state.headers.nt[160] = *(_OWORD *)&minimal_headers->nt[160];
      p_sections = &minimal_headers->sections;
      if ( &state.headers.sections != &minimal_headers->sections )
      {
        Myfirst = state.headers.sections._Mypair._Myval2._Myfirst;
        if ( state.headers.sections._Mypair._Myval2._Myfirst )
        {
          v11 = 28 * (state.headers.sections._Mypair._Myval2._Myend - state.headers.sections._Mypair._Myval2._Myfirst);
          if ( v11 >= 0x1000 )
          {
            v11 += 39LL;
            Myfirst = *(_MINIMAL_IMAGE_SECTION_HEADER **)&state.headers.sections._Mypair._Myval2._Myfirst[-1].PointerToRawData;
            if ( (unsigned __int64)((char *)state.headers.sections._Mypair._Myval2._Myfirst - (char *)Myfirst - 8) > 0x1F )
              invalid_parameter_noinfo_noreturn();
          }
          operator delete(Myfirst, v11);
        }
        state.headers.sections = *p_sections;
        p_sections->_Mypair._Myval2._Myfirst = 0;
        p_sections->_Mypair._Myval2._Mylast = 0;
        p_sections->_Mypair._Myval2._Myend = 0;
      }
      std::vector<_MINIMAL_IMAGE_SECTION_HEADER>::~vector<_MINIMAL_IMAGE_SECTION_HEADER>(&result.sections);
      current_stage = LOAD;
      goto LABEL_32;
    }
    v1 = current_stage - 1;
    if ( !v1 )
    {
      if ( !load_stage(&state) )
        goto LABEL_34;
      current_stage = state.current_stage;
      goto LABEL_33;
    }
    v2 = v1 - 1;
    if ( !v2 )
    {
      if ( !fixup_stage(&state) )
        goto LABEL_34;
      current_stage = state.current_stage;
      goto LABEL_33;
    }
    v3 = v2 - 1;
    if ( v3 )
      break;
    for ( i = 0; i < *(_WORD *)&state.headers.nt[2]; ++i )
    {
      v5 = &state.headers.sections._Mypair._Myval2._Myfirst[i];
      Characteristics = v5->Characteristics;
      if ( (Characteristics & 0x20000000) != 0 )
      {
        if ( Characteristics >= 0 )
        {
          v7 = 16;
          if ( (Characteristics & 0x40000000) != 0 )
            v7 = 32;
        }
        else
        {
          v7 = 64;
        }
      }
      else if ( Characteristics >= 0 )
      {
        v7 = 1;
        if ( (Characteristics & 0x40000000) != 0 )
          v7 = 2;
      }
      else
      {
        v7 = 4;
      }
      if ( !VirtualProtect(&state.image[v5->VirtualAddress], v5->SizeOfRawData, v7, flOldProtect) )
      {
        v14 = std::operator<<<std::char_traits<char>>(&std::cerr, "Error: failed to set section protection. Error: ");
        LastError = GetLastError();
        v16 = std::ostream::operator<<(v14, LastError);
        std::ostream::operator<<(v16, v17);
        ExitProcess(3u);
      }
    }
    current_stage = EXECUTE;
LABEL_32:
    state.current_stage = current_stage;
LABEL_33:
    if ( is_running_in_vm() )
      goto LABEL_34;
  }
  if ( v3 == 1 )
  {
    v18 = &state.image[*(unsigned int *)&state.headers.nt[12]];
    v19 = 8;
    do
    {
      GetTickCount64();
      --v19;
    }
    while ( v19 );
    if ( !is_debugger_present() && !has_hardware_breakpoints() && v18 )
    {
      *(_QWORD *)flOldProtect = v18;
      if ( is_debugger_present() || has_hardware_breakpoints() )
        MEMORY[0]();
      else
        ((void (*)(void))_InterlockedExchange64((volatile __int64 *)flOldProtect, *(__int64 *)flOldProtect))();
    }
  }
LABEL_34:
  v12 = state.raw_image._Mypair._Myval2._Myfirst;
  if ( state.raw_image._Mypair._Myval2._Myfirst )
  {
    v13 = state.raw_image._Mypair._Myval2._Myend - state.raw_image._Mypair._Myval2._Myfirst;
    if ( (unsigned __int8 *)(state.raw_image._Mypair._Myval2._Myend - state.raw_image._Mypair._Myval2._Myfirst) >= (unsigned __int8 *)0x1000 )
    {
      v13 += 39LL;
      v12 = (unsigned __int8 *)*((_QWORD *)state.raw_image._Mypair._Myval2._Myfirst - 1);
      if ( (unsigned __int64)(state.raw_image._Mypair._Myval2._Myfirst - v12 - 8) > 0x1F )
        invalid_parameter_noinfo_noreturn();
    }
    operator delete(v12, v13);
    memset(&state.raw_image, 0, sizeof(state.raw_image));
  }
  std::vector<_MINIMAL_IMAGE_SECTION_HEADER>::~vector<_MINIMAL_IMAGE_SECTION_HEADER>(&state.headers.sections);
}
```
Hàm duy nhất được gọi trong `main` thực hiện các bước liên quan đến đọc thông tin từ **PE Header** --> cài đặt các truy cập section --> sử dụng kỹ thuật anti-debug, anti-vm --> nếu chương trình không chạy trong máy ảo hoặc bị debug thì thực thi shellcode tại entry point:
![image](https://hackmd.io/_uploads/B1bB1EQ-xg.png)

Đây là anti-vm, nếu chạy chương trình bằng 1 trong các vm đã liệt kê thì thoát chương trình:
![image](https://hackmd.io/_uploads/rJVs2IXbge.png)

Để tiện debug và quan sát hoạt động của shellcode thì bypass những đoạn check vm và debug bằng cách patch nop đi là được.

Trước khi vào shellcode thì quan sát kỹ đoạn mã của `_scrt_common_main_seh()` của challenge này, 1 hàm liên quan đến startup của 1 ứng dụng Windows sử dụng Microsoft CRT (C Runtime Library) giúp quản lý khởi động và dọn dẹp bộ nhớ khi chương trình kết thúc:
![image](https://hackmd.io/_uploads/SyHYlVXZxg.png)

![image](https://hackmd.io/_uploads/HkGRfN7bge.png)

Đây là hàm bên trong shellcode được thực thi, chức năng y hệt như hàm `_scrt_common_main_seh` --> như vậy hàm `execute_flow` là 1 unpacker thực hiện giải mã vùng code và lấy địa chỉ hàm entry đã được unpack để thực thi luồng thật sự.

#### main_process
Gồm các phần chính như sau:
* Đọc input và chuyển đổi ký tự số sang số nguyên (`*inp - '0'`) rồi lưu vào mảng
![image](https://hackmd.io/_uploads/H1-j8EQ-lg.png)

* Chuyển đổi mảng số input tạo thành mã máy để gây ra ngoại lệ (`0F 0B --> ud2`) 
> ud2 gây ra **Invalid Opcode Exception** tức là đánh dấu 1 đoạn mã không hợp lệ.
* Debug nhập thử 30 ký tự `1` thì nó sẽ thêm `ud2` xen kẽ phía trước từng giá trị input tạo thành 1 đoạn mã máy để thực thi.
![image](https://hackmd.io/_uploads/Hk1JlU7Zgx.png)

* Thiết lập các Vectored Exception Handlers (VEH) để xử lý ngoại lê:
![image](https://hackmd.io/_uploads/Byv50HX-xx.png)

Để ý `qword_1D413D377C8()` chính là đoạn mã máy được tạo để thực thi ở trên.

Nhìn chung các hàm `func` mà VEH đăng ký sẽ xử lý ngoại lệ illegal instruction (lệnh không hợp lệ `ud2` như đã đề cập) sẽ kiểm tra giá trị tại `*(rip+2)`(byte thứ 3) để quyết định call hàm nào và qua tìm hiểu thì nó chính là thao tác của [brainfuck vm](https://github.com/acdzh/BrainFuckVM/blob/master/src/bl.cc)
![image](https://hackmd.io/_uploads/rJ3iZUQbgl.png)

##### func0
Xử lý mã máy tại `*(rip+2)` nếu = `0` tương đương với `>` tức dịch con trỏ dữ liệu sang phải.

![image](https://hackmd.io/_uploads/ryQp7IQZee.png)

##### func1
`1` ~ `<` : dịch con trỏ dữ liệu sang trái

![image](https://hackmd.io/_uploads/S1FNfIQZel.png)

##### func2
`2` ~ `+` : tăng giá trị tại ô hiện tại

![image](https://hackmd.io/_uploads/BkJPE87Zgl.png)

##### func3
`3` ~ `-` : giảm giá trị tại ô hiện tại

![image](https://hackmd.io/_uploads/ByhDHLXbgg.png)

##### func4
`4` ~ `.` : in giá trị tại ô hiện tại đồng thời kiểm tra xem kết quả có là `KMA CTF 2025` hay không? Nếu không thì không in ra thông báo gì.

![image](https://hackmd.io/_uploads/r165B87bll.png)

##### func5
`5` ~ `,` : nhận 1 giá trị

![image](https://hackmd.io/_uploads/rJF9587bxx.png)

##### func6
`6` ~ `[` : bắt đầu loop

![image](https://hackmd.io/_uploads/BJc_9U7bxg.png)

##### func7
`7` ~ `]` : kết thúc loop

![image](https://hackmd.io/_uploads/rkgx5U7ble.png)


##### jmp
Nếu input không hợp lệ thì bỏ qua nhảy sang mã máy tiếp theo.

### 3. Solve
Tóm lại challenge sẽ nhận input, biến đổi thành 1 đoạn mã máy xen kẽ là lệnh không hợp lệ `ud2` sau đó thực thi.
Với mỗi giá trị input sẽ ứng với các `func` mà VEH đã đăng ký để xử lý, nếu output là `KMA CTF 2025` thì input đó hợp lệ.

Như vậy, cần phải nhập 1 chuỗi số sao cho qua brainfuck vm đó để in ra`KMC CTF 2025`.

Chuyển chuỗi `KMA CTF 2025` sang mã brainfuck: 
```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>+++++.++.------------.<++.>++.>----------------.<+++.<.++++++++++++++++++.--.++.+++.
```
Mỗi giá trị trong mã sẽ ứng với các `func`ở trên nên từ đó có thể khôi phục lại chuỗi số ban đầu.
> solve.py
```python
func = {
    '>': '0',
    '<': '1',
    '+': '2',
    '-': '3',
    '.': '4',
    ',': '5',
    '[': '6',
    ']': '7'
}
bf_code = "++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>+++++.++.------------.<++.>++.>----------------.<+++.<.++++++++++++++++++.--.++.+++."
inp = ''
for c in bf_code:
    if c in func:
        inp += func[c]
print(inp)
```
![image](https://hackmd.io/_uploads/B14CPLm-gg.png)
