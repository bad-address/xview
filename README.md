# `xview`

`xview` is a small but quite flexible way to see binary data. Think in
tools like `hexdump` and `xxd` but with super powers.

## High level functions: `hexdump` and `display`

At a high level, `xview` offers the traditional `hexdump` function:


```python
>>> from xview import hexdump

>>> b1 = bytes.fromhex('255044462d312e320d25e2e3cfd30d0a323234372030206f626a0d3c3c200d2f4c696e656172697a65642031200d')
>>> hexdump(b1)
00000000  25 50 44 46 2d 31 2e 32  0d 25 e2 e3 cf d3 0d 0a  |%PDF-1.2.%......|
00000010  32 32 34 37 20 30 20 6f  62 6a 0d 3c 3c 20 0d 2f  |2247 0 obj.<< ./|
00000020  4c 69 6e 65 61 72 69 7a  65 64 20 31 20 0d        |Linearized 1 .  |
```

A more flexible tool is `display` which has some other predefined
layouts.

Display words of 4 bytes in hexadecimal (you can control the endianess
with '>' (big), '<' (little) or '=' (native)):

```python
>>> from xview import display
>>> display('dc', b1, endianess='>')
00000000  25504446 2d312e32 0d25e2e3 cfd30d0a  |%PDF-1.2.%......|
00000010  32323437 2030206f 626a0d3c 3c200d2f  |2247 0 obj.<< ./|
00000020  4c696e65 6172697a 65642031           |Linearized 1 .  |
```

Display float of 4 bytes:

```python
>>> display('df', b1)
00000000  1.256404e+04  1.013931e-08  -8.343268e+21  6.828740e-33
00000010  1.074052e-05  4.957578e+28  8.631321e-03  1.283533e-10
00000020  7.036660e+22  3.030313e+35  2.334013e-09
```

Even you can disassemble the binary. You will need to have `Capstone`
installed first.

```python
>>> display('uu', b1, extra_kargs={'arch': 'x86', 'mode': 64})
00000000  and     eax, 0x2d464450
00000005  xor     dword ptr [rsi], ebp
<...>
00000029  and     byte ptr fs:[rcx], dh
0000002c  .byte   0x20
0000002d  .byte   0x0d
```

See the documentation of `hexdump` and `display` to have a complete
picture.

## Low level objects: `Ex` and `Formatter`

`xview` also offers you a low level API.

The core of `xview` are the `Ex` objects, *examiners* that reads and
interprets the raw data.

This includes the size of each element, the endianess and the format.

For example the following shows little endian words of 4 bytes
in octal format:

```python
>>> from xview import Ex

>>> ex0 = Ex(fmt='o', sz=4, endianess='<')
>>> print('\n'.join(out for address, out in ex0.examine_iter(b1)))
010621050045
006213430455
034370422415
<...>
014533464514
017232271141
006110062145
```

While the next example shows the same input as unsigned decimal numbers
of 1 byte each:

```python
>>> ex1 = Ex(fmt='u', sz=1, endianess='=')
>>> print('\n'.join(out for address, out in ex1.examine_iter(b1)))
37
80
68
70
45
<...>
32
49
32
13
```

The glue that combines different examiners is the `Formatter` object.

It allows to see the same memory with different representations at the
same time, showing them *line by line*.

What defines a *line* is the *line format*.

```python
>>> line_fmt = "{addr:08x}: {0:1//12} | {1:4}"
```

The above says:

 - show the address of the line in hexadecimal notation
 - show 1 element from the examiner `0` filling with spaces to complete
   12 characters
 - show 4 elements from the examiner `4`

The `Formatter` object is created as:

```python
>>> from xview import Formatter
>>> f = Formatter(line_fmt, '*', ex0, ex1)
```

So the examiner `0` is `ex0`, the octal examiner and `1` is `ex1`, the
decimal examiner.

Here is the result of showing the data `b1` in octal an in decimal
notations:


```python
>>> print('\n'.join(f.lines(b1, 0, ruler=1)))
00000000: 010621050045 | 37 80 68 70
00000004: 006213430455 | 45 49 46 50
00000008: 034370422415 | 13 37 226 227
0000000c: 001203351717 | 207 211 13 10
<...>
00000020: 014533464514 | 76 105 110 101
00000024: 017232271141 | 97 114 105 122
00000028: 006110062145 | 101 100 32 49
0000002c:              | 32 13
```

Take at look at the documentation of `Ex` and `Formatter` for more
examples.

## License

This project is licensed under LGPLv3

```shell
$ head -n 2 LICENSE     # byexample: +norm-ws
       GNU LESSER GENERAL PUBLIC LICENSE
           Version 3, 29 June 2007
```

See [LICENSE](https://github.com/bad-address/xview/tree/master/LICENSE.md) for more details.
