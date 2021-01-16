import sys, codecs
from functools import partial
from struct import unpack
'''
>>> from xview import examine
'''


class Ex:
    def __init__(self, cols, fmt, unit, endianess, sep='  '):
        self._validate_params(cols, fmt, unit, endianess, sep)
        self._unpacker, self._sz = self._build_unpacker(fmt, unit, endianess)

        self._formatter = self._build_formatter(fmt, unit, endianess, self._sz)

        self._cols = cols
        self._sep = sep

    def _validate_params(self, cols, fmt, unit, endianess, sep):
        if cols is not None and not (0 < cols <= 64):
            raise ValueError(
                "Column count '%s' must be a number between 1 and 64 or None."
                % cols
            )

        if unit not in ('b', 'h', 'w', 'g'):
            raise ValueError(
                "Unit '%s' unknown. Expected (b)yte, (h)alf, (w)ord or (g)iant."
                % unit
            )

        if fmt not in (
            'x', 'd', 'u', 'o', 't', 'a', 'c', 'f', 's', 'z', 'r', 'i'
        ):
            raise ValueError(
                "Format '%s' unknown. Expected he(x), signe(d), (u)nsigned, (o)ctal, (t)wo, (a)ddress, (c)har, (f)loat, (s)tring, (z)ero padded, (r)aw or (i)nstruction."
                % fmt
            )

        if fmt == 'f' and unit not in ('w', 'g'):
            raise ValueError(
                "Format (f)loat can work only with (w)ords and (g)iants units but received '%s'"
                % unit
            )

        if fmt in ('c', 's') and unit == 'g':
            raise ValueError("Format (c)har/(s)tring can work (g)iant units.")

        if fmt in ('a', 'i', 'z', 's'):
            raise NotImplementedError("Format '%s' not supported yet." % fmt)

        if endianess not in ('b', 'l', 'n'):
            raise ValueError(
                "Endianess type '%s' unknown. Expected (b)ig, (l)ittle or (n)ative."
            )

    def _build_unpacker(self, fmt, unit, endianess):
        # format for struct.unpack
        sfmt = {'b': '>', 'l': '<', 'n': '='}[endianess]

        # struct.unpack opcode and size in bytes of the object
        op, sz = {
            'b': ('B', 1),
            'h': ('H', 2),
            'w': ('I', 4),
            'g': ('L', 8),
        }[unit]

        if fmt == 'r':
            op = '%is' % sz  # raw means raw string, no conversion

        if fmt == 'd':
            op = op.lower()  # signed version

        if fmt == 'f':
            assert sz in (4, 8)
            op = 'f' if sz == 4 else 'd'

        # encoding for string-like examinations based on the object's size
        if fmt in ('c', 's'):
            enc = {1: 'utf-8', 2: 'utf-16', 4: 'utf-32'}[sz]

            force_big_endian = endianess == 'b' or (
                endianess == 'n' and sys.byteorder == 'big'
            )
            if force_big_endian:
                enc += '-be'
            else:
                assert endianess == 'l'
                enc += '-le'

        # final format for struct.unpack and method for unpacking;
        # 'c' is special as it will not use struct.unpack at all
        # but str
        if fmt in ('c', ):
            sfmt = None
            unpack = partial(str, encoding=enc, errors='replace')
        else:
            sfmt = sfmt + op
            unpack = partial(_unpack_1, sfmt=sfmt)

        return unpack, sz

    def _build_formatter(self, fmt, unit, endianess, sz):
        # representation type (method format()) and padding per byte
        ftype, npad = {
            'x': ('x', 2),
            'd': ('d', 0),
            'u': ('d', 0),  # same as 'd'
            'o': ('o', 3),
            't': ('b', 8),
            'f': ('e', 0),
            'c': ('', 0),
            'r': ('', 0),
            's': ('', 0),
        }[fmt]

        # eg: an he(x) with npad of 2 requires 8 bytes of padding
        # to print a 4 bytes numbers like 0x0000abcd
        npad *= sz

        # representation format (method format())
        # eg: {0:08x} or {0:d} or {0:}
        if npad:
            rfmt = '{0:0{npad}{ftype}}'
        else:
            rfmt = '{0:{ftype}}'

        return partial(_format_1, rfmt=rfmt, npad=npad, ftype=ftype)

    def print(self, mem):
        mem = memoryview(mem)  # avoid copies when slicing
        cols = self._cols
        sep = self._sep

        sz = self._sz
        unpack = self._unpacker
        formatter = self._formatter

        offset = 0
        cnt = len(mem) // sz
        line = []
        for i, offset in enumerate(range(0, cnt * sz, sz), 1):
            m = mem[offset:offset + sz]

            obj = unpack(m)

            line.append(formatter(obj))

            if cols is None:
                assert len(line) == 1
                print(*line, end=sep)
                line.clear()

            elif i % cols == 0:
                print(*line, sep=sep)
                line.clear()

        if line:
            print(*line, sep=sep)


def _unpack_1(data, sfmt):
    # note: the colon after 'obj' forces a tuple unpack. If
    # the method returns anything else except a tuple with a single element
    # this will fail (and it should it!)
    obj, = unpack(sfmt, data)
    return obj


def _format_1(obj, rfmt, **kargs):
    return rfmt.format(obj, **kargs)


# https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html
# https://sourceware.org/gdb/current/onlinedocs/gdb/Output-Formats.html#Output-Formats
# https://blog.mattjustice.com/2018/08/24/gdb-for-windbg-users/
# invalid utf16: string s = "a\ud800b";
def examine(mem, cols, fmt, unit, endianess, sep='  '):
    '''
        >>> b1 = bytes.fromhex('04fdffbe21000000')

        The left lower-index side of the bytes are interpreted as
        low addresses.

        When you see the memory as a sequence of bytes this
        is not important:
        >>> examine(b1, cols=None, fmt='x', unit='b', endianess='b')
        04  fd  ff  be  21  00  00  00

        But when you see it as elements of more than one byte it is
        because the endianess plays a role here:

        Little endian (left/lower addresses are less significant;
        "bytes are swapped"):
        >>> examine(b1, cols=None, fmt='x', unit='w', endianess='l')
        befffd04  00000021

        Big endian (left/lower addresses are more significant;
        "bytes are not swapped"):
        >>> examine(b1, cols=None, fmt='x', unit='w', endianess='b')
        04fdffbe  21000000

        Decimal (signed and unsigned) interpretations:

        >>> examine(b1, cols=None, fmt='d', unit='w', endianess='l')
        -1090519804  33

        >>> examine(b1, cols=None, fmt='u', unit='w', endianess='l')
        3204447492  33

        This differs a little from gdb's output where the last number (1)
        is padded with a single 0 while in our case is padded to complete
        the necessary digits to represent a 4 bytes (word) number.

        >>> examine(b1, cols=None, fmt='o', unit='w', endianess='l')
        027677776404  000000000041

        >>> examine(b1, cols=None, fmt='t', unit='w', endianess='l')
        10111110111111111111110100000100  00000000000000000000000000100001

        This differs from gdb: 'raw' means for gdb 'do not pretty print'.
        Because such pretty print does not exist in out case, 'raw' means
        print the byte strings (and ignore the endianess)

        >>> examine(b1, cols=None, fmt='r', unit='w', endianess='l')
        b'\x04\xfd\xff\xbe'  b'!\x00\x00\x00'

        When the (c)har format is used, the interpretation of unit
        changes: not only specifies how much bytes each character
        will consume but also which encoding to use to decode it.

            (b)yte reads 1 byte and decodes it as utf-8
            (h)alf reads 2 bytes and decode them as utf-16
            (w)ord reads 4 bytes and decode them as utf-32

        (g)iant is not supported.

        Note that utf-8 and utf-16 are *variable size* decoders:
        a single character may require 1 or more bytes to be decoded
        however xview will *not* read a variable amount of bytes;
        the specified unit will be honored.

        GDB does something weird in this case: it reads the same amount
        of bytes than xview but then it sees the read number module 256
        and print it as a char and an octal.

        xview follows more the GDB approach of the 's' format.

        >>> examine(b1, cols=None, fmt='c', unit='w', endianess='l')
        �  !

        Note that endianess plays a role here too:

        >>> examine(b1, cols=None, fmt='c', unit='h', endianess='l')
        ﴄ  뻿  ! <...>

        >>> examine(b1, cols=None, fmt='c', unit='h', endianess='b')
        ӽ  ﾾ  ℀  <...>

        Float point works similar for (w)ords and (g)iants but it is
        not supported for (b)ytes and (h)alf. In those cases gdb rollbacks
        to a decimal notation.
        >>> examine(b1, cols=None, fmt='f', unit='w', endianess='l')
        -4.999772e-01  4.624285e-44

        >>> examine(b1, cols=None, fmt='f', unit='g', endianess='l')
        7.160907e-313

        '''
    return Ex(cols, fmt, unit, endianess, sep).print(mem)
