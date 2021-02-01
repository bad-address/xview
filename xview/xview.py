import sys, codecs
from functools import partial
from struct import unpack
from itertools import islice
import string
from more_itertools import peekable, take

try:
    import capstone
    is_capstone_available = True
except ImportError:
    is_capstone_available = False
'''
>>> from xview import examine, Ex, Formatter, display

>>> def print_iter1(it):
...     print('\n'.join('%s' % t for t in it))

>>> def print_iter2(it):
...     print('\n'.join('%s  %s' % t for t in it))
'''

# what unicodes are control code?
#   import unicodedata
#   ctrl_codes = [i for i in range(sys.maxunicode+1)
#                   if unicodedata.category(chr(i)) == 'Cc']
#
#   0 <= i <= 31 or 127 <= i <= 159
#
# whitespace control codes?: 9 <= i <= 13
ctrl_tr = {
    i: u'.' if (0 <= i <= 31 or 127 <= i <= 159) else chr(i)
    for i in range(160)
}

## (0 <= i <= 31 or 127 <= i <= 159) and not (9 <= i <= 13) else chr(i)


class Ex:
    def __init__(self, fmt, sz, endianess):
        sz = self._alias_sz(sz)
        self._validate_params(fmt, sz, endianess)
        self._fmt = fmt

        self._unpacker, self._sz = self._build_unpacker(fmt, sz, endianess)
        self._formatter = self._build_formatter(fmt, sz, endianess)

    def _are_we_examining_instructions(self):
        return self._fmt == 'i'

    def _alias_sz(self, sz):
        if isinstance(sz, str) and sz.isdigit():
            return int(sz)
        return sz

    def _validate_params(self, fmt, sz, endianess):
        if fmt != 'i' and sz not in (1, 2, 4, 8):
            raise ValueError(
                "Size '%s' unknown. Expected 1, 2, 4, or 8 bytes." % sz
            )

        if fmt == 'i':
            try:
                arch, mode = sz
            except ValueError:
                raise ValueError(
                    "Unit must be a tuple with the architecture and mode for Capstone."
                )

            if not is_capstone_available:
                raise ValueError("Capstone engine is not available.")

        if fmt not in (
            'x', 'd', 'u', 'o', 'b', 'a', 'c', 'f', 's', 'z', 'r', 'i'
        ):
            raise ValueError(
                "Format '%s' unknown. Expected he(x), signe(d), (u)nsigned, (o)ctal, (b)inary, (a)ddress, (c)har, (f)loat, (s)tring, (z)ero padded, (r)aw or (i)nstruction."
                % fmt
            )

        if fmt == 'f' and sz not in (4, 8):
            raise ValueError(
                "Format (f)loat can work only with 4 and 8 sizes but received '%s'"
                % sz
            )

        if fmt in ('c', 's') and sz == 8:
            raise ValueError(
                "Format (c)har/(s)tring cannot work with sizes of 8 bytes."
            )

        if fmt in ('a', 'z', 's'):
            raise NotImplementedError("Format '%s' not supported yet." % fmt)

        if endianess not in ('>', '<', '='):
            raise ValueError(
                "Endianess type '%s' unknown. Expected (>)big, (<)little or (=)native."
            )

    def _build_unpacker(self, fmt, sz, endianess):
        if self._are_we_examining_instructions():
            md = capstone.Cs(*sz)
            md.skipdata = True

            unpack = partial(md.disasm_lite, offset=0)
            return unpack, 0

        # format for struct.unpack
        sfmt = {'>': '>', '<': '<', '=': '='}[endianess]

        # struct.unpack opcode of the object
        op = {
            1: 'B',
            2: 'H',
            4: 'I',
            8: 'L',
        }[sz]

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

            force_big_endian = endianess == '>' or (
                endianess == '=' and sys.byteorder == 'big'
            )

            if sz != 1:
                if force_big_endian:
                    enc += '-be'
                else:
                    assert endianess == '<'
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

    def _build_formatter(self, fmt, sz, endianess):
        if self._are_we_examining_instructions():
            return _format_ins

        # representation type (method format()) and padding per byte
        ftype, npad = {
            'x': ('x', 2),
            'd': ('d', 0),
            'u': ('d', 0),  # same as 'd'
            'o': ('o', 3),
            'b': ('b', 8),
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

        if fmt == 'c':
            return partial(_format_c, rfmt=rfmt, npad=npad, ftype=ftype)
        else:
            return partial(_format_1, rfmt=rfmt, npad=npad, ftype=ftype)

    def examine_iter(self, mem, start_addr=0):
        ''' Iterate over the given bytes yielding (addr, output) tuples.

            The addresses are the offset in the input where the elements
            were taken and the output are their representations as strings.

            Optionally the starting address can be specified.

            <mem> can be bytes or a memoryview. If the format specified
            in the constructor was (i)nstructions, <mem> must be bytes.

            Examples:

            >>> b1 = bytes.fromhex('04fdffbe21000000')

            1 byte in hexadecimal notation:
            >>> print_iter2(Ex(fmt='x', sz=1, endianess='>').examine_iter(b1))
            0  04
            1  fd
            2  ff
            3  be
            4  21
            5  00
            6  00
            7  00

            4 bytes in hexadecimal, reading in little and big endian:
            >>> print_iter2(Ex(fmt='x', sz=4, endianess='<').examine_iter(b1))
            0  befffd04
            4  00000021

            >>> print_iter2(Ex(fmt='x', sz=4, endianess='>').examine_iter(b1))
            0  04fdffbe
            4  21000000

            Big endian is equivalent to do slicing from the input bytes:
            >>> b1[0:4].hex(), b1[4:8].hex()
            ('04fdffbe', '21000000')

            Decimal (signed (d) and unsigned (u)) interpretations:

            >>> print_iter2(Ex(fmt='d', sz=4, endianess='<').examine_iter(b1))
            0  -1090519804
            4  33

            >>> print_iter2(Ex(fmt='u', sz=4, endianess='<').examine_iter(b1))
            0  3204447492
            4  33

            Octal (o) and binary (b) interpretations:

            >>> print_iter2(Ex(fmt='o', sz=4, endianess='<').examine_iter(b1))
            0  027677776404
            4  000000000041

            >>> print_iter2(Ex(fmt='b', sz=4, endianess='<').examine_iter(b1))
            0  10111110111111111111110100000100
            4  00000000000000000000000000100001

            Raw strings (like slicing) (the endianess is ignored)
            >>> print_iter2(Ex(fmt='r', sz=4, endianess='<').examine_iter(b1))
            0  b'\x04\xfd\xff\xbe'
            4  b'!\x00\x00\x00'

            When the (c)har format is used, the interpretation of <sz>
            changes: not only specifies how much bytes each character
            will consume but also which encoding to use to decode it.

                sz==1 reads 1 byte and decodes it as utf-8
                sz==2 reads 2 bytes and decode them as utf-16
                sz==4 reads 4 bytes and decode them as utf-32

            Sizes of 8 are not supported.

            Note that utf-8 and utf-16 are *variable size* decoders:
            a single character may require 1 or more bytes to be decoded.

            However xview will *not* read a variable amount of bytes;
            the specified size will be honored.

            >>> print_iter2(Ex(fmt='c', sz=1, endianess='<').examine_iter(b1))  # byexample: +skip
            0  ?
            1  �
            2  �
            3  �
            4  !
            5  ?
            6  ?
            7  ?

            >>> print_iter2(Ex(fmt='c', sz=4, endianess='<').examine_iter(b1))  # byexample: +skip
            0  �
            4  !

            Note that endianess plays a role here too:

            >>> print_iter2(Ex(fmt='c', sz=2, endianess='<').examine_iter(b1))  # byexample: +skip
            0  ﴄ
            2  뻿
            4  !
            6  ?

            >>> print_iter2(Ex(fmt='c', sz=2, endianess='>').examine_iter(b1))  # byexample: +skip
            0  ӽ
            2  ﾾ
            4  ℀
            6  ?

            Float point interpretation is supported only for 4 and
            8 bytes sizes.

            >>> print_iter2(Ex(fmt='f', sz=4, endianess='<').examine_iter(b1))
            0  -4.999772e-01
            4  4.624285e-44

            >>> print_iter2(Ex(fmt='f', sz=8, endianess='<').examine_iter(b1))
            0  7.160907e-313

            >>> print_iter2(Ex(fmt='f', sz=2, endianess='<').examine_iter(b1))
            Traceback<...>
            ValueError: Format (f)loat can work only with 4 and 8 sizes but received '2'

            Instructions are decoded too and invalid opcodes are marked
            as "bytes":
            >>> from capstone import *
            >>> print_iter2(Ex(fmt='i', sz=(CS_ARCH_X86, CS_MODE_64), endianess='<').examine_iter(b1))
            0  add     al, 0xfd
            2  .byte   0xff
            3  mov     esi, 0x21
            '''
        if self._are_we_examining_instructions():
            if not isinstance(mem, bytes):
                raise TypeError(
                    "Input memory must by of type 'bytes' but '%s' was found."
                    % type(mem)
                )
            yield from self._examine_instr_iter(mem, start_addr)
        else:
            yield from self._examine_mem_slices_iter(mem, start_addr)

    def _examine_instr_iter(self, mem, start_addr):
        assert self._are_we_examining_instructions()
        unpack = self._unpacker
        formatter = self._formatter

        for addr, size, mnemonic, op_str in unpack(mem, offset=start_addr):
            yield (addr, formatter(mnemonic, op_str, size=size))

    def _examine_mem_slices_iter(self, mem, start_addr):
        assert not self._are_we_examining_instructions()
        unpack = self._unpacker
        formatter = self._formatter

        mem = memoryview(mem)  # avoid copies when slicing
        sz = self._sz

        offset = 0
        cnt = len(mem) // sz
        line = []
        for i, offset in enumerate(range(0, cnt * sz, sz), 1):
            m = mem[offset:offset + sz]

            obj = unpack(m)
            yield start_addr + offset, formatter(obj)


class Formatter:
    def __init__(self, line_fmt, *exs_in_args, **exs_in_kwargs):
        self._line_fmt = line_fmt
        self._examiner_by_key = {
            str(ix): ex
            for ix, ex in enumerate(exs_in_args)
        }
        self._examiner_by_key.update(exs_in_kwargs)
        self._formatter = string.Formatter()

    def _line_template(self, mem, start_addr):
        ''' Return a list of tuples (<literal_text>, <examiner it>,
            <length>, <separator>, <width>, <fill>).

            Each tuple describe what literal text forms the line before the
            output of the examiner (the literal could be empty).

            The examiner's iterator is already initialized with <mem> and
            <start_addr>.

            The <length> defines how many elements from the iterator should
            be read and joined with <separator> to form the output that
            follows the literal text.

            Which of the examiners defined in __init__ is chosen is
            based on the <field_name> extracted from <self._line_fmt>.

            The <length> and the <separator> for each iterator is extracted
            from that <self._line_fmt> too.

            The examiner's iterator can be None in which should be ignored.

            The <self._line_fmt> defines the <literal_text>s, <examiner it>s,
            <length>s and <separator>s (in plural).

            The syntax is similar to the Python Format String
            https://docs.python.org/3/library/string.html#formatstrings.

            Here is an example:

            >>> line_fmt = "line: {0:8/ /23/ }  {0:8/ /23/ } | {1:8/} {1:8/}"

            The <self._line_fmt> uses 2 examiners "0" ans "1". There
            are 2 "calls" to each examiner: 2 calls are made
            to the examiner "0" to read 8 elements in each occasion ({0:8/ /23/ })
            and 2 more calls to the examiner "1" also to read 8 elements
            ({1:8/}).

            After the ":" a serie of parameters can be configured
            separated with "/":

                - <length>: how many entries read from the examiner
                - <separator>: with which string join the entries read
                - <width>: the total width of the output
                - <fill>: with which string the field will be filled if
                  the output is less than <width>

            In {0:8/ /23/ }, we say 8 entries are read from the examiner
            "0", joined with a space and the whole output is filled
            with a space if the string is less than 23.

            The separator, width and fill string can be omitted:
                {0:8/ /23}  use a default fill (a space)
                {0:8/ }     no fill at all
                {0:8}       use a default separator (a space); no fill either

            In {1:8/} the separator is the empty string.

            So, we need to create the examiners "0" and "1":

            >>> ex0 = Ex(fmt='x', sz=1, endianess='>')
            >>> ex1 = Ex(fmt='c', sz=1, endianess='>')

            Note the examiners not necessary must have the same "size"
            (bytes to read) however you need to make sure that the
            bytes per read times the lengths for that examiner
            coincide. In other words, the *total* bytes read for
            each examiner must be the same otherwise one examiner
            will advance faster than other.

            >>> b1 = bytes.fromhex('04fdffbe2100000041412121')
            >>> f = Formatter(line_fmt, ex0, ex1)

            ### print('\n'.join(str(t) for t in f._line_template(b1, start_addr=1)))
            ('line: ', <...>, 8, ' ', 23, ' ')
            ('  ', <...>, 8, ' ', 23, ' ')
            (' | ', <...>, 8, '', 0, ' ')
            (' ', <...>, 8, '', 0, ' ')

        '''
        results = []
        f = self._formatter
        line_fmt = self._line_fmt

        RULE = None
        initialized = {}
        for literal_text, field_name, format_spec, conversion in f.parse(
            line_fmt
        ):
            if field_name is not None:
                if field_name == '':
                    raise ValueError("Empty field names is not supported")

                if field_name == 'addr':
                    if conversion is None:
                        it = '{0:%s}' % (format_spec, )
                    else:
                        it = '{0!%s:%s}' % (conversion, format_spec)
                    length, separator, width, fill = None, None, None, None
                else:
                    it = self.get_iter(
                        field_name, mem, start_addr, initialized
                    )
                    RULE = it

                    # examples:
                    #   {0:8/.} denotes 8 elements from the stream 0 joined
                    #           with a dot
                    #   {0:8/}  denotes 8 elements from the stream 0 joined
                    #   {0:8/ } denotes 8 elements from the stream 0 joined
                    #           with a space
                    #   {0:8}   denotes 8 elements from the stream 0 joined
                    #           with the default separator.
                    tmp = format_spec.split('/')
                    separator, width, fill = ' ', 0, ' '  # defaults
                    if len(tmp) == 1:
                        length = tmp[0]
                    elif len(tmp) == 2:
                        length, separator = tmp
                    elif len(tmp) == 3:
                        length, separator, width = tmp
                    elif len(tmp) == 4:
                        length, separator, width, fill = tmp
                    else:
                        raise ValueError("Invalid format")

                    length = int(length)
                    width = int(width)

            else:
                it, length, separator, width, fill = None, None, None, None, None

            results.append((literal_text, it, length, separator, width, fill))

        # TODO check initialized against self._examiner_by_key
        return results, initialized, RULE

    def _lines(self, mem, start_addr):
        ''' Yields formatted lines from the examined <mem>.
            See _line_template.

            >>> line_fmt = "line: {0:4/ /11}  {0:4/ /11} | {1:4//4} {1:4//4}"
            >>> ex0 = Ex(fmt='x', sz=1, endianess='>')
            >>> ex1 = Ex(fmt='x', sz=1, endianess='>')

            >>> b1 = bytes.fromhex('04fdffbe2100000041412121')
            >>> f = Formatter(line_fmt, ex0, ex1)

            >>> print_iter2(f._lines(b1, start_addr=1))
            1  line: 04 fd ff be  21 00 00 00 | 04fdffbe 21000000
            9  line: 41 41 21 21              | 41412121

        '''
        line = []
        template, initialized, RULE = self._line_template(mem, start_addr)
        exhausted = set()
        line_addr = None
        while len(exhausted) < len(initialized):
            line_addr = RULE.peek()[0]
            for literal_text, examiner_it, length, separator, width, fill in template:
                if literal_text is not None:
                    line.append(literal_text)

                # TODO hardcoded
                if isinstance(examiner_it, str):
                    fmt = examiner_it
                    line.append(fmt.format(line_addr))

                elif examiner_it is not None and examiner_it not in exhausted:
                    # TODO addr is dropped
                    addr_out = take(length, examiner_it)
                    if len(addr_out) < length:
                        exhausted.add(examiner_it)
                    out = separator.join(out for _, out in addr_out)
                    if width:
                        out = out.ljust(width, fill)
                    line.append(out)

            if line:
                yield (line_addr, ''.join(line))
                line = []

    def get_iter(self, key, mem, start_addr, initialized):
        ''' Return an examiner's iterator. The examiner is
            chosen by key and initialized with <mem>
            and <start_addr> if it was not initialized
            previously.

            Otherwise, return and already initialized
            iterator.
            '''
        try:
            return initialized[key]
        except KeyError:
            ex = self._examiner_by_key[key]
            it = peekable(ex.examine_iter(mem, start_addr))
            initialized[key] = it
            return it


def _unpack_1(data, sfmt):
    # note: the colon after 'obj' forces a tuple unpack. If
    # the method returns anything else except a tuple with a single element
    # this will fail (and it should it!)
    obj, = unpack(sfmt, data)
    return obj


def _format_1(obj, rfmt, **kargs):
    return rfmt.format(obj, **kargs)


def _format_c(obj, rfmt, **kargs):
    return rfmt.format(obj, **kargs).translate(ctrl_tr)


def _format_ins(mnemonic, op_str, **kargs):
    return ''.join((mnemonic.ljust(8), op_str))


# https://sourceware.org/gdb/current/onlinedocs/gdb/Memory.html
# https://sourceware.org/gdb/current/onlinedocs/gdb/Output-Formats.html#Output-Formats
# https://blog.mattjustice.com/2018/08/24/gdb-for-windbg-users/
# invalid utf16: string s = "a\ud800b";
def examine(mem, fmt, sz, endianess, cols=4, sep='  '):
    ''' Examine a piece of memory <mem> in a similar but exactly
        way that the GNU Debugger GDB does.

        Assume the following bytes to be examined:

        >>> b1 = bytes.fromhex('04fdffbe21000000')

        The left lower-index side of the bytes are interpreted as
        low addresses.

        When you see the memory as a sequence of bytes this
        is not important:
        >>> examine(b1, fmt='x', sz=1, endianess='>')
        04  fd  ff  be
        21  00  00  00

        In the example we saw the memory as bytes (sz=1) in hexadecimal
        notation (fmt='x').

        But when you see it as elements of more than one byte it is
        where the endianess plays a role and which byte is less or
        more significant is important.

        Little endian (left/lower addresses are less significant;
        "bytes are swapped"):
        >>> examine(b1, fmt='x', sz=4, endianess='<')
        befffd04  00000021

        Big endian (left/lower addresses are more significant;
        "bytes are not swapped"):
        >>> examine(b1, fmt='x', sz=4, endianess='>')
        04fdffbe  21000000

        Big endian is equivalent to do slicing from the input bytes:
        >>> b1[0:4].hex(), b1[4:8].hex()
        ('04fdffbe', '21000000')

        Decimal (signed (d) and unsigned (u)) interpretations:

        >>> examine(b1, fmt='d', sz=4, endianess='<')
        -1090519804  33

        >>> examine(b1, fmt='u', sz=4, endianess='<')
        3204447492  33

        Octal (o) and binary (b) interpretations are also available.
        Them differs a little from GDB's output: we always pad the
        numbers' representations to complete the given size (4 bytes
        in the next example):

        >>> examine(b1, fmt='o', sz=4, endianess='<')
        027677776404  000000000041

        >>> examine(b1, fmt='b', sz=4, endianess='<')
        10111110111111111111110100000100  00000000000000000000000000100001

        Note: GDB uses 't' for binary.

        A raw (r) view also exists and it is equivalent to do slicing
        (endianess here is ignore and forced to be 'big endian'.

        This differs from GDB where 'raw' means 'do not pretty print'.
        Not applicable to us.

        >>> examine(b1, fmt='r', sz=4, endianess='<')
        b'\x04\xfd\xff\xbe'  b'!\x00\x00\x00'

        When the (c)har format is used, the interpretation of <sz>
        changes: not only specifies how much bytes each character
        will consume but also which encoding to use to decode it.

            sz==1 reads 1 byte and decodes it as utf-8
            sz==2 reads 2 bytes and decode them as utf-16
            sz==4 reads 4 bytes and decode them as utf-32

        Sizes of 8 are not supported.

        Note that utf-8 and utf-16 are *variable size* decoders:
        a single character may require 1 or more bytes to be decoded.

        However xview will *not* read a variable amount of bytes;
        the specified size will be honored.

        GDB does something weird in this case: it reads the same amount
        of bytes than xview but then it sees the read number module 256
        and print it as a char and an octal.

        We believe that this is less usable. Instead xview follows
        more the GDB approach of the 's' format and tries to show
        the input as strings.

        The following shows the input as two characters (c) of
        4 bytes each one in utf-32:

        >>> examine(b1, fmt='c', sz=4, endianess='<')
        �  !

        Note that endianess plays a role here too:

        >>> examine(b1, fmt='c', sz=2, endianess='<')
        ﴄ  뻿  ! <...>

        >>> examine(b1, fmt='c', sz=2, endianess='>')
        ӽ  ﾾ  ℀  <...>

        Float point interpretation is supported only for 4 and
        8 bytes sizes.

        >>> examine(b1, fmt='f', sz=4, endianess='<')
        -4.999772e-01  4.624285e-44

        >>> examine(b1, fmt='f', sz=8, endianess='<')
        7.160907e-313

        >>> examine(b1, fmt='f', sz=2, endianess='<')
        Traceback<...>
        ValueError: Format (f)loat can work only with 4 and 8 sizes but received '2'

        >>> from capstone import *
        >>> examine(b1, cols=1, fmt='i', sz=(CS_ARCH_X86, CS_MODE_64), endianess='<')
        add     al, 0xfd
        .byte   0xff
        mov     esi, 0x21
        '''
    ex = Ex(fmt, sz, endianess)
    line_fmt = '{0:%i/%s}' % (cols, sep)
    print(
        '\n'.join(
            out
            for _, out in Formatter(line_fmt, ex)._lines(mem, start_addr=0)
        )
    )


def idisplay(spec, mem):
    '''
        >>> b1 = bytes.fromhex('255044462d312e320d25e2e3cfd30d0a323234372030206f626a0d3c3c200d2f4c696e656172697a65642031200d')

        'db': display lines of 16 bytes from <mem> showing the address,
              then the bytes in hexadecimal and then the same bytes
              in ASCII. If the byte is not printable, a period is used.

        >>> display('db', b1)
        00000000  25 50 44 46 2d 31 2e 32-0d 25 e2 e3 cf d3 0d 0a  |%PDF-1.2.%......|
        00000010  32 32 34 37 20 30 20 6f-62 6a 0d 3c 3c 20 0d 2f  |2247 0 obj.<< ./|
        00000020  4c 69 6e 65 61 72 69 7a-65 64 20 31 20 0d        |Linearized 1 .  |

        'dc': display lines of 8 words (4 bytes each) from <mem> showing
              the address then the 8 words in hexadecimal and then the
              same bytes in ASCII. If the byte is not printable, a period
              is used.

        >>> display('db', b1)
        00000000  25504446 2d312e32 0d25e2e3 cfd30d0a  |%PDF-1.2.%......|
        00000010  32323437 2030206f 626a0d3c 3c200d2f  |2247 0 obj.<< ./|
        00000020  4c696e65 6172697a 65642031 200d      |Linearized 1 .  |

        'dd': display lines of 4 words (4 bytes each) from <mem> like in 'dc'
              but without the ASCII representation.

        >>> display('db', b1)
        00000000  25504446 2d312e32 0d25e2e3 cfd30d0a
        00000010  32323437 2030206f 626a0d3c 3c200d2f
        00000020  4c696e65 6172697a 65642031 200d

        'dD': display lines of 4 double precision float (8 bytes each)
              from <mem>.

        >>> display('dD', b1)
        00000000
        00000020

        'df': like 'dD' but display simple precision floats (4 bytes each)

        >>> display('dD', b1)
        00000000
        00000010
        00000020

        'dq': display lines of 2 quads (8 bytes each) from <mem>

        >>> display('dq', b1)
        00000000
        00000010
        00000020

        References:
        https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memor
        '''

    if spec == 'db':
        line_fmt = '{addr:08x}  {0:8/ /23}-{0:8/ /23}  |{1:16/}|'
        exs = [
            Ex(fmt='x', sz=1, endianess='='),
            Ex(fmt='c', sz=1, endianess='=')
        ]
    elif spec == 'dc':
        line_fmt = '{addr:08x}  {0:4/ /19}  |{1:16/}|'
        exs = [
            Ex(fmt='x', sz=4, endianess='='),
            Ex(fmt='c', sz=1, endianess='=')
        ]
    elif spec == 'dd':
        line_fmt = '{addr:08x}  {0:4/ /19}'
        exs = [Ex(fmt='x', sz=4, endianess='=')]
    elif spec == 'dD':
        line_fmt = '{addr:08x}  {0:4/ }'
        exs = [Ex(fmt='f', sz=8, endianess='=')]
    elif spec == 'df':
        line_fmt = '{addr:08x}  {0:4/ }'
        exs = [Ex(fmt='f', sz=4, endianess='=')]
    elif spec == 'dq':
        line_fmt = '{addr:08x}  {0:2/ }'
        exs = [Ex(fmt='x', sz=8, endianess='=')]
    else:
        raise ValueError("Spec '%s' not supported." % spec)

    yield from Formatter(line_fmt, *exs)._lines(mem, 0)


def display(spec, mem):
    print('\n'.join(out for _, out in idisplay(spec, mem)))
