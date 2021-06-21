import sys, codecs
from functools import partial
from struct import unpack
from itertools import islice
import string
from more_itertools import peekable, take, unique_justseen

try:
    import capstone
    is_capstone_available = True
except ImportError:
    is_capstone_available = False
'''
>>> from xview import Ex, Formatter, display, hexdump

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
ctrl_tr[65533] = u'.'


class Ex:
    def __init__(self, fmt, sz, endianess, extra_kargs=None):
        fmt, sz, endianess = self._validate_params(
            fmt, sz, endianess, extra_kargs
        )
        self._fmt = fmt

        self._unpacker, self._sz = self._build_unpacker(fmt, sz, endianess)
        self._formatter = self._build_formatter(fmt, sz, endianess)

    def _are_we_examining_instructions(self):
        return self._fmt == 'i'

    def _validate_params(self, fmt, sz, endianess, extra_kargs):
        if fmt != 'i' and sz not in (1, 2, 4, 8):
            raise ValueError(
                "Size '%s' unknown. Expected 1, 2, 4, or 8 bytes." % sz
            )

        if fmt == 'i':
            try:
                if extra_kargs is None:
                    extra_kargs = {}  # make this to uniform the errors
                arch, mode = extra_kargs['arch'], extra_kargs['mode']
            except KeyError as err:
                raise KeyError(
                    "You need to pass the architecture and mode for Capstone: %s"
                    % str(err)
                )

            if not is_capstone_available:
                raise ValueError("Capstone engine is not available.")

            arch = getattr(capstone, 'CS_ARCH_' + str(arch).upper())
            mode = getattr(capstone, 'CS_MODE_' + str(mode).upper())

            # nasty trick to encode "the size".
            sz = (arch, mode)

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

        return fmt, sz, endianess

    def _build_unpacker(self, fmt, sz, endianess):
        if self._are_we_examining_instructions():
            md = capstone.Cs(*sz)
            md.skipdata = True

            unpack = partial(md.disasm_lite, offset=0)
            return unpack, 0

        # format for struct.unpack
        sfmt = {'>': '>', '<': '<', '=': '='}[endianess]

        # struct.unpack opcode of the object
        # https://docs.python.org/3.8/library/struct.html#format-characters
        op = {
            1: 'B',
            2: 'H',
            4: 'I',
            8: 'Q',
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

            >>> print_iter2(Ex(fmt='c', sz=1, endianess='<').examine_iter(b1))
            0  .
            1  .
            2  .
            3  .
            4  !
            5  .
            6  .
            7  .

            >>> print_iter2(Ex(fmt='c', sz=4, endianess='<').examine_iter(b1))
            0  .
            4  !

            Note that endianess plays a role here too:

            >>> print_iter2(Ex(fmt='c', sz=2, endianess='<').examine_iter(b1))
            0  ﴄ
            2  뻿
            4  !
            6  .

            >>> print_iter2(Ex(fmt='c', sz=2, endianess='>').examine_iter(b1))
            0  ӽ
            2  ﾾ
            4  ℀
            6  .

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
            >>> cnf = {'arch': 'x86', 'mode': 64}
            >>> print_iter2(Ex(fmt='i', sz=0, endianess='<', extra_kargs=cnf).examine_iter(b1))
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
    def __init__(
        self, line_fmt, compress_marker, *exs_in_args, **exs_in_kwargs
    ):
        self._line_fmt = line_fmt
        self._examiner_by_key = {
            str(ix): ex
            for ix, ex in enumerate(exs_in_args)
        }
        self._examiner_by_key.update(exs_in_kwargs)
        self._formatter = string.Formatter()
        self._compress_marker = compress_marker

    def _line_template(self, mem, start_addr, ruler):
        ''' Returns a list of tuples (<literal_text>, <examiner it>,
            <length>, <separator>, <width>, <fill>).

            Each tuple describes what literal text forms the line before the
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

            The <self._line_fmt> uses 2 examiners "0" and "1". There
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

            If the line format has the special "{addr}" specifier,
            this method will yield an <examiner_it> which will *not*
            be an interator but a tuple (<format_spec>, <conversion>).

            The <format_spec> and <conversion> are extracted from the
            format "{addr}" following the Python Formatter rules:

                {addr}: equivalent to "%s"
                {addr:x}: replace by the hexadecimal notation of addr
                {addr:08x}: replace by the hexadecimal notation of addr, padded
                            with zeros to complete a number of 8 digits.
                {addr!s}: convert the addr to a string.

            See lines() for more info.
        '''
        results = []
        f = self._formatter
        line_fmt = self._line_fmt

        # we support integers because it is natural to use them to refer
        # the 3rd examiner like in {2} but Python will not return an int
        # but a string for '2'. To simplify the comparisons later we
        # normalize it to str.
        if isinstance(ruler, int):
            ruler = str(ruler)

        RULER = None
        initialized = {}
        for literal_text, field_name, format_spec, conversion in f.parse(
            line_fmt
        ):
            if field_name is not None:
                if field_name == '':
                    raise ValueError("Empty field names are not supported")

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

                    # Pick the first examiner_it as the ruler if not one was
                    # specified, otherwise pick the named one.
                    if RULER is None and (
                        ruler is None or field_name == ruler
                    ):
                        RULER = it

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

        if RULER is None:
            raise ValueError(
                f"The examiner '{ruler}' is not in the line format and cannot be used as the ruler."
            )

        # TODO check initialized against self._examiner_by_key
        return results, initialized, RULER

    def lines(
        self,
        mem,
        start_addr,
        compress=False,
        ret_addresses=False,
        ruler=None
    ):
        ''' Yields formatted lines from the examined <mem>.
            See _line_template.

            >>> line_fmt = "line: {0:4/ /11}  {0:4/ /11} | {1:4//4} {1:4//4}"
            >>> ex0 = Ex(fmt='x', sz=1, endianess='>')
            >>> ex1 = Ex(fmt='x', sz=1, endianess='>')

            >>> b1 = bytes.fromhex('04fdffbe2100000041412121')
            >>> f = Formatter(line_fmt, None, ex0, ex1)

            >>> print_iter1(f.lines(b1, start_addr=0))
            line: 04 fd ff be  21 00 00 00 | 04fdffbe 21000000
            line: 41 41 21 21              | 41412121

            If the special {addr} is used, it will be replaced
            by the address of the current line.

            The {addr} is subject to rules of string formatting of Python
            and *not* to the rules of xview.Formatter (so {addr:4/ /} has no
            meaning and it is invalid).

            >>> line_fmt = "{addr:08x} {0:4/ /11}  {0:4/ /11} | {1:4//4} {1:4//4}"
            >>> f = Formatter(line_fmt, None, ex0, ex1)

            >>> print_iter1(f.lines(b1, start_addr=0))
            00000000 04 fd ff be  21 00 00 00 | 04fdffbe 21000000
            00000008 41 41 21 21              | 41412121

            Negative starting addresses are supported (but may look uggly)

            >>> print_iter1(f.lines(b1, start_addr=-4))
            -0000004 04 fd ff be  21 00 00 00 | 04fdffbe 21000000
            00000004 41 41 21 21              | 41412121

            If <compress> is True, repeated lines are suppressed and replaced
            by <self._compress_marker>

            >>> b2 = bytes.fromhex('aabbccdd00112233aabbccdd00112233aabbccdd00112233ffff')
            >>> print_iter1(f.lines(b2, start_addr=0, compress=True))
            00000000 aa bb cc dd  00 11 22 33 | aabbccdd 00112233
            None
            None
            00000018 ff ff                    | ffff

            And works even if the repeated line is the last one.

            >>> b3 = bytes.fromhex('aabbccdd00112233aabbccdd00112233')
            >>> print_iter1(f.lines(b3, start_addr=0, compress=True))
            00000000 aa bb cc dd  00 11 22 33 | aabbccdd 00112233
            None

            Instead of yielding only the lines, the method can yield tuples
            with the address of the line and the line itself.

            >>> print_iter2(f.lines(b1, start_addr=0, ret_addresses=True))
            0  00000000 04 fd ff be  21 00 00 00 | 04fdffbe 21000000
            8  00000008 41 41 21 21              | 41412121

            The line addresses (called the ruler) are taken from the first
            examiner but this can be changed. In theory this should not have
            any noticeable change.

            >>> print_iter1(f.lines(b3, start_addr=0, ruler=1))
            00000000 aa bb cc dd  00 11 22 33 | aabbccdd 00112233
            00000008 aa bb cc dd  00 11 22 33 | aabbccdd 00112233

            >>> print_iter1(f.lines(b'', start_addr=0, ruler=1)) # nothing to print

            But the ruler is important because once the ruler iterator gets
            exhausted, the lines() iterator will finish regardless if the rest
            of the examiners were exhausted or not.

            If one examiner gets exhausted and *after* that the ruler does not
            get exhausted, an exception will be raised.

            >>> ex_fast = Ex(fmt='x', sz=4, endianess='>')
            >>> f = Formatter(line_fmt, None, ex0, ex_fast)

            >>> print_iter1(f.lines(b3, start_addr=0))
            <...>
            ValueError: The 1 examiners got exhausted earlier before the ruler: ['1']

            Using the fastest examiner as the ruler fixes that but it is *very*
            likely that the examiners get out of sync (it is very likely that
            you are having a bug).

            In the following example the left side shows 8 bytes but the right
            side shows 16!

            >>> print_iter1(f.lines(b3, start_addr=0, ruler=1))
            00000000 aa bb cc dd  00 11 22 33 | aabbccdd00112233aabbccdd00112233

            Using a non existent ruler will fail. The ruler is always required.
            If you don't want to have the addresses in the output, just don't
            put '{addr}'

            >>> f = Formatter(line_fmt, None, ex0, ex1)
            >>> print_iter1(f.lines(b3, start_addr=0, ruler="foobar"))
            <...>
            ValueError: The examiner 'foobar' is not in the line format and cannot be used as the ruler.

        '''
        line = []
        ruler = str(ruler) if ruler else ruler  # stringnify it unless is None
        template, initialized, RULER = self._line_template(
            mem, start_addr, ruler
        )
        exhausted = set()
        line_addr = None
        cur_data = []
        last_data = []
        while True:
            try:
                line_addr = RULER.peek()[0]
            except StopIteration:
                assert not line
                break

            if exhausted:
                keys = []
                for ex in exhausted:
                    for k, v in initialized.items():
                        if v == ex:
                            keys.append(k)
                keys = list(sorted(keys))
                raise ValueError(
                    f"The {len(keys)} examiners got exhausted earlier before the ruler: {keys}"
                )

            for literal_text, examiner_it, length, separator, width, fill in template:
                if literal_text is not None:
                    line.append(literal_text)

                # TODO hardcoded
                if isinstance(examiner_it, str):
                    fmt = examiner_it
                    line.append(fmt.format(line_addr))

                elif examiner_it is not None:
                    # TODO addr is dropped
                    addr_out = take(length, examiner_it)
                    if len(addr_out) < length:
                        exhausted.add(examiner_it)
                    out = separator.join(out for _, out in addr_out)
                    if width:
                        out = out.ljust(width, fill)
                    line.append(out)
                    cur_data.append(out)

            if line:
                if compress and cur_data == last_data:
                    out = self._compress_marker
                else:
                    out = ''.join(line)

                if ret_addresses:
                    yield (line_addr, out)
                else:
                    yield out

                line = []
                last_data = cur_data
                cur_data = []

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


def idisplay(
    spec, mem, endianess='=', start_addr=0, compress=False, extra_kargs={}
):
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
              Note: the endianess by default is the endianess if the
              host/machine but it can be changed to big endian (>) or
              little endian (<).
              Note: if the input is not multiple of 4, the last bytes
              will not be displayed in the hexadecimal part because
              they don't form a 4-bytes word, however they will be
              displayed in the ASCII part.

        >>> display('dc', b1)
        00000000  46445025 322e312d e3e2250d 0a0dd3cf  |%PDF-1.2.%......|
        00000010  37343232 6f203020 3c0d6a62 2f0d203c  |2247 0 obj.<< ./|
        00000020  656e694c 7a697261 31206465           |Linearized 1 .  |

        >>> display('dc', b1, endianess='>')
        00000000  25504446 2d312e32 0d25e2e3 cfd30d0a  |%PDF-1.2.%......|
        00000010  32323437 2030206f 626a0d3c 3c200d2f  |2247 0 obj.<< ./|
        00000020  4c696e65 6172697a 65642031           |Linearized 1 .  |

        'dd': display lines of 4 words (4 bytes each) from <mem> like in 'dc'
              but without the ASCII representation.

        >>> display('dd', b1)
        00000000  46445025 322e312d e3e2250d 0a0dd3cf
        00000010  37343232 6f203020 3c0d6a62 2f0d203c
        00000020  656e694c 7a697261 31206465

        'dD': display lines of 4 double precision float (8 bytes each)
              from <mem>.

        >>> display('dD', b1)
        00000000  5.599436e-67  3.031161e-260  1.917431e+227  4.797675e-82
        00000020  4.619119e+281

        'df': like 'dD' but display simple precision floats (4 bytes each)

        >>> display('df', b1)
        00000000  1.256404e+04  1.013931e-08  -8.343268e+21  6.828740e-33
        00000010  1.074052e-05  4.957578e+28  8.631321e-03  1.283533e-10
        00000020  7.036660e+22  3.030313e+35  2.334013e-09

        'dq': display lines of 2 quads (8 bytes each) from <mem>

        >>> display('dq', b1)
        00000000  322e312d46445025  0a0dd3cfe3e2250d
        00000010  6f20302037343232  2f0d203c3c0d6a62
        00000020  7a697261656e694c

        'uu': disassembly the memory into instructions. Display as raw bytes
              the pieces of memory that couldn't be disassembled.

        >>> display('uu', b1)
        00000000  and     eax, 0x2d464450
        00000005  xor     dword ptr [rsi], ebp
        00000007  xor     cl, byte ptr [rip - 0x301c1ddb]
        0000000d  ror     dword ptr [rip + 0x3432320a], cl
        00000013  .byte   0x37
        00000014  and     byte ptr [rax], dh
        00000016  and     byte ptr [rdi + 0x62], ch
        00000019  push    0xd
        0000001b  cmp     al, 0x3c
        0000001d  and     byte ptr [rip + 0x6e694c2f], cl
        00000023  .byte   0x65
        00000024  .byte   0x61
        00000025  jb      0x90
        00000027  jp      0x8e
        00000029  and     byte ptr fs:[rcx], dh
        0000002c  .byte   0x20
        0000002d  .byte   0x0d

        References:
        https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/d--da--db--dc--dd--dd--df--dp--dq--du--dw--dw--dyb--dyd--display-memor
        https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/u--unassemble-
        '''

    if spec == 'db':
        line_fmt = '{addr:08x}  {0:8/ /23}-{0:8/ /23}  |{1:16//16}|'
        exs = [
            Ex(fmt='x', sz=1, endianess=endianess),
            Ex(fmt='c', sz=1, endianess=endianess)
        ]
    elif spec == 'dc':
        line_fmt = '{addr:08x}  {0:4/ /35}  |{1:16//16}|'
        exs = [
            Ex(fmt='x', sz=4, endianess=endianess),
            Ex(fmt='c', sz=1, endianess=endianess)
        ]
    elif spec == 'dd':
        line_fmt = '{addr:08x}  {0:4/ /19}'
        exs = [Ex(fmt='x', sz=4, endianess=endianess)]
    elif spec == 'dD':
        line_fmt = '{addr:08x}  {0:4/  }'
        exs = [Ex(fmt='f', sz=8, endianess=endianess)]
    elif spec == 'df':
        line_fmt = '{addr:08x}  {0:4/  }'
        exs = [Ex(fmt='f', sz=4, endianess=endianess)]
    elif spec == 'dq':
        line_fmt = '{addr:08x}  {0:2/  }'
        exs = [Ex(fmt='x', sz=8, endianess=endianess)]
    elif spec == 'uu':
        line_fmt = '{addr:08x}  {0:1}'

        exs = [
            Ex(
                fmt='i',
                sz=0,
                endianess=endianess,
                extra_kargs={
                    'arch': extra_kargs.get('arch', 'x86'),
                    'mode': extra_kargs.get('mode', 64)
                }
            )
        ]
    else:
        raise ValueError("Spec '%s' not supported." % spec)

    it = Formatter(line_fmt, '*', *exs).lines(mem, start_addr, compress)
    if compress:
        yield from unique_justseen(it)
    else:
        yield from it


def display(
    spec, mem, endianess='=', start_addr=0, compress=False, extra_kargs={}
):
    print(
        '\n'.join(
            out for out in
            idisplay(spec, mem, endianess, start_addr, compress, extra_kargs)
        )
    )


def ihexdump(mem, start_addr=0, compress=False):
    line_fmt = '{addr:08x}  {0:8/ /23}  {0:8/ /23}  |{1:16//16}|'
    exs = [Ex(fmt='x', sz=1, endianess='='), Ex(fmt='c', sz=1, endianess='=')]

    it = Formatter(line_fmt, '*', *exs).lines(mem, start_addr, compress)
    if compress:
        yield from unique_justseen(it)
    else:
        yield from it


def hexdump(mem, start_addr=0, compress=False):
    '''
        Display the bytes of <mem> in 16-bytes lines showing
        them twice: one as hexadecimal numbers and the other
        as ASCII characters.

        If a ASCII character is not printable, a period is used.

        At the begin of each line the address of the line is shown
        in hexadecimal.

        >>> b1 = bytes.fromhex('255044462d312e320d25e2e3cfd30d0a323234372030206f626a0d3c3c200d2f4c696e656172697a65642031200d')
        >>> hexdump(b1)
        00000000  25 50 44 46 2d 31 2e 32  0d 25 e2 e3 cf d3 0d 0a  |%PDF-1.2.%......|
        00000010  32 32 34 37 20 30 20 6f  62 6a 0d 3c 3c 20 0d 2f  |2247 0 obj.<< ./|
        00000020  4c 69 6e 65 61 72 69 7a  65 64 20 31 20 0d        |Linearized 1 .  |

        The starting address can be changed even it can be negative:

        >>> hexdump(b1, start_addr=-0x10)
        -0000010  25 50 44 46 2d 31 2e 32  0d 25 e2 e3 cf d3 0d 0a  |%PDF-1.2.%......|
        00000000  32 32 34 37 20 30 20 6f  62 6a 0d 3c 3c 20 0d 2f  |2247 0 obj.<< ./|
        00000010  4c 69 6e 65 61 72 69 7a  65 64 20 31 20 0d        |Linearized 1 .  |

        Consecutive repeating lines can be suppressed:

        >>> b2 = bytes.fromhex('aa' + 'ff' * 128 + 'bb')
        >>> hexdump(b2, compress=True)
        00000000  aa ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
        00000010  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
        *
        00000080  ff bb                                             |..              |
    '''
    print('\n'.join(out for out in ihexdump(mem, start_addr, compress)))
