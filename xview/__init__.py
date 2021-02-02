'''Examine memory views/bytes pretty printing it.'''

__version__ = "0.0.5"

_author = 'Di Paola Martin'
_license = 'GNU LGPLv3'
_url = 'https://github.com/bad-address/xview'

_license_disclaimer = r'''Copyright (C) {author} - {url}

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

try:
    from .xview import Ex, Formatter, display, hexdump
except (SystemError, ImportError):
    pass  # this happens when importing from setup.py
