#!/usr/bin/env python3
"Generates the posiitons and lengths of encrypted bytes in a file encrypted by the Black Basta ransomware"
# Copyright 2023 Tobias Mueller <tobias@srlabs.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pathlib import Path
import logging
import sys

from magic import detect_magic_size


log = logging.getLogger(__name__)

GB = 1024*1024*1024

def ranges_for_file_size(fsize):
    blocksize = 64

    if fsize < 5000:
        yield (0, fsize - fsize % blocksize)
        i = fsize
    elif fsize <= 1*GB:
        skip = 128+64
        i = 0
    else:
        yield (0, 5000)
        skip = 6400
        i = 5000

    while i < fsize:
        if not i+blocksize > fsize:
            yield (i, blocksize)
            assert i+blocksize <= fsize, f"i: {i}, bs: {blocksize}, fsize: {fsize}"
        i += skip

def ranges_for_file_generated(path):
    fsize = detect_magic_size(path)
    return ranges_for_file_size(fsize)



def ranges_for_file_real(path):
    "Rather than generating, this function actually walks over an encrypted file of zero-bytes and notices when the zero-bytes change, i.e. when the encryption happened"
    fsize = path.stat().st_size
    with open(path, 'br') as fd:
        SIZE = 8
        null_block = b'\x00' * SIZE
        last = i = 0
        counting_nulls = False

    """ Commenting for Python <3.10 compatibility
        with mmap(fd.fileno(), 0, MAP_PRIVATE) as mm:
            while i <= fsize:
                #block = fd.read(SIZE)
                block = mm[i:i+SIZE]
                #log.debug("loop %i read: %r block== %s countring: %s", i, block, (block == null_block), counting_nulls)
                match ((block == null_block), counting_nulls):
                    case (True, True):
                        last = i
                    case (True, False):
                        yield (last, i-last)
                        counting_nulls = True
                    case (False, True):
                        # Here we have a toggle
                        last = i
                        counting_nulls = False
                    case (False, False):
                        pass

                i += SIZE
"""
    return

    if fsize:
        yield (0, 5056)
        skip = 128
    else:
        raise ValueError("unknown size")


    yield

def ranges_for_file(path, fsize=None):
    #return ranges_for_file_real(path)
    if fsize is None:
        return ranges_for_file_generated(path)
    else:
        return ranges_for_file_size(fsize)


def main():
    p = Path(sys.argv[1])
    for offset, length in ranges_for_file_generated(p):
        print ("%s %d" % (hex(offset), length))

def main_size():
    size = int(sys.argv[1])
    for offset, length in ranges_for_file_size(size):
        print ("%s %d" % (offset, length))

if __name__ =="__main__":
    main()
