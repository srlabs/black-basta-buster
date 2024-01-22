#!/usr/bin/env python3
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
import argparse
import datetime
import logging
try:
    from mmap import MAP_SHARED, MAP_PRIVATE, MADV_SEQUENTIAL, MADV_DONTNEED
except ImportError:
    # Windows does not have these constants
    MAP_SHARED, MAP_PRIVATE, MADV_SEQUENTIAL, MADV_DONTNEED = None, None, None, None
from mmap import mmap, PAGESIZE
from pathlib import Path
import sys

from magic import detect_magic_size, backup_magic_footer
from ranges import ranges_for_file

log = logging.getLogger(__name__)


def make_int(i):
    if i.startswith("0x"):
        try:
            r = int(i[len("0x"):], 16)
        except:
            raise
    else:
        try:
            r = int(i)
        except:
            raise

    return r

class Percent(int):
    pass

def make_int_or_percent(i):
    if i.endswith("%"):
        return Percent(i[:-1])
    else:
        return make_int(i)


def xor_blocks(var, key, byteorder=sys.byteorder):
    key, var = key[:len(var)], var[:len(key)]
    int_var = int.from_bytes(var, byteorder)
    int_key = int.from_bytes(key, byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), byteorder)


def write_block(fd, offset, block):
    fd.seek(offset)
    r= fd.write(block)
    return r




GB = 1024*1024*1024
BLOCK_SIZE = 64

def main():
    argparser = argparse.ArgumentParser("Decrypts a file with a key by XORing the key onto well-known locations within a file")
    argparser.add_argument("--hexdump", action="store_true")
    argparser.add_argument("--dry", action="store_true",
        help="Do not write anything")
    argparser.add_argument("--output", type=Path)
    argparser.add_argument("--assume-size", type=make_int, default=0)
    argparser.add_argument("--start-at", type=make_int, default=0)
    argparser.add_argument("file", type=Path)
    argparser.add_argument("nullblock", type=Path)

    args = argparser.parse_args()

    assume_size = args.assume_size
    is_hexdump = args.hexdump
    is_dry = args.dry
    f = args.file
    keyblock = args.nullblock
    start_at = args.start_at

    logging.basicConfig(level=logging.WARNING)

    if is_hexdump:
        from hexdump import hexdump


    with open(args.nullblock, 'br') as fd:
        null = fd.read()
        assert len(null) == 64
        BLOCK_SIZE = len(null)

    if not is_dry:
        backup_magic_footer(f)

    fsize = f.stat().st_size if not assume_size else assume_size

    return decrypt_file(f, keyblock=null, fsize=fsize, is_dry=is_dry, lower_limit=start_at)

def decrypt_file(f, keyblock, fsize=None, is_dry=True, lower_limit=None, upper_limit=None):
    fsize = f.stat().st_size if fsize is None else fsize
    f_mode = "br+" if not is_dry else "br"
    if lower_limit is None:
        lower_limit = 0
    if upper_limit is None:
        upper_limit = fsize
    assert lower_limit < upper_limit

    if MAP_SHARED is None:
        mmap_args = {}
    else:
        mmap_args = { flags: MAP_SHARED if not is_dry else MAP_PRIVATE }

    with open(f, f_mode) as fd:
        with mmap(fd.fileno(), 0, **mmap_args) as mm:
            if lower_limit > PAGESIZE:
                mm.madvise(MADV_DONTNEED, 0, lower_limit - (lower_limit % PAGESIZE))
            try:
                mm.madvise(MADV_SEQUENTIAL, lower_limit - (lower_limit % PAGESIZE), upper_limit + (upper_limit % PAGESIZE))
                def advise(t, start, end):
                    return mm.madvise(t, start, end)
            except (OSError, AttributeError):
                log.exception("Cannot mmap")
                def advise(*args, **kwargs):
                    log.info("Cannot mmap")
                    return
            last_time = datetime.datetime.now()
            last_time = last_time.replace(second=(last_time.second-1) % 60)
            last_offset = 0
            for n, (offset, length) in enumerate(filter(lambda offset_len: lower_limit <= offset_len[0] < upper_limit, ranges_for_file(f, fsize)), start=1):
                if (n % (1<<18)) == 0:
                    now = datetime.datetime.now()
                    delta = now - last_time
                    progress_per_second = (offset - last_offset) / delta.total_seconds()
                    remaining_size = (fsize - offset)
                    remaining_seconds = remaining_size / progress_per_second
                    eta = now + datetime.timedelta(seconds=remaining_seconds)
                    log.warning("Looking at %d %d (%d): %05.03f%% %3.2fMB/s %d seconds remaining, ETA: %s", n, offset, fsize, (offset/fsize)*100, progress_per_second/1024/1024, remaining_seconds, eta.isoformat(timespec="minutes"))
                    advise(MADV_DONTNEED, last_offset - (last_offset % PAGESIZE), offset - (offset % PAGESIZE))
                    last_time = datetime.datetime.now()
                    last_offset = offset
                #log.debug("Looking at %d (length %d)", offset, length)
                i = length - BLOCK_SIZE
                assert i >= 0
                last_block = b'\x00' * BLOCK_SIZE

                this_offset = offset
                while this_offset + BLOCK_SIZE <= offset + length:
                    #log.debug(f"this offset: {this_offset} + {BLOCK_SIZE} = {this_offset + BLOCK_SIZE} until {offset + length}")
                    current_block = mm[this_offset:this_offset+BLOCK_SIZE]
                    #log.debug("Current block:\n%s", hexdump(current_block, result="return"))
                    decrypted_block = xor_blocks(current_block, keyblock)
                    #log.debug("Decrypted block at %d:\n%s", this_offset, hexdump(decrypted_block, result="return"))
                    cbc_block = xor_blocks(decrypted_block, last_block)

                    # FIXME: This is a hot if. Is a try/except or a function call cheaper?
                    if not is_dry:
                        mm[this_offset:this_offset+BLOCK_SIZE] = cbc_block

                    last_block = current_block
                    this_offset += BLOCK_SIZE



if __name__ == "__main__":
    main()
