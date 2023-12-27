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
import logging
import posix
from pathlib import Path
import sys

try:
    from hexdump import hexdump
except ModuleNotFoundError:
    import logging
    log = logging.getLogger(__name__)
    log.warning("Could not find hexdump module. Try pip install hexdump")
    def hexdump(*args):
        log.error("Could not find hexdump module. Try pip install hexdump")

from decryptblocks import make_int
from ranges import ranges_for_file_size

log = logging.getLogger(__name__)



BLOCKSIZE = 64

def main():
    argparser = argparse.ArgumentParser(
        description="""Finds a (small) chunk in a (large) file and prints the positions of the chunk's occurence.
        This can be useful to determine the first occurence of a block in a file,
        e.g. by running with a pipe: findblocks | head | less
        This first occurence may then be useful for starting a decryption at a certain offset.
        """
    )
    argparser.add_argument("--hexdump", action="store_true")
    argparser.add_argument("--find-first", action="store_true")
    argparser.add_argument("--start-at", type=make_int, default=0)
    argparser.add_argument("--end-at", type=make_int, default=-1)
    argparser.add_argument("file", type=Path)
    argparser.add_argument("block", type=Path, help="The chunk to be found in a file")

    args = argparser.parse_args()
    needle_f = args.block
    f = args.file
    start_at = args.start_at
    end_at = args.end_at

    logging.basicConfig(level=logging.INFO)

    needle = open(needle_f, "br").read()
    assert len(needle) == BLOCKSIZE
    log.info("Trying to find\n%s\nin %s (from %d to %d)",
        hexdump(needle, result="return"), f, start_at, end_at)

    fsize = f.stat().st_size

    lower_limit = start_at
    if end_at == -1:
        end_at = fsize
    upper_limit = end_at

    with open(f, "br") as fd:
        for i, (offset, length) in enumerate(filter(lambda offset_len: lower_limit < offset_len[0] < upper_limit, ranges_for_file_size(fsize))):
            n = BLOCKSIZE
            # Somehow, pread does not exist?! O_o  read_bytes = posix.pread(pread, fd, n)
            fd.seek(offset)
            read_bytes = fd.read(length)
            assert len(read_bytes) == n

            if read_bytes == needle:
                log.info("Found needle at %d: %d", i, offset)
                print ("%d" % offset)

if __name__ == "__main__":
    main()
