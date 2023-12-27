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
from hexdump import hexdump
from pathlib import Path

from extractblock import make_int
from decryptblocks import xor_blocks

def main():
    argparser = argparse.ArgumentParser(description="XOR a single chunk in a file at a given offset")
    argparser.add_argument("--hexdump", action="store_true")
    argparser.add_argument("--output", type=Path)
    argparser.add_argument("file", type=Path)
    argparser.add_argument("nullblock", type=Path)
    argparser.add_argument("offset", type=make_int)

    args = argparser.parse_args()

    args.hexdump
    f = args.file
    null = args.nullblock
    offset = args.offset
    output = args.output

    null_block = null.open("rb").read()

    print ("Null:")
    hexdump(null_block)

    with f.open("rb") as fd:
        fd.seek(offset)
        b = fd.read(len(null_block))
        r = xor_blocks(b, null_block)

    print ("Original:")
    hexdump(b)

    print ("Result:")
    hexdump(r)

    if output:
        output.open("bx").write(r)
    return r

if __name__ == "__main__":
    main()
