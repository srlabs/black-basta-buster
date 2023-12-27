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
from collections import deque
from itertools import islice
import logging
from pathlib import Path
import sys

try:
    from hexdump import hexdump
except ModuleNotFoundError:
    import logging
    log = logging.getLogger(__name__)
    log.warning("hexdump module not found. Try pip install hexdump")
    def hexdump(*args, **kwargs):
        log.error("Cannot find the hexdump module. Try pip install hexdump")

from decryptblocks import detect_magic_size, make_int, make_int_or_percent, Percent
from ranges import ranges_for_file

log = logging.getLogger(__name__)


def extract_block(fd, offset, size=64):
    #log.debug("Reading %r at %r for %r ", fd, offset, size)
    fd.seek(offset)
    block = fd.read(size)
    log.debug("Read %i bytes at %r for %r:\n%s", len(block), offset, size, hexdump(block, result="return"))
    return block

def make_int_or_auto(s):
    if s.strip() == "auto":
        return "auto"
    else:
        return make_int(s)




### Entropy taken from https://stackoverflow.com/a/37890790/2015768
import math
from collections import Counter

def eta(data, unit='natural'):
    base = {
        'shannon' : 2.,
        'natural' : math.exp(1),
        'hartley' : 10.
    }

    if len(data) <= 1:
        return 0

    counts = Counter()

    for d in data:
        counts[d] += 1

    ent = 0

    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.:
            ent -= p * math.log(p, base[unit])

    return ent


BLOCKSIZE = 64
NULLBLOCK = b'\x00' * BLOCKSIZE

def auto_detect_key_block(f, fsize=None, lower_limit=None, upper_limit=None):
    if fsize is None:
        fsize = detect_magic_size(f)

    block = None

    if lower_limit is None:
        # we skip the first few block, unless explicitly requested
        lower_limit = next(islice(ranges_for_file(f, fsize), 5, 6))[0]

    if upper_limit is None:
        upper_limit = fsize

    CONFIDENCE = 5
    with open(f, "rb") as fd:
        confidence_blocks = deque(maxlen=CONFIDENCE)
        for n, (offset, length) in enumerate(filter(lambda offset_len: lower_limit <= offset_len[0] < upper_limit, ranges_for_file(f, fsize))):
            t = True
            for i in (-2, -1, 1, 2):
                b = extract_block(fd, offset-i*BLOCKSIZE)
                t &= b == NULLBLOCK
                log.debug("T is now: %s", t)
                #if not t:
                #    raise
            if t:
                log.debug("Confidence: %s", confidence_blocks)
                b = extract_block(fd, offset)
                if b == NULLBLOCK:
                    log.debug("B is null")
                else:
                    log.debug("Adding confidence at %d %r", offset, b)
                    confidence_blocks.append((offset, b))
                    if len(confidence_blocks) == CONFIDENCE:
                        if all((b == x[1] for x in confidence_blocks)):
                            log.info ("Found blocks: %r", confidence_blocks)
                            block = b # Urhgs. This is spaghetti control flow. Sorry.
                            break
                        else:
                            log.info("Not all blocks are equal to %r: %s", b, confidence_blocks)
                            raise
                    else:
                        log.info("only %d blocks: %s", len(confidence_blocks), confidence_blocks)
        else:
            print ("non found")
            raise


    return block

def main():
    argparser = argparse.ArgumentParser(description="Extracts a 64 byte long chunk out of a file. This can be useful for taking that block as an encryption key.")
    argparser.add_argument("--hexdump", action="store_true")
    argparser.add_argument("--dry", action="store_true",
        help="Do not write anything")
    argparser.add_argument("--size", type=int, default=0x40, help="Chunk size")
    argparser.add_argument("--start-at", type=make_int_or_percent, default=None, help="Start the automatic determination from here, only")
    argparser.add_argument("--output", type=Path, help="Write the chunk to a file rather than stdout")
    argparser.add_argument("file", type=Path, help="The file to cut a chunk out of")
    argparser.add_argument("offset", type=make_int_or_auto, help="Position to cut the chunk out of the file, or 'auto' to detect encrypted zero bytes")

    args = argparser.parse_args()
    offset = args.offset
    f = args.file
    size = args.size
    start_at = args.start_at

    logging.basicConfig(level=logging.INFO)

    fsize = detect_magic_size(f)
    if isinstance(start_at, Percent):
        pct = start_at
        start_at = pct/100 * fsize
        log.info("Starting at %d%% of %d: %d", pct, fsize, start_at)


    if offset == "auto":
        block = auto_detect_key_block(f, lower_limit=start_at)
    else:
        with open(args.file, 'br') as fd:
            block = extract_block(fd, args.offset, size=size)

    if args.hexdump:
        print(hexdump(block, result='return'), file=sys.stderr)

    if args.output:
        f = open(args.output, 'bx')
    else:
        f = sys.stdout.buffer

    if not args.dry:
        log.debug("Writing %i bytes to %r", len(block), f)
        f.write(block)

if __name__ == "__main__":
    main()
