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
from binascii import hexlify
from datetime import datetime, timedelta
import logging
from pathlib import Path
import struct
import sys
import time

from decryptblocks import detect_magic_size

log = logging.getLogger(__name__)

SEEK_END = 2
def read_counter(fd):
    fd.seek(-22, SEEK_END)
    counter_bytes = fd.read(8)
    counter = struct.unpack("<Q",counter_bytes)[0]
    log.info("Read counter: %s %s", hexlify(counter_bytes), counter)
    return counter

def set_counter(fd, counter):
    fd.seek(-22, SEEK_END)
    counter_bytes = struct.pack("<Q",counter)
    log.info("Setting counter: %s %s", hexlify(counter_bytes), counter)
    fd.write(counter_bytes)
    return counter_bytes


def main():
    argparser = argparse.ArgumentParser(
        description="""Reads the footer of an encrypted file to determine how much of the file has been encrypted.
        The ransomware leaves a footer in an encrypted file.
        The footer contains a pointer into the file of how far the en- or decryption has come.
        This information can be used to determine how quickly the ransomware can en- or decrypt
        by subsequently reading the footer and measuring how far it has gotten in a certain amount of time.
        The --wait switch implements this behaviour.

        Finally, the pointer can be manipulated to the file's size.
        This can be useful if the en- or decryption is not complete to convince the en- or decrypter about
        the encrypted ranges of the file.
        The --set-to-size switch implements this behaviour.
        """
    )
    argparser.add_argument("--set-to-size", action="store_true", help="Manipulate the pointer into the file to match the file's size")
    argparser.add_argument("--wait", nargs='?', const=30, type=int, help="Continuously Re-read the file after this many seconds")
    argparser.add_argument("file", type=Path)

    args = argparser.parse_args()
    f = args.file
    set_to_size = args.set_to_size
    wait = args.wait

    logging.basicConfig(level=logging.INFO)

    with f.open("br") as fd:
        counter = read_counter(fd)

    print ("Counter for %s is %d" % (f, counter))

    if set_to_size:
        fsize = detect_magic_size(f)
        with f.open("br+") as fd:
            set_counter(fd, fsize)
        print ("Counter set to %d" % fsize)


    if wait:
        fsize = detect_magic_size(f)
        log.info("Waiting for changes for %d seconds", wait)
        with f.open("br") as fd:
            last_time = datetime.now()
            last_counter = counter

            cont = True
            while cont:
                time.sleep(wait)

                counter = read_counter(fd)
                counter_diff = counter - last_counter
                if counter_diff <= 0:
                    log.error("Did not make any progress in %d seconds!", wait)

                now = datetime.now()
                time_diff = (now - last_time).total_seconds()
                remaining_bytes = fsize - counter
                byte_per_sec = counter_diff / time_diff
                remaining_secs = remaining_bytes / byte_per_sec
                eta = now + timedelta(seconds=remaining_secs)
                print ("%4.2f%% at %5.2fMB/s  %d / %d, %d remaining. ETA %s"  % ((counter / fsize) * 100,  byte_per_sec / 1024 / 1024, counter, fsize,  remaining_bytes, eta.isoformat(timespec="minutes")))

                last_time = now
                last_counter = counter

if __name__ == "__main__":
    main()
