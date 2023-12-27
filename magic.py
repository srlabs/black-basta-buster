#!/usr/bin/env python3
"""The encryptor leaves a byte sequence in the footer of each encrypted file.
We try to detect that sequence to not operate on non-encrypted files.
The last 12 byte of a file could well be the magic.
If you know what you are doing you can ignore these checks and assume the magic exists.
Because the file size determines which parts of the file are encrypted,
it is important to subtract the size of the footer before determining the encrypted blocks.
The magic extension you probably know. Encrypted files should have a 9 byte suffix.
"""
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
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from pathlib import Path
import os
import sys

from version import VERSION

log = logging.getLogger(__name__)


if os.environ.get("SRL_BBB_MAGIC", None):
    MAGIC = os.environ.get("SRL_BBB_MAGIC").encode() + b'\x00'
else:
    ### !!!   PLEASE EDIT YOUR MAGIC HERE  !!!
    MAGIC = None

if os.environ.get("SRL_BBB_MAGIC_EXT", None):
    MAGIC_EXT = os.environ.get("SRL_BBB_MAGIC_EXT")
else:
    ### !!!   PLEASE EDIT YOUR MAGIC_EXT HERE  !!!
    MAGIC_EXT = None

SEEK_END = 2



IGNORE_MAGIC = bool(os.environ.get("SRL_IGNORE_MAGIC", None))

def detect_version(path):
    with path.open("rb") as fd:
        fd.seek(-23, SEEK_END)
        version = fd.read(1)
        if version != b'\x06':
            raise ValueError("I think we can only handly v 0x06, not %r", version)

    return version


def read_magic(fd):
    fd.seek(-12, SEEK_END)
    magic = fd.read(12)
    return magic

def detect_magic(path):
    if IGNORE_MAGIC:
        log.warning("Since we do not know the MAGIC, we will attempt to detect it.")
        return False

    with path.open("rb") as fd:
        magic = read_magic(fd)
        is_magic = magic == MAGIC

        if is_magic:
            log.info("Found MAGIC, Adjusting size ")
        else:
            log.debug("Read magic: %r", magic)

    is_magic = magic == MAGIC
    log.info("File %s is " +  ("" if is_magic else "not ") + "magic", path)
    return is_magic


def detect_magic_size(path):
    fsize = path.stat().st_size

    if detect_magic(path):
        fsize -= 314

    return fsize

def backup_magic_footer(f):
    if detect_magic(f):
        with f.open("rb") as fd:
            fd.seek(-314, SEEK_END)
            footer = fd.read(314)
            with f.with_suffix(f".{MAGIC_EXT}.kbckp").open("bx") as bckp:
                bckp.write(footer)

        with f.open("br+") as fd:
            fd.seek(-314, SEEK_END)
            fd.truncate()

def rename_file(f):
    log.debug(f"Suffix: {f.suffix}; magic_ext: {MAGIC_EXT}")
    if f.suffix == "." + MAGIC_EXT:
        new_fname = f.with_suffix('')
        log.info(f"Renaming file to remove magic suffix: {f} {new_fname}")
        f.rename(new_fname)
        r = new_fname
    else:
        r = f

    return r

if __name__ == "__main__":
    try:
        fname = sys.argv[1]
    except IndexError:
        print ("Provide a filename as argument", file=sys.stderr)
    else:
        with Path(fname).open('rb') as fd:
            magic = read_magic(fd)

        print (f"Your MAGIC is {magic}")
        print (f"Please edit magic.py to include")
        print (f"MAGIC={magic}")
        if magic[-1] != 0:
            print ("Your MAGIC does not look legit: %r (%r)" % (magic[-1], magic))

        suffix = Path(fname).suffix[1:]
        log.debug("Suffix: %r", suffix)
        if len(suffix) == 9:
            print (f"MAGIC_EXT={suffix}")

            print ()
            print ("Alternatively, you can run with")
            print ("env SRL_BBB_MAGIC=%s SRL_BBB_MAGIC_EXT=%s  ./decryptauto.py %s" % (magic[:-1].decode(), suffix, fname))

else:
    if not IGNORE_MAGIC:
        if MAGIC is None:
            raise ValueError("You need to adjust the MAGIC to be safe. If you know what you are doing, you can run with a SRL_IGNORE_MAGIC environment variable set.")

        if MAGIC_EXT is None:
            raise ValueError("You need to adjust the MAGIC_EXT to backup the footer. "
                    "If you know what you are doing, you can run with the SRL_IGNORE_MAGIC environment variable set.")


        assert len(MAGIC) == 12, "Expect 11 characters of MAGIC, not %d" % (len(MAGIC)-1)
        assert len(MAGIC_EXT) == 9, "Expect 9 characters of MAGIC_EXT, not %d" % len(MAGIC_EXT)
