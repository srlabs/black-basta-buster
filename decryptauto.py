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
from pathlib import Path
import sys

from magic import backup_magic_footer, rename_file
from decryptblocks import detect_magic_size, decrypt_file, make_int
from extractblock import auto_detect_key_block

log = logging.getLogger(__name__)


def main():
    argparser = argparse.ArgumentParser(description="Tries to automatically determine encrypted zero bytes and applies that key to the whole file or parts thereof, if --start-at is given.")
    argparser.add_argument("--dry", action="store_true",
        help="Do not write anything")
    argparser.add_argument("--start-at", type=int, default=None)
    argparser.add_argument("file", type=Path)

    args = argparser.parse_args()
    f = args.file
    is_dry = args.dry
    start_at = args.start_at
    end_at = None

    logging.basicConfig(level=logging.INFO)

    if not is_dry:
        backup_magic_footer(f)

    keyblock = auto_detect_key_block(f, lower_limit=start_at)
    decrypt_file(f, keyblock=keyblock, fsize=detect_magic_size(f), is_dry=is_dry, lower_limit=start_at, upper_limit=end_at)

    if not is_dry:
        fname = rename_file(f)
        print ("Decrypted: %s" % fname)



if __name__ == "__main__":
    main()
