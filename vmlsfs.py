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
import os
from pathlib import Path
import subprocess
import sys

log = logging.getLogger(__name__)



def check_output_to_file(cmd, filename):
    try:
        with open(filename, mode="x") as fd:
            subprocess.check_call(cmd, stdout=fd)
    except subprocess.CalledProcessError:
        fcmd = " ".join(("'%s'" % c for c in cmd))
        print ("Call failed: %s" % fcmd, file=sys.stderr)
        if os.stat(filename).st_size == 0:
            os.unlink(filename)
        raise


def dir_path(path):
    p = Path(path).expanduser()
    return p
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")


def main():
    parser = argparse.ArgumentParser(
        description="""Helps to execute virt-ls by arranging its arguments based on a directory's contents.
            This is useful after having decrypted a VM to see whether the filesystem can be listed."""
    )
    parser.add_argument("--output-dir",
        type=dir_path,
        default=Path("/tmp/vfs")
    )
    parser.add_argument("--dry-run", action="store_true", help="Do not actually run potentially time consuming commands")
    parser.add_argument("vmdirs", nargs="+")
    args = parser.parse_args()

    directories = args.vmdirs
    output_dir = args.output_dir
    dry_run = args.dry_run


    vmdk_files = []
    machine_name = None

    for i, directory in enumerate(directories):
        p = Path(directory)
        if not machine_name:
            machine_name = p.name
        else:
            if not machine_name == p.name:
                raise ValueError(f"Names are not equal: {machine_name} vs. {p.name}")

        vmdk_files += list(p.glob("*.vmdk"))

    assert machine_name

    def split_vmdk_name(n):
        splits = n.rsplit('_', 1)
        if len(splits) == 1:
            return 0
        else:
            try:
                i = int(splits[1])
            except ValueError:
                return 0
            else:
                return i

    vmdks = sorted(filter(
        lambda x: not ('-flat' in x.name or '-ctk' in x.name or '-delta' in x.name or '-00000' in x.name or '-sesparse' in x.name),
        vmdk_files), key=lambda x: split_vmdk_name(x.name[:-len('.vmdk')]))

    dash_as = []
    for vmdk in vmdks:
        dash_as.append("--format=vmdk")
        dash_as.append("-a")
        dash_as.append(str(vmdk))

    vfs = ["virt-filesystems"] + dash_as + ["--all", "--uuid", "--long"]

    print (" ".join(vfs))

    output_fn = Path(output_dir) / Path(machine_name + ".fs.txt")

    check_output_to_file(vfs, output_fn) if not dry_run else print (vfs)

    print (f"Written to {output_fn}")


    subprocess.check_call(vfs) if not dry_run else print (vfs)


    vfs = ["virt-filesystems"] + dash_as + ["--filesystems"]
    filesystems = subprocess.check_output(vfs).decode('ascii')
    for fs in filesystems.splitlines():
        print (f"FS on {fs}")
        if not fs.startswith('/'):
            print (f"Ignoring {fs}; does not start with / ...")
            continue
        vls = ["virt-ls"] + dash_as + ["-m", fs,
                                       "-R", "/"]
        output_fn = Path(output_dir) / Path(machine_name + "." + fs.replace('/', "_") + ".ls-R.txt")
        check_output_to_file(vls, output_fn) if not dry_run else print (vls)
        print (f"Written to {output_fn}")


if __name__ == "__main__":
    main()
