##
# @internal
# @remark     Winbond Electronics Corporation - Confidential
# @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
# @endinternal
#
# @file       file_hasher.py
# @brief      This file implements a CRC and digest hash calculation on a specific input file
# @note       The implementation uses cryptography and argh modules. please install them before use
#

DEBUG = False

import zlib
import os
from cryptography.hazmat.primitives import hashes
import argh
from argh import arg

class filehash(object):
    def __init__(self, file_name = None, buffer_offset = 0, buffer_size = 0, padding = '', hash_algorithm = ''):
        file_data, padding = self.__get_hashed_data(file_name, buffer_size, buffer_offset, padding)

        if (hash_algorithm.lower() == "sha256"):
            sha256_digest = hashes.Hash(hashes.SHA256())
            sha256_digest.update(file_data)
            sha256_digest.update(padding)
            self.digest = int.from_bytes(sha256_digest.finalize()[24:32], byteorder='little')
        elif (hash_algorithm.lower() == "sm3"):
            sm3_digest = hashes.Hash(hashes.SM3())
            sm3_digest.update(file_data)
            sm3_digest.update(padding)
            self.digest = int.from_bytes(sm3_digest.finalize()[24:32], byteorder='little')
        else:
            self.digest = 0
            raise Exception('wrong digest algorithm')

        self.crc = ((zlib.crc32(file_data + padding)) & (0xffffffff))

    def __print(self, str):
        if DEBUG:
            print(str)

    def __get_hashed_data(self, file_name, buffer_size, buffer_offset, padding):

        if (file_name != None):
            try:
                bin_file = open(file_name, 'rb')
                file_size = os.stat(file_name).st_size
                data_size = file_size - buffer_offset
                bin_file.seek(buffer_offset, 0)
        
                self.__print("ftell returned " + str(buffer_size))

                file_data = bin_file.read(min(data_size, buffer_size))
                bin_file.close()
            except Exception as e:
                print(e)
                print("could not open input file: " + file_name)
                raise Exception('file error')
        else:
            data_size = 0
            file_data = bytes()

        padding_size = 0 if data_size >= buffer_size else buffer_size - data_size
        padding_data = bytes.fromhex(padding.replace("0x" , "")) * padding_size
        self.__print("data_size = " + str(data_size) + " padding_size = " + str(padding_size))
        return file_data, padding_data

    def get_digest(self):
        return (self.digest)

    def get_crc(self):
        return (self.crc)

@arg('--file_name', help='binary file')
@arg('--section_size', help='section size in KB(or active partition size in case rollback is enabled)')
@arg('--padding', help='padding data, in case section size goes beyond the binary file size')
@arg('--hash', help='hash algorithm (sha256/sm3)')
def cliHasher(file_name = None, section_size = 512, padding = "0xff", hash="sha256"):
    if DEBUG:
        file_name = r'c:\workspace\wtl\sw\projects\qsfi\bsp\w77q_dual_flash_demo_proj\w77q_dual_flash_demo\proj\demo\w77q_dual_flash_demo_proj.axf'
    "Calculates digest and crc of the file over section(offset and size in KB) with padding"
    print("File " + str ("None" if file_name is None else file_name) + " on section of " + str(section_size) + " KB padded with " + padding)
    hasher = filehash(file_name, 0, section_size*1024, padding, hash)

    #convert digest to big endian hex string
    ba = bytearray.fromhex(format(hasher.get_digest(), '016X'))
    ba.reverse()
    digest_as_hexString = ''.join(format(x, '02x') for x in ba)

    print(hash + " digest: " + digest_as_hexString.upper() + " (" + hex(hasher.get_digest()) + ")")
    print("crc32: " + hex(hasher.get_crc()))

if __name__ == "__main__":
    argh.dispatch_command(cliHasher)
