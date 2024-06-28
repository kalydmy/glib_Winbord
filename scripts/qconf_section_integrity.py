##
# @internal
# @remark     Winbond Electronics Corporation - Confidential
# @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
# @endinternal
#
# @file       qconf_section_integrity.py
# @brief      This file calculates CRC and digest of section and sets them in QCONF configuration structure in the axf file 
#

DEBUG = False
#DEBUG = True

import os
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from elftools.elf.constants import SH_FLAGS
from elftools.common.py3compat import bytes2str

import argh
from argh import arg

from file_hasher import filehash

from qconf_section_integrity_common import find_symbol_in_file

from create_section_config import section_config

# Global constants for offsets in QCONF_T structure.
NEED_DIGEST_MASK = 0x01
NEED_CRC_MASK = 0x02
ROLLBACK_PROTECTED_MASK = 0x08

class sectionintegrity(object):
    def __init__(self, file_name = '', symbol_name='', object_copy_path = '', sections_config = {}, section_struct_fields_addr = {}):
        # axf firmware file name
        self.axfFile = file_name
        
        # qconf structure symbol name
        self.symbol_name = symbol_name
        
        # objcopy executable path   
        self.objcopy_path  = object_copy_path

        self.section_struct_fields_addr = section_struct_fields_addr

        self.file_obj = open(self.axfFile, "rb")
                
        self.symbol_file_offset, self.symbol_size = find_symbol_in_file(self.file_obj, self.symbol_name)

        self.sections_config = sections_config
        self.__read_sections_config()

        self.file_obj.close()
      
    def set_crc_digest(self, sections_crc_digest):
        self.sections_crc_digest = sections_crc_digest

    def run(self):
        for section in range(8):
            self.__updateIntegrity(section)

        if DEBUG:
            fileObj = open(self.axfFile, "r+b")
      
            # read qconf original struct
            fileObj.seek(self.symbol_file_offset + self.section_struct_fields_addr['section_table_offset'], 0)
            qconf_data = fileObj.read(self.symbol_size)
            for i in range(8):
                print("address: " + hex(int.from_bytes(qconf_data[self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_address_offset'] : self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_address_offset'] + self.section_struct_fields_addr['section_table_address_size']], byteorder='little')))
                print("length: " + hex(int.from_bytes(qconf_data[self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_length_offset'] : self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_length_offset'] + self.section_struct_fields_addr['section_table_length_size']], byteorder='little')))
                print("policy: " + hex(int.from_bytes(qconf_data[self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_policy_offset'] : self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_policy_offset'] + self.section_struct_fields_addr['section_table_policy_size']], byteorder='little')))
                print("crc: " + hex(int.from_bytes(qconf_data[self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_crc_offset'] : self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_crc_offset'] + self.section_struct_fields_addr['section_table_crc_size']], byteorder='little')))
                print("digest: " + hex(int.from_bytes(qconf_data[self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_digest_offset'] : self.section_struct_fields_addr['section_table_entry_size'] * i + self.section_struct_fields_addr['section_table_digest_offset'] + self.section_struct_fields_addr['section_table_digest_size']], byteorder='little')))
  
    def __calc_section_table_crc_digest_offset(self, section):
        section_offset = self.section_struct_fields_addr['section_table_offset'] + (self.section_struct_fields_addr['section_table_entry_size'] * section)
        return (section_offset + self.section_struct_fields_addr['section_table_crc_offset'], section_offset + self.section_struct_fields_addr['section_table_digest_offset'])
    
    def __read_sections_config(self):
        sections_table = []
        fileObj = open(self.axfFile, "r+b")
        
        # read qconf original struct
        fileObj.seek(self.symbol_file_offset, 0)
        qconf_data = fileObj.read(self.symbol_size)
        fileObj.close()

        qconf_data_hex = []

        for i in range(8):
            section_address_offset = self.section_struct_fields_addr['section_table_offset'] + (self.section_struct_fields_addr['section_table_entry_size'] * i) + self.section_struct_fields_addr['section_table_address_offset']
            section_address = int.from_bytes(qconf_data[section_address_offset : section_address_offset + self.section_struct_fields_addr['section_table_address_size']], 'little')
            section_size_offset = self.section_struct_fields_addr['section_table_offset'] + (self.section_struct_fields_addr['section_table_entry_size'] * i) + self.section_struct_fields_addr['section_table_length_offset']
            section_size = int.from_bytes(qconf_data[section_size_offset : section_size_offset + self.section_struct_fields_addr['section_table_length_size']], 'little')
            section_policy_offset = self.section_struct_fields_addr['section_table_offset'] + (self.section_struct_fields_addr['section_table_entry_size'] * i) + self.section_struct_fields_addr['section_table_policy_offset']
            section_policy = int.from_bytes(qconf_data[section_policy_offset : section_policy_offset + self.section_struct_fields_addr['section_table_policy_size']], 'little')
            need_digest = True if((section_policy & NEED_DIGEST_MASK) == NEED_DIGEST_MASK) else False
            need_crc = True if((section_policy & NEED_CRC_MASK) == NEED_CRC_MASK) else False
            if ((section_policy & ROLLBACK_PROTECTED_MASK) == ROLLBACK_PROTECTED_MASK):
                section_size = (int)(section_size/2)
            sections_table.append({"need_crc" : need_crc,  "need_digest" : need_digest,  "section_addr" : section_address,   "section_size": section_size})
        
        self.sections_config.update({"sections_table" : sections_table})

    def zero_qconf_struct_in_bin_file(self, bin_file):
        fileObj = open(self.axfFile, "r+b")
        
        # read qconf original struct
        fileObj.seek(self.symbol_file_offset, 0)
        qconf_orig_data = fileObj.read(self.symbol_size)

        #override qconf structure with zeros in axf file
        fileObj.seek(self.symbol_file_offset, 0)
        fileObj.write(bytes(self.symbol_size))
        fileObj.close()

        #convert the new axf to binary
        os.system(self.objcopy_path + " --gap-fill 0xff -O binary " + self.axfFile + " " + bin_file)
        
        #write the qconf structure back to its position in axf file
        fileObj = open(self.axfFile, "r+b")
        fileObj.seek(self.symbol_file_offset, 0)
        fileObj.write(qconf_orig_data)
        fileObj.close()

    def __updateIntegrity(self, section):
        crc = self.sections_crc_digest[section][0]
        digest = self.sections_crc_digest[section][1]
        print("integrity for section " + str(section) + "  " + hex(crc) + " " + hex(digest))

        crc_offset, digest_offset = self.__calc_section_table_crc_digest_offset(section)

        fileObj = open(self.axfFile, "r+b")
        
        # read qconf original struct
        fileObj.seek(self.symbol_file_offset + min(crc_offset, digest_offset), 0)
        qconf_orig_data = fileObj.read(self.section_struct_fields_addr['section_table_crc_size'] + self.section_struct_fields_addr['section_table_digest_size'])
                    
        #set the CRC and digest in the original qconf struct
        qconf_new_data = bytearray(qconf_orig_data)
        crc_byte_array = crc.to_bytes(self.section_struct_fields_addr['section_table_crc_size'], 'little')
        digest_byte_array = digest.to_bytes(self.section_struct_fields_addr['section_table_digest_size'], 'little')
        qconf_new_data[0 : self.section_struct_fields_addr['section_table_crc_size']] = crc_byte_array
        qconf_new_data[self.section_struct_fields_addr['section_table_crc_size'] : self.section_struct_fields_addr['section_table_crc_size'] + self.section_struct_fields_addr['section_table_digest_size']] = digest_byte_array

        #write the qconf struct back to its position in axf file
        fileObj.seek(self.symbol_file_offset + min(crc_offset, digest_offset), 0)
        fileObj.write(qconf_new_data)
        fileObj.close()

@arg('--axf_filename', help='axf file name')
@arg('--qconf_struct_name', help='symbol name of QCONF_T struct')
@arg('--objcopy_path', help='path of objcopy executable')
@arg('--sections_config', help='section configuration as a dictionary')
@arg('--section_struct_fields_addr', help='section structure fields address')
def calc_section_integrity(axf_filename = "", qconf_struct_name = "", objcopy_path = "", sections_config = {}, section_struct_fields_addr = {}):
    """! calculates and sets the digest and crc of the section in the axf qconf structure
    @param axf_filename                 axf file name
    @param qconf_struct_name            Symbol name of QCONF_T struct
    @param objcopy_path                 Path of objcopy executable
    @param sections_config              dictionary containing section configuration including padding, hash algorithm and for each section the address and size
    @param section_struct_fields_addr   dictionary containing section fields address
    """
    if DEBUG:
        axf_filename = r'c:\workspace\wtl\sw\projects\qsfi\bsp\w77q_dual_flash_demo_proj_new\w77q_dual_flash_demo\proj_1050\demo\1050Board.axf'
        qconf_struct_name = "qconf_g"
        objcopy_path = r'arm-none-eabi-objcopy'
        sections_config = {"padding" : "0xff", "hash" : "sha256"}

    sections_struct_fields_vars = \
    {
        'qconf_offset': 'qconf_offset',
        'qconf_SectionTable_0_offset': 'qconf_SectionTable_0_offset',
        'qconf_SectionTable_baseAddr_offset': 'qconf_SectionTable_baseAddr_offset',
        'qconf_SectionTable_size_offset': 'qconf_SectionTable_size_offset',
        'qconf_SectionTable_policy_offset': 'qconf_SectionTable_policy_offset',
        'qconf_SectionTable_crc_offset': 'qconf_SectionTable_crc_offset',
        'qconf_SectionTable_digest_offset': 'qconf_SectionTable_digest_offset',
        'qconf_SectionTable_1_offset': 'qconf_SectionTable_1_offset'
    }
    section_config_var = section_config(axf_filename, sections_struct_fields_vars)
    section_struct_fields_addr = section_config_var.prepare_section_config()
    section_integrity = sectionintegrity(axf_filename, qconf_struct_name, objcopy_path, sections_config, section_struct_fields_addr)
    section_integrity.run()

if __name__ == "__main__":
    argh.dispatch_command(calc_section_integrity)
