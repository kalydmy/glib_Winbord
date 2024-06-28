##
# @internal
# @remark     Winbond Electronics Corporation - Confidential
# @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
# @endinternal
#
# @file       create_section_config.py
# @brief      This file reads from the axf file variables that point to the section configuration in the qconf structure
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

from qconf_section_integrity_common import find_symbol_in_file

class section_config(object):
    def __init__(self, file_name = '', sections_struct_fields_vars = {}):
        self.axfFile = file_name
        self.sections_struct_fields_vars = sections_struct_fields_vars

    def prepare_section_config(self):
        try:
            sections_struct_fields_addr = {}
            file_obj = open(self.axfFile, "rb")
            qconf_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_offset'])
            qconf_SectionTable_0_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_0_offset'])
            qconf_SectionTable_baseAddr_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_baseAddr_offset'])
            qconf_SectionTable_size_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_size_offset'])
            qconf_SectionTable_policy_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_policy_offset'])
            qconf_SectionTable_crc_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_crc_offset'])
            qconf_SectionTable_digest_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_digest_offset'])
            qconf_SectionTable_1_offset_value = self.__read_data_from_axf(file_obj, self.sections_struct_fields_vars['qconf_SectionTable_1_offset'])

            sections_struct_fields_addr['section_table_offset'] = qconf_SectionTable_0_offset_value - qconf_offset_value
            sections_struct_fields_addr['section_table_entry_size'] = qconf_SectionTable_1_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_address_offset'] = qconf_SectionTable_baseAddr_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_length_offset'] = qconf_SectionTable_size_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_address_size'] = sections_struct_fields_addr['section_table_length_offset'] - sections_struct_fields_addr['section_table_address_offset']
            sections_struct_fields_addr['section_table_policy_offset'] = qconf_SectionTable_policy_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_length_size'] = sections_struct_fields_addr['section_table_policy_offset'] - sections_struct_fields_addr['section_table_length_offset']
            sections_struct_fields_addr['section_table_crc_offset'] = qconf_SectionTable_crc_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_policy_size'] = sections_struct_fields_addr['section_table_crc_offset'] - sections_struct_fields_addr['section_table_policy_offset']
            sections_struct_fields_addr['section_table_digest_offset'] = qconf_SectionTable_digest_offset_value - qconf_SectionTable_0_offset_value
            sections_struct_fields_addr['section_table_crc_size'] = sections_struct_fields_addr['section_table_digest_offset'] - sections_struct_fields_addr['section_table_crc_offset']
            sections_struct_fields_addr['section_table_digest_size'] = qconf_SectionTable_1_offset_value - qconf_SectionTable_digest_offset_value
            pass
        except OSError as err:
            print("failed to open " + self.axfFile)
            raise err
        file_obj.close()
        return sections_struct_fields_addr

    def __read_data_from_axf(self, file_obj, symbol):
        offset, size = find_symbol_in_file(file_obj, symbol)
        file_obj.seek(offset, 0)
        data = file_obj.read(size)
        return int.from_bytes(data, byteorder='little')

@arg('--axf_filename', help='axf file name')
@arg('--sections_struct_fields_vars', help='the varaiables to get the section configuraiton from')
def get_sections_struct_fields_addr(axf_filename = "", sections_struct_fields_vars = {}):
    """! returns the address of the relevant filelds in the qconf structure, required for calculating the section digest and CRC
    @param axf_filename                 axf file name
    @param sections_struct_fields_vars  dictionary containing section configuration including padding, hash algorithm and for each section the address and size
    """
    if DEBUG:
        axf_filename = r'c:\workspace\wtl\sw\projects\qsfi\bsp\w77q_dual_flash_demo_proj_new\w77q_dual_flash_demo\proj_1050\demo\1050Board.axf'
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
    sections_struct_fields_addr = section_config_var.prepare_section_config()
    pass

if __name__ == "__main__":
    argh.dispatch_command(get_sections_struct_fields_addr)
