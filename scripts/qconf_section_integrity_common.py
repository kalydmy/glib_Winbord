##
# @internal
# @remark     Winbond Electronics Corporation - Confidential
# @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
# @endinternal
#
# @file       qconf_section_integrity_common.py
# @brief      This file has common functionality for the qconf section integrity project
#

import os
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from elftools.elf.constants import SH_FLAGS
from elftools.common.py3compat import bytes2str

# This function finds the qconf symbol offset in the axf file
def find_symbol_in_file(file_obj, symbol_name):
    try:
        elf_file = ELFFile(file_obj)
        symbol_virt_addr = 0
        symbol_size = 0
        symbol_file_offset = 0
        for section in elf_file.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
        
            for cnt, symbol in enumerate(section.iter_symbols()):
                if symbol.name == symbol_name:
                #   if self.qconfSymbolName in symbol.name:
                    symbol_virt_addr = symbol['st_value']
                    symbol_size = symbol['st_size']
                    break
            if symbol_size > 0:
                break;
        
        if symbol_size == 0:
            print(f"Error: can not find symbol {symbol_name} location")
            exit(1)

        for section in elf_file.iter_sections():
            if ((symbol_virt_addr >= section.header['sh_addr']) and (symbol_virt_addr < (section.header['sh_addr'] + section.header['sh_size'])) and (section.header['sh_flags'] & SH_FLAGS.SHF_ALLOC)):
                symbol_file_offset = symbol_virt_addr - section.header['sh_addr'] + section.header['sh_offset']
                #print(f"Symbol is in section: {section.name}. symbol offset in file:{hex(symbol_file_offset)} size:{hex(symbol_size)}")
                break
        
        if symbol_file_offset == 0:
            print(f"Error: can not find symbol {symbol_name} location")
            exit(1)

        return symbol_file_offset, symbol_size
    except OSError as err:
        print("failed to open axf file")
        raise err
