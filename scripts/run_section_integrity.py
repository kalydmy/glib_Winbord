##
# @internal
# @remark     Winbond Electronics Corporation - Confidential
# @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
# @endinternal
#
# @file       run_section_integrity.py
# @brief      This file calculates CRC and digest of section and sets them in QCONF configuration structure in the axf file 
#

DEBUG = False
#DEBUG = True

from qconf_section_integrity import sectionintegrity
from create_section_config import section_config
from file_hasher import filehash
import argh
from argh import arg
import os

@arg('--axf_filename', help='axf file name')
@arg('--qconf_struct_name', help='symbol name of QCONF_T struct')
@arg('--section_struct_fields_addr', help='section structure fields address')
@arg('--objcopy_path', help='path of objcopy executable')
@arg('--padding', help='padding data, in case section size goes beyond the binary file size')
@arg('--hash', help='hash algorithm (sha256/sm3)')
def run_section_integrity(axf_filename = "", qconf_struct_name = "qconf_g", objcopy_path = "arm-none-eabi-objcopy", padding = "0xff", hash = "sha256", section_struct_fields_addr = {}):
    """! calculates and sets the digest and crc of the section in the axf qconf structure
    @param axf_filename                 axf file name
    @param qconf_struct_name            Symbol name of QCONF_T struct
    @param section_struct_fields_addr   dictionary containing section fields address
    @param objcopy_path                 Path of objcopy executable
    @param padding                      padding
    @param hash                         hash algorithm (sha256 / sm3)
    """
    if DEBUG:
        #initialize arguments in debug mode
        axf_filename = r'c:\workspace\wtl\sw\projects\qsfi\bsp\w77q_dual_flash_demo_proj_new\w77q_dual_flash_demo\proj_1050\demo\1050Board.axf'
        qconf_struct_name = "qconf_g"
        objcopy_path = r'arm-none-eabi-objcopy'
        padding = "0xff"
        hash = "sha256"

    #Currently we define the adderss variables internally. The user can send them to the function as argument.
    #The dictionary shoujld contain the variables names which contain the address of the qconf structure fields.
    if section_struct_fields_addr == {}:
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

    bin_filename = "{0}_{2}.{3}".format(*axf_filename.rsplit('.', 1) + ["temp"] + ["bin"])

    #initialize the sections_config with the padding and hash algorithm
    sections_config = {"padding" : padding, "hash" : hash}
    section_integrity = sectionintegrity(axf_filename, qconf_struct_name, objcopy_path, sections_config, section_struct_fields_addr)
    
    #rewrite the qconf structure int the axf file with zeros
    section_integrity.zero_qconf_struct_in_bin_file(bin_filename)

    #calculate the crc and digest for each section and add them to the list
    sections_crc_digest = []
    for i in range(8):
        if(sections_config["sections_table"][i]["need_crc"] or sections_config["sections_table"][i]["need_digest"]):
            hasher = filehash(
                        bin_filename, 
                        sections_config["sections_table"][i]["section_addr"], 
                        sections_config["sections_table"][i]["section_size"], 
                        sections_config["padding"], 
                        sections_config["hash"])
        if(sections_config["sections_table"][i]["need_crc"]):
            crc = hasher.get_crc()
        else:
            crc = 0

        if(sections_config["sections_table"][i]["need_digest"]):
            digest = hasher.get_digest()
        else:
            digest = 0
        sections_crc_digest.append([crc, digest])

    section_integrity.set_crc_digest(sections_crc_digest)
    section_integrity.run()
    if os.path.exists(bin_filename):
        os.remove(bin_filename)

if __name__ == "__main__":
    argh.dispatch_command(run_section_integrity)
