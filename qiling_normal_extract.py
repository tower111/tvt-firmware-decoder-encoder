#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#
import struct
from typing import Mapping
import sys
sys.path.append("..")
import traceback
from qiling.core import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE,QL_INTERCEPT
from qiling.os.const import STRING


start=0
decode_start=0
def end(ql:Qiling):
    #8000B5D4
    ql.log.info(f"加密数据结束：{ql.arch.regs.read('r0')}")
    if ql.arch.regs.read('r0')==1:
        print("解密成功")
        custom_error_handler(ql)
    else:
        print("解密失败")
    
def debug_hook(ql:Qiling):
    global start
    start=ql.arch.regs.read('r0')
    print("加密数据开始地址：",hex(ql.arch.regs.read('r0')))
    print("加密数据长度：",hex(ql.arch.regs.read('r1')))
    
    print(f"解密后数据存放地址:{hex(0x100000+0x80000000)}")
    # r3=struct.unpack("<I",ql.mem.read(r3,4))[0]
def __map_regs() -> Mapping[int, int]:
    """Map Capstone x86 regs definitions to Unicorn's.
    """

    from capstone import x86_const as cs_x86_const
    from unicorn import x86_const as uc_x86_const

    def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
        return dict((k[len(prefix):], getattr(module, k)) for k in dir(module) if k.startswith(prefix))

    cs_x86_regs = __canonicalized_mapping(cs_x86_const, 'X86_REG')
    uc_x86_regs = __canonicalized_mapping(uc_x86_const, 'UC_X86_REG')

    return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs)

# capstone to unicorn regs mapping
CS_UC_REGS = __map_regs()
def custom_error_handler(ql):
    # if ql.verbose & QL_VERBOSE.EXCEPTION:
    #     print("Exception:", exception)

    # 获取寄存器信息
    md = ql.arch.disassembler
    md.detail = True
    regs = ["r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12", "sp", "lr", "pc"]
    for R in regs:
        registers = ql.arch.regs.read(R)
        ql.log.info(f'{R}:{hex(registers)}')
    # 获取当前指令信息
    asm_addr=ql.arch.regs.pc-0x100
    current_instruction = ql.mem.read(asm_addr, 0x100+4)  # 读取当前指令的前16个字节
    # insn = next(md.disasm(current_instruction, ql.arch.regs.pc))
    for insn in md.disasm(current_instruction, asm_addr):
        nibbles = ql.arch.bits // 4

        trace_line = f'{insn.address+0x80008000:0{nibbles}x} | {insn.bytes.hex():24s} {insn.mnemonic:12} {insn.op_str:35s} '

        # emit the trace line in a faded color, so it would be easier to tell trace info from other log entries
        # ql.log.info(f'{color_faded}{trace_line}{color_reset}')
        ql.log.info(f'{trace_line}')

    ql.log.info(f'encode:{hex(start)} {ql.mem.read(start,30)}')
    ql.log.info(f'decode:{hex(decode_start)} {ql.mem.read(decode_start,30)}')
    
    with open("vmlinux_qiling",'wb') as fd :
        fd.write(ql.mem.read(decode_start,0xffffff))
# def bypass(ql:Qiling):
#     print('bypass')
    # ql.log.info('bypass')
def get_kaimendaji_password():
    def partial_run_init(ql: Qiling):
        # argv prepare
        global decode_start
        decode_start=0x1000000+0x80000000
        ql.mem.map(decode_start, 0x1000000, info='my_hook')
        # ql.mem.write(0x10000, b'ubuntu')
        ql.arch.regs.write('r0',decode_start)
        ql.mem.map(0x2000000+0x80000000, 0x1000000, info='my_hook1')
        ql.arch.regs.write('r1',0x2000000+0x80000000)
        ql.arch.regs.write('r2',0x3000000-1+0x80000000)
        ql.arch.regs.write('r3',1)
        
        


    with open("../uImage", "rb") as f:
        uboot_code = f.read()
    ql = Qiling(code=uboot_code[0x40:], archtype=QL_ARCH.ARM, ostype=QL_OS.BLOB, profile="uboot_bin.ql", verbose=QL_VERBOSE.DEBUG)

    image_base_addr = ql.loader.load_address
    # ql.hook_address(my_getenv, image_base_addr + 0x13AC0)
    # ql.hook_address(get_password, image_base_addr + 0x48634)
    print("image base :",hex(image_base_addr))
    partial_run_init(ql)
    # ql.hook_exception(custom_error_handler)
    # ql.debugger = "qdb"
    # try:
    ql.hook_address(debug_hook,0x8000B51C-0x80008000)
    ql.hook_address(end,0x8000B5D4-0x80008000)
    # ql.hook_address(bypass,0x8000B5DC-0x80008000,QL_INTERCEPT.CALL)
    # try:
    ql.run(0x80008AAC-0x80008000,0x80008B40-0x80008000)
    # except Exception as e:
    #     print(e)
        # custom_error_handler(ql)
    
if __name__ == "__main__":

    get_kaimendaji_password()