# c1n

import r2pipe
import subprocess

#
# Change the mips-linux-gnu-objcopy and binary path
# sudo apt install radare2
# pip install r2pipe
#  

def symbolizer(binary_path):
    r2 = r2pipe.open(binary_path)
    r2.cmd("aaa")  # Analyze everything
    functions = r2.cmdj("aflj")  # Get function list
    # Get the address of the .text section
    section_address = r2.cmd('iS')  # 'iS' lists all sections and their addresses
    #print(f".text section address: {section_address}")
    section_address=section_address.splitlines()
    text_section_address=0xdeadbeef
    for line in section_address:
        if ".text" in line:
            text_section_address = line.split()[3]
    
    if text_section_address == 0xdeadbeef:
        print("Error : .text section is not found!")
        return -1

    for func in functions:
        addr = func["offset"]
        name = func["name"]
        print(hex(addr-int(text_section_address,16)))
        offset=(addr-int(text_section_address,16))
        name=name.split(".")[-1]
        print(f"Function at 0x{addr:x}: {name}")
        command=f"mips-linux-gnu-objcopy {binary_path} --add-symbol {name}=.text:0x{offset:x},function,global {binary_path}-with-symbols"
        print(command)
        subprocess.run(command, shell=True)


binary_path = "busybox"
symbolizer(binary_path)