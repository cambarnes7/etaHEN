#!/usr/bin/env python3
"""
PS5 Game Import Analyzer
Extracts NIDs from decrypted PS5 ELF/SELF files and resolves them.
Works on Mac/Linux/Windows - no binutils required.

Usage: python3 analyze_game.py <eboot.bin> [nid_database.txt]
"""

import struct
import sys
import os

# ELF constants
ELF_MAGIC = b'\x7fELF'
ET_DYN = 3
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_HASH = 4

# Symbol binding/type
STB_GLOBAL = 1
STB_WEAK = 2

def read_elf_imports(filepath):
    """Extract imported symbol names (NIDs) from an ELF file."""
    with open(filepath, 'rb') as f:
        # Check ELF magic
        magic = f.read(4)
        if magic != ELF_MAGIC:
            print(f"Error: {filepath} is not an ELF file", file=sys.stderr)
            print(f"Magic bytes: {magic.hex()}", file=sys.stderr)
            return None
        
        f.seek(0)
        
        # Read ELF header
        e_ident = f.read(16)
        is_64bit = e_ident[4] == 2
        is_le = e_ident[5] == 1
        
        if not is_64bit:
            print("Error: Only 64-bit ELF supported", file=sys.stderr)
            return None
        
        endian = '<' if is_le else '>'
        
        # Read rest of ELF header (64-bit)
        f.seek(16)
        e_type, e_machine, e_version = struct.unpack(endian + 'HHI', f.read(8))
        e_entry, e_phoff, e_shoff = struct.unpack(endian + 'QQQ', f.read(24))
        e_flags, e_ehsize, e_phentsize, e_phnum = struct.unpack(endian + 'IHHH', f.read(10))
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + 'HHH', f.read(6))
        
        # Find PT_DYNAMIC segment
        dyn_offset = 0
        dyn_size = 0
        
        for i in range(e_phnum):
            f.seek(e_phoff + i * e_phentsize)
            p_type, p_flags = struct.unpack(endian + 'II', f.read(8))
            p_offset, p_vaddr, p_paddr = struct.unpack(endian + 'QQQ', f.read(24))
            p_filesz, p_memsz, p_align = struct.unpack(endian + 'QQQ', f.read(24))
            
            if p_type == PT_DYNAMIC:
                dyn_offset = p_offset
                dyn_size = p_filesz
                break
        
        if dyn_offset == 0:
            print("Error: No PT_DYNAMIC segment found", file=sys.stderr)
            return None
        
        # Parse dynamic section
        strtab_off = 0
        symtab_off = 0
        strsz = 0
        hash_off = 0
        
        f.seek(dyn_offset)
        while True:
            d_tag, d_val = struct.unpack(endian + 'QQ', f.read(16))
            if d_tag == DT_NULL:
                break
            elif d_tag == DT_STRTAB:
                strtab_off = d_val
            elif d_tag == DT_SYMTAB:
                symtab_off = d_val
            elif d_tag == DT_STRSZ:
                strsz = d_val
            elif d_tag == DT_HASH:
                hash_off = d_val
        
        # These are virtual addresses, need to convert to file offsets
        # Find the load segment that contains these addresses
        def vaddr_to_offset(vaddr):
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                p_type, p_flags = struct.unpack(endian + 'II', f.read(8))
                p_offset, p_vaddr, p_paddr = struct.unpack(endian + 'QQQ', f.read(24))
                p_filesz, p_memsz, p_align = struct.unpack(endian + 'QQQ', f.read(24))
                
                if p_type == 1:  # PT_LOAD
                    if p_vaddr <= vaddr < p_vaddr + p_filesz:
                        return p_offset + (vaddr - p_vaddr)
            return vaddr  # Fallback
        
        strtab_file_off = vaddr_to_offset(strtab_off)
        symtab_file_off = vaddr_to_offset(symtab_off)
        hash_file_off = vaddr_to_offset(hash_off) if hash_off else 0
        
        # Get symbol count from hash table
        nsyms = 0
        if hash_file_off:
            f.seek(hash_file_off)
            nbucket, nchain = struct.unpack(endian + 'II', f.read(8))
            nsyms = nchain
        else:
            # Estimate from section size (not ideal)
            nsyms = 1000
        
        # Read string table
        f.seek(strtab_file_off)
        strtab = f.read(strsz if strsz else 0x10000)
        
        def get_string(offset):
            end = strtab.find(b'\x00', offset)
            if end == -1:
                return strtab[offset:].decode('utf-8', errors='replace')
            return strtab[offset:end].decode('utf-8', errors='replace')
        
        # Read symbols
        imports = []
        sym_size = 24  # Elf64_Sym size
        
        for i in range(nsyms):
            f.seek(symtab_file_off + i * sym_size)
            try:
                st_name, st_info, st_other, st_shndx = struct.unpack(endian + 'IBBH', f.read(8))
                st_value, st_size = struct.unpack(endian + 'QQ', f.read(16))
            except:
                break
            
            # Check if it's an undefined symbol (import)
            if st_shndx == 0 and st_name != 0:  # SHN_UNDEF
                binding = st_info >> 4
                if binding in (STB_GLOBAL, STB_WEAK):
                    name = get_string(st_name)
                    if name and len(name) > 0:
                        imports.append(name)
        
        return imports

def load_nid_database(db_path):
    """Load NID->name mapping from database file."""
    nid_map = {}
    try:
        with open(db_path, 'r') as f:
            for line in f:
                line = line.strip()
                if '\t' in line:
                    nid, name = line.split('\t', 1)
                    nid_map[nid] = name
    except FileNotFoundError:
        print(f"Warning: NID database not found at {db_path}", file=sys.stderr)
    return nid_map

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_game.py <eboot.bin> [nid_database.txt]")
        print("")
        print("Analyzes a decrypted PS5 ELF and shows imported NIDs.")
        sys.exit(1)
    
    elf_path = sys.argv[1]
    
    # Find NID database
    if len(sys.argv) > 2:
        db_path = sys.argv[2]
    else:
        # Try to find it relative to this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, 'ps5_nid_database.txt')
    
    print(f"Analyzing: {elf_path}")
    print(f"NID database: {db_path}")
    print("")
    
    # Extract imports
    imports = read_elf_imports(elf_path)
    if imports is None:
        sys.exit(1)
    
    # Load NID database
    nid_db = load_nid_database(db_path)
    
    # Analyze
    resolved = []
    unresolved = []
    
    for nid in imports:
        if nid in nid_db:
            resolved.append((nid, nid_db[nid]))
        else:
            unresolved.append(nid)
    
    # Output results
    print(f"=== IMPORT SUMMARY ===")
    print(f"Total imports: {len(imports)}")
    print(f"Resolved:      {len(resolved)}")
    print(f"Unresolved:    {len(unresolved)}")
    print("")
    
    print(f"=== RESOLVED IMPORTS ({len(resolved)}) ===")
    for nid, name in sorted(resolved, key=lambda x: x[1]):
        print(f"  {nid}  {name}")
    
    print("")
    print(f"=== UNRESOLVED NIDS ({len(unresolved)}) ===")
    for nid in sorted(unresolved):
        print(f"  {nid}")
    
    # Save to files
    with open('resolved_imports.txt', 'w') as f:
        for nid, name in sorted(resolved, key=lambda x: x[1]):
            f.write(f"{nid}\t{name}\n")
    
    with open('unresolved_nids.txt', 'w') as f:
        for nid in sorted(unresolved):
            f.write(f"{nid}\n")
    
    print("")
    print(f"Results saved to: resolved_imports.txt, unresolved_nids.txt")

if __name__ == "__main__":
    main()
