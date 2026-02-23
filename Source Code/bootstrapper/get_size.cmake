file(SIZE "${ELF_FILE}" FILE_SIZE)
file(WRITE "${ELF_FILE}.lzma.size" "${FILE_SIZE}")
