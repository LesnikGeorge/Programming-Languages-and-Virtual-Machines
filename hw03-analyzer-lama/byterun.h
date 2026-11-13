#ifndef BYTERUN_H
#define BYTERUN_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    const char    *filename;
    uint32_t       stringtab_size;
    uint32_t       global_area_size;
    uint32_t       public_symbols_number;
    const char    *public_ptr;
    const char    *string_ptr;
    const uint8_t *code_ptr;
    uint32_t       code_size;
    char          *raw_data;
} bytefile;

typedef struct {
    uint32_t length;
    uint32_t target;
    bool     has_target;
    bool     falls_through;
    bool     is_call;
} insn_info;

_Noreturn void vm_error(const char *fmt, ...);

bytefile   *read_file(const char *fname);
void        close_file(bytefile *bf);

uint32_t    get_public_offset(const bytefile *bf, uint32_t i);
const char *get_public_name(const bytefile *bf, uint32_t i);

insn_info   decode_insn(const bytefile *bf, uint32_t ip);
uint32_t    disassemble_insn(FILE *f, const bytefile *bf, uint32_t ip);

#endif