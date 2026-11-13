#define _GNU_SOURCE 1
#include "byterun.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

typedef struct __attribute__((packed)) {
    int32_t name_offset;
    int32_t offset;
    uint8_t flag;
} public_entry;

typedef struct __attribute__((packed)) {
    int32_t st_size;
    int32_t glob_size;
    int32_t pub_num;
} file_header;

// Группы инструкций по старшему полубайту (high nibble)
typedef enum {
    H_BINOP = 0x0,
    H_LD    = 0x2,
    H_LDA   = 0x3,
    H_ST    = 0x4,
    H_PATT  = 0x6
} insn_group_t;

// Локация переменной (low nibble для LD/LDA/ST и байт спецификатора в CLOSURE)
typedef enum {
    VAR_GLOBAL  = 0,
    VAR_LOCAL   = 1,
    VAR_ARG     = 2,
    VAR_CLOSURE = 3
} var_loc_t;

// Полные опкоды инструкций
typedef enum {
    OP_CONST      = 0x10,
    OP_STRING     = 0x11,
    OP_SEXP       = 0x12,
    OP_STI        = 0x13,
    OP_STA        = 0x14,
    OP_JMP        = 0x15,
    OP_END        = 0x16,
    OP_RET        = 0x17,
    OP_DROP       = 0x18,
    OP_DUP        = 0x19,
    OP_SWAP       = 0x1A,
    OP_ELEM       = 0x1B,

    OP_CJMPZ      = 0x50,
    OP_CJMPNZ     = 0x51,
    OP_BEGIN      = 0x52,
    OP_CBEGIN     = 0x53,
    OP_CLOSURE    = 0x54,
    OP_CALLC      = 0x55,
    OP_CALL       = 0x56,
    OP_TAG        = 0x57,
    OP_ARRAY      = 0x58,
    OP_FAIL       = 0x59,
    OP_LINE       = 0x5A,

    OP_CALL_READ   = 0x70,
    OP_CALL_WRITE  = 0x71,
    OP_CALL_LENGTH = 0x72,
    OP_CALL_STRING = 0x73,
    OP_CALL_ARRAY  = 0x74,

    OP_STOP       = 0xFF
} opcode_t;

_Noreturn void vm_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "VM Error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

static inline uint8_t read_byte(const bytefile *bf, uint32_t *cursor, uint32_t insn_ip) {
    if (*cursor >= bf->code_size) {
        vm_error("Unexpected end of bytecode at offset 0x%x (code size: %u)",
                 insn_ip, bf->code_size);
    }
    return bf->code_ptr[(*cursor)++];
}

static inline int32_t read_int32(const bytefile *bf, uint32_t *cursor, uint32_t insn_ip) {
    if ((uint64_t)(*cursor) + sizeof(int32_t) > bf->code_size) {
        vm_error("Unexpected end of bytecode while reading int32 at offset 0x%x (code size: %u)",
                 insn_ip, bf->code_size);
    }
    int32_t value;
    memcpy(&value, bf->code_ptr + *cursor, sizeof(value));
    *cursor += (uint32_t)sizeof(int32_t);
    return value;
}

static inline const char *get_string(const bytefile *bf, int32_t pos, uint32_t insn_ip) {
    if (pos < 0 || (uint32_t)pos >= bf->stringtab_size) {
        vm_error("String offset %d out of bounds at instruction offset 0x%x", pos, insn_ip);
    }
    return &bf->string_ptr[pos];
}

static inline uint32_t check_target(const bytefile *bf, int32_t target, uint32_t insn_ip) {
    if (target < 0 || (uint32_t)target >= bf->code_size) {
        vm_error("Control-flow target %d out of bounds at instruction offset 0x%x",
                 target, insn_ip);
    }
    return (uint32_t)target;
}

static inline void check_non_negative(int32_t val, const char *what, uint32_t insn_ip) {
    if (val < 0) {
        vm_error("Negative %s %d at offset 0x%x", what, val, insn_ip);
    }
}

static inline const public_entry *get_public_entry(const bytefile *bf, uint32_t i) {
    if (i >= bf->public_symbols_number) {
        vm_error("Public symbol index %u out of bounds", i);
    }
    return (const public_entry *)(bf->public_ptr + (size_t)i * sizeof(public_entry));
}

uint32_t get_public_offset(const bytefile *bf, uint32_t i) {
    int32_t off = get_public_entry(bf, i)->offset;
    if (off < 0 || (uint32_t)off >= bf->code_size) {
        vm_error("Public symbol #%u offset %d out of code bounds", i, off);
    }
    return (uint32_t)off;
}

const char *get_public_name(const bytefile *bf, uint32_t i) {
    int32_t name_off = get_public_entry(bf, i)->name_offset;
    if (name_off < 0 || (uint32_t)name_off >= bf->stringtab_size) {
        vm_error("Public symbol #%u name offset %d out of string table bounds", i, name_off);
    }
    return &bf->string_ptr[name_off];
}

// Загружает файл целиком и парсит смещения секций
bytefile *read_file(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) vm_error("Cannot open file '%s': %s", fname, strerror(errno));

    if (fseeko(f, 0, SEEK_END) != 0) {
        int err = errno;
        fclose(f);
        vm_error("fseeko failed on '%s': %s", fname, strerror(err));
    }
    off_t file_size = ftello(f);
    if (file_size < 0) {
        int err = errno;
        fclose(f);
        vm_error("ftello failed on '%s': %s", fname, strerror(err));
    }
    rewind(f);

    if (file_size < (off_t)sizeof(file_header)) {
        fclose(f);
        vm_error("Corrupted file '%s': size (%lld bytes) is smaller than header (%zu bytes)",
                 fname, (long long)file_size, sizeof(file_header));
    }
    if ((uint64_t)file_size > (uint64_t)SIZE_MAX) {
        fclose(f);
        vm_error("File '%s' is too large (%lld bytes)", fname, (long long)file_size);
    }

    char *raw = (char *)malloc((size_t)file_size);
    if (!raw) {
        fclose(f);
        vm_error("Out of memory");
    }

    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(raw);
        fclose(f);
        vm_error("Failed to read file '%s'", fname);
    }
    fclose(f);

    file_header hdr;
    memcpy(&hdr, raw, sizeof(hdr));
    int32_t st_size   = hdr.st_size;
    int32_t glob_size = hdr.glob_size;
    int32_t pub_num   = hdr.pub_num;

    if (st_size < 0 || glob_size < 0 || pub_num < 0) {
        free(raw);
        vm_error("Corrupted header: negative field (stringtab=%d, globals=%d, publics=%d)",
                 (int)st_size, (int)glob_size, (int)pub_num);
    }

    // Защита от краша при переполнении int, если файл битый
    uint64_t pub_bytes = (uint64_t)(uint32_t)pub_num * sizeof(public_entry);
    uint64_t header_and_tables = sizeof(file_header) + pub_bytes + (uint64_t)(uint32_t)st_size;

    if (header_and_tables > (uint64_t)file_size) {
        free(raw);
        vm_error("Corrupted header: tables size (%llu) exceeds file size (%lld)",
                 (unsigned long long)header_and_tables, (long long)file_size);
    }

    uint64_t code_bytes = (uint64_t)file_size - header_and_tables;
    if (code_bytes == 0) {
        free(raw);
        vm_error("Corrupted bytecode: empty code section");
    }
    if (code_bytes > (uint64_t)UINT32_MAX) {
        free(raw);
        vm_error("Code section in '%s' is too large (%llu bytes)",
                 fname, (unsigned long long)code_bytes);
    }

    bytefile *bf = (bytefile *)calloc(1, sizeof(bytefile));
    if (!bf) {
        free(raw);
        vm_error("Out of memory");
    }

    bf->filename              = fname;
    bf->raw_data              = raw;
    bf->stringtab_size        = (uint32_t)st_size;
    bf->global_area_size      = (uint32_t)glob_size;
    bf->public_symbols_number = (uint32_t)pub_num;
    bf->public_ptr            = raw + sizeof(file_header);
    bf->string_ptr            = bf->public_ptr + pub_bytes;
    bf->code_ptr              = (const uint8_t *)(bf->string_ptr + st_size);
    bf->code_size             = (uint32_t)code_bytes;

    if (bf->stringtab_size > 0 && bf->string_ptr[bf->stringtab_size - 1] != '\0') {
        close_file(bf);
        vm_error("Corrupted string table: not null-terminated");
    }

    for (uint32_t i = 0; i < bf->public_symbols_number; ++i) {
        (void)get_public_name(bf, i);
        (void)get_public_offset(bf, i);
    }

    return bf;
}

void close_file(bytefile *bf) {
    if (!bf) return;
    free(bf->raw_data);
    free(bf);
}

static void print_var_designator(FILE *f, uint8_t loc, int32_t idx) {
    static const char loc_chars[] = {'G', 'L', 'A', 'C'};
    fprintf(f, "%c(%d)", loc_chars[loc], idx);
}

// Доработанный дизассемблер из byterun.c с проверками.
// Если f == NULL, только проверяет инструкцию и возвращает её свойства для анализатора.
static insn_info parse_insn(FILE *f, const bytefile *bf, uint32_t ip) {
    static const char *const ops[]  = {"+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "!!"};
    static const char *const pats[] = {"=str", "#string", "#array", "#sexp", "#ref", "#val", "#fun"};
    static const char *const lds[]  = {"LD", "LDA", "ST"};

    uint32_t cursor = ip;
    uint8_t  op     = read_byte(bf, &cursor, ip);
    uint8_t  h      = (op & 0xF0u) >> 4;
    uint8_t  l      = op & 0x0Fu;

    insn_info info = {
        .length        = 0,
        .target        = 0,
        .has_target    = false,
        .falls_through = true,
        .is_call       = false
    };

    if (h == H_BINOP) {
        if (l < 1 || l > 13) {
            vm_error("Unknown binary opcode 0x%02x at offset 0x%x", op, ip);
        }
        if (f) fprintf(f, "BINOP\t%s", ops[l - 1]);
    } else if (h == H_LD || h == H_LDA || h == H_ST) {
        if (l > VAR_CLOSURE) {
            vm_error("Unknown variable location in opcode 0x%02x at offset 0x%x", op, ip);
        }
        int32_t idx = read_int32(bf, &cursor, ip);
        check_non_negative(idx, "variable index", ip);
        if (f) {
            fprintf(f, "%s\t", lds[h - H_LD]);
            print_var_designator(f, l, idx);
        }
    } else if (h == H_PATT) {
        if (l > 6) {
            vm_error("Unknown pattern opcode 0x%02x at offset 0x%x", op, ip);
        }
        if (f) fprintf(f, "PATT\t%s", pats[l]);
    } else {
        switch (op) {
            case OP_CONST: {
                int32_t val = read_int32(bf, &cursor, ip);
                if (f) fprintf(f, "CONST\t%d", val);
                break;
            }

            case OP_STRING: {
                int32_t pos = read_int32(bf, &cursor, ip);
                const char *s = get_string(bf, pos, ip);
                if (f) fprintf(f, "STRING\t%s", s);
                break;
            }

            case OP_SEXP: {
                int32_t pos = read_int32(bf, &cursor, ip);
                int32_t n   = read_int32(bf, &cursor, ip);
                const char *s = get_string(bf, pos, ip);
                check_non_negative(n, "sexp arity", ip);
                if (f) fprintf(f, "SEXP\t%s %d", s, n);
                break;
            }

            case OP_STI:  if (f) fputs("STI", f); break;
            case OP_STA:  if (f) fputs("STA", f); break;
            case OP_DROP: if (f) fputs("DROP", f); break;
            case OP_DUP:  if (f) fputs("DUP", f); break;
            case OP_SWAP: if (f) fputs("SWAP", f); break;
            case OP_ELEM: if (f) fputs("ELEM", f); break;

            case OP_JMP: {
                uint32_t tgt = check_target(bf, read_int32(bf, &cursor, ip), ip);
                info.target        = tgt;
                info.has_target    = true;
                info.falls_through = false;
                if (f) fprintf(f, "JMP\t0x%.8x", tgt);
                break;
            }

            case OP_END:
                info.falls_through = false;
                if (f) fputs("END", f);
                break;

            case OP_RET:
                info.falls_through = false;
                if (f) fputs("RET", f);
                break;

            case OP_CJMPZ:
            case OP_CJMPNZ: {
                uint32_t tgt = check_target(bf, read_int32(bf, &cursor, ip), ip);
                info.target        = tgt;
                info.has_target    = true;
                info.falls_through = true;
                if (f) fprintf(f, "%s\t0x%.8x", op == OP_CJMPZ ? "CJMPz" : "CJMPnz", tgt);
                break;
            }

            case OP_BEGIN:
            case OP_CBEGIN: {
                int32_t nargs   = read_int32(bf, &cursor, ip);
                int32_t nlocals = read_int32(bf, &cursor, ip);
                check_non_negative(nargs, "nargs", ip);
                check_non_negative(nlocals, "nlocals", ip);
                if (f) fprintf(f, "%s\t%d %d", op == OP_BEGIN ? "BEGIN" : "CBEGIN", nargs, nlocals);
                break;
            }

            case OP_CLOSURE: {
                uint32_t tgt = check_target(bf, read_int32(bf, &cursor, ip), ip);
                int32_t  n   = read_int32(bf, &cursor, ip);
                check_non_negative(n, "closure size", ip);
                info.target     = tgt;
                info.has_target = true;

                if (f) fprintf(f, "CLOSURE\t0x%.8x", tgt);
                for (int32_t i = 0; i < n; ++i) {
                    uint8_t loc = read_byte(bf, &cursor, ip);
                    int32_t idx = read_int32(bf, &cursor, ip);
                    if (loc > VAR_CLOSURE) {
                        vm_error("Unknown variable location in CLOSURE at offset 0x%x", ip);
                    }
                    check_non_negative(idx, "captured variable index", ip);
                    if (f) {
                        fputc(' ', f);
                        print_var_designator(f, loc, idx);
                    }
                }
                break;
            }

            case OP_CALLC: {
                int32_t nargs = read_int32(bf, &cursor, ip);
                check_non_negative(nargs, "callc argc", ip);
                info.falls_through = true;
                info.is_call       = true;
                if (f) fprintf(f, "CALLC\t%d", nargs);
                break;
            }

            case OP_CALL: {
                uint32_t tgt   = check_target(bf, read_int32(bf, &cursor, ip), ip);
                int32_t  nargs = read_int32(bf, &cursor, ip);
                check_non_negative(nargs, "call argc", ip);
                info.target        = tgt;
                info.has_target    = true;
                info.falls_through = true;
                info.is_call       = true;
                if (f) fprintf(f, "CALL\t0x%.8x %d", tgt, nargs);
                break;
            }

            case OP_TAG: {
                int32_t pos = read_int32(bf, &cursor, ip);
                int32_t n   = read_int32(bf, &cursor, ip);
                const char *s = get_string(bf, pos, ip);
                check_non_negative(n, "tag arity", ip);
                if (f) fprintf(f, "TAG\t%s %d", s, n);
                break;
            }

            case OP_ARRAY: {
                int32_t n = read_int32(bf, &cursor, ip);
                check_non_negative(n, "array size", ip);
                if (f) fprintf(f, "ARRAY\t%d", n);
                break;
            }

            case OP_FAIL: {
                int32_t line = read_int32(bf, &cursor, ip);
                int32_t col  = read_int32(bf, &cursor, ip);
                info.falls_through = false;
                if (f) fprintf(f, "FAIL\t%d %d", line, col);
                break;
            }

            case OP_LINE: {
                int32_t line = read_int32(bf, &cursor, ip);
                if (f) fprintf(f, "LINE\t%d", line);
                break;
            }

            case OP_CALL_READ:   if (f) fputs("CALL\tread", f); break;
            case OP_CALL_WRITE:  if (f) fputs("CALL\twrite", f); break;
            case OP_CALL_LENGTH: if (f) fputs("CALL\tlength", f); break;
            case OP_CALL_STRING: if (f) fputs("CALL\tstring", f); break;

            case OP_CALL_ARRAY: {
                int32_t n = read_int32(bf, &cursor, ip);
                check_non_negative(n, "array size", ip);
                if (f) fprintf(f, "CALL\t.array\t%d", n);
                break;
            }

            case OP_STOP:
                info.falls_through = false;
                if (f) fputs("STOP", f);
                break;

            default:
                vm_error("Unknown opcode 0x%02x at offset 0x%x", op, ip);
        }
    }

    info.length = cursor - ip;
    return info;
}

insn_info decode_insn(const bytefile *bf, uint32_t ip) {
    return parse_insn(NULL, bf, ip);
}

uint32_t disassemble_insn(FILE *f, const bytefile *bf, uint32_t ip) {
    insn_info info = parse_insn(f, bf, ip);
    return ip + info.length;
}