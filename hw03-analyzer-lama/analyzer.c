#define _GNU_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

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

typedef struct {
    const char *filename;
    int   stringtab_size;
    int   global_area_size;
    int   public_symbols_number;
    const char *public_ptr;
    const char *string_ptr;
    const char *code_ptr;
    int   code_size;
    char *raw_data;
} bytefile;

_Noreturn static void vm_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "VM Error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

static inline unsigned char read_byte(const bytefile *bf, int *ip_offset) {
    if (*ip_offset < 0 || *ip_offset >= bf->code_size) {
        vm_error("Unexpected end of bytecode at offset 0x%x (code size: %d)",
                 *ip_offset, bf->code_size);
    }
    unsigned char b = (unsigned char)bf->code_ptr[*ip_offset];
    (*ip_offset) += 1;
    return b;
}

static inline int read_int32(const bytefile *bf, int *ip_offset) {
    if (*ip_offset < 0 || *ip_offset + (int)sizeof(int32_t) > bf->code_size) {
        vm_error("Unexpected end of bytecode while reading int32 at offset 0x%x (code size: %d)",
                 *ip_offset, bf->code_size);
    }
    int32_t val = 0;
    memcpy(&val, bf->code_ptr + *ip_offset, sizeof(int32_t));
    (*ip_offset) += (int)sizeof(int32_t);
    return (int)val;
}

static inline const char *get_string(const bytefile *bf, int offset, int insn_offset) {
    if (offset < 0 || offset >= bf->stringtab_size) {
        vm_error("String offset %d out of bounds [0, %d) at instruction offset 0x%x",
                 offset, bf->stringtab_size, insn_offset);
    }
    return &bf->string_ptr[offset];
}

static inline const public_entry *get_public_entry(const bytefile *bf, int i) {
    return (const public_entry *)(bf->public_ptr + (size_t)i * sizeof(public_entry));
}

static inline int get_public_offset(const bytefile *bf, int i) {
    return (int)get_public_entry(bf, i)->offset;
}

// Загружает файл целиком и парсит смещения секций
static bytefile *read_file(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) vm_error("Cannot open file '%s': %s", fname, strerror(errno));

    if (fseeko(f, 0, SEEK_END) != 0) {
        vm_error("fseeko failed on '%s': %s", fname, strerror(errno));
    }
    off_t file_size = ftello(f);
    if (file_size < 0) {
        vm_error("ftello failed on '%s': %s", fname, strerror(errno));
    }
    rewind(f);

    if (file_size < (off_t)sizeof(file_header)) {
        vm_error("Corrupted file '%s': size (%lld bytes) is smaller than header (%zu bytes)",
                 fname, (long long)file_size, sizeof(file_header));
    }
    if ((uint64_t)file_size > (uint64_t)INT32_MAX) {
        vm_error("File '%s' is too large (%lld bytes): bytecode offsets are 32-bit signed integers",
                 fname, (long long)file_size);
    }

    char *raw = (char *)malloc((size_t)file_size);
    if (!raw) vm_error("Out of memory allocating %lld bytes", (long long)file_size);

    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        vm_error("Failed to read file '%s'", fname);
    }
    fclose(f);

    bytefile *bf = (bytefile *)calloc(1, sizeof(bytefile));
    if (!bf) vm_error("Out of memory");

    bf->filename = fname;
    bf->raw_data = raw;

    const file_header *hdr = (const file_header *)raw;
    int32_t st_size   = hdr->st_size;
    int32_t glob_size = hdr->glob_size;
    int32_t pub_num   = hdr->pub_num;

    if (st_size < 0 || glob_size < 0 || pub_num < 0) {
        vm_error("Corrupted header: negative field (stringtab=%d, globals=%d, publics=%d)", 
                 (int)st_size, (int)glob_size, (int)pub_num);
    }

    // Защита от краша при переполнении int, если файл битый
    int64_t pub_bytes = (int64_t)pub_num * (int64_t)sizeof(public_entry);
    int64_t header_and_tables = (int64_t)sizeof(file_header) + pub_bytes + (int64_t)st_size;

    if (header_and_tables > (int64_t)file_size) {
        vm_error("Corrupted header: tables size (%lld) exceeds file size (%lld)", 
                 (long long)header_and_tables, (long long)file_size);
    }

    bf->stringtab_size        = (int)st_size;
    bf->global_area_size      = (int)glob_size;
    bf->public_symbols_number = (int)pub_num;
    bf->public_ptr            = raw + sizeof(file_header);
    bf->string_ptr            = bf->public_ptr + pub_bytes;
    bf->code_ptr              = bf->string_ptr + st_size;
    bf->code_size             = (int)((int64_t)file_size - header_and_tables);

    if (bf->code_size <= 0) vm_error("Corrupted bytecode: empty code section");

    if (bf->stringtab_size > 0 && bf->string_ptr[bf->stringtab_size - 1] != '\0') {
        vm_error("Corrupted string table: not null-terminated");
    }

    return bf;
}

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

typedef struct {
    int ip;
    char str[256];     // Буфер с запасом под список захваченных переменных в CLOSURE
    int is_terminator; // Разрывает цепочку после себя (JMP, RET, FAIL, STOP, CJMP)
    int is_label;      // Точка входа (цель прыжка/вызова или паблик)
    int is_ignored;    // Служебные инструкции (LINE)
} Instruction;

typedef struct {
    char *str;
    int count;
} Freq;

static int compare_str(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

static int compare_freq(const void *a, const void *b) {
    Freq *fa = (Freq *)a;
    Freq *fb = (Freq *)b;
    if (fa->count != fb->count) return fb->count - fa->count;
    return strcmp(fa->str, fb->str);
}

static void count_and_print(char **ngrams, int count, const char *title) {
    if (count == 0) return;
    
    qsort(ngrams, count, sizeof(char*), compare_str);

    Freq *freqs = malloc(count * sizeof(Freq));
    if (!freqs) vm_error("Out of memory in analyzer");
    int unique = 0;

    freqs[0].str = ngrams[0];
    freqs[0].count = 1;
    unique = 1;

    for (int i = 1; i < count; ++i) {
        if (strcmp(ngrams[i], ngrams[i-1]) == 0) {
            freqs[unique-1].count++;
        } else {
            freqs[unique].str = ngrams[i];
            freqs[unique].count = 1;
            unique++;
        }
    }

    qsort(freqs, unique, sizeof(Freq), compare_freq);

    printf("\n=== %s ===\n", title);
    for (int i = 0; i < unique; ++i) {
        printf("%8d  %s\n", freqs[i].count, freqs[i].str);
    }
    free(freqs);
}

static void analyze_bytecode(const bytefile *bf) {
    Instruction *insns = calloc(bf->code_size, sizeof(Instruction));
    uint8_t *is_label_map = calloc(bf->code_size, 1);
    if (!insns || !is_label_map) vm_error("Out of memory in analyzer");

    int insn_count = 0;
    
    // Все экспортируемые функции - безусловные точки входа
    for (int i = 0; i < bf->public_symbols_number; ++i) {
        int offset = get_public_offset(bf, i);
        if (offset >= 0 && offset < bf->code_size) {
            is_label_map[offset] = 1;
        }
    }

    int ip = 0;
    
    // Парсим инструкции и собираем адреса переходов
    while (ip < bf->code_size) {
        int start_ip = ip;
        unsigned char op = read_byte(bf, &ip);
        unsigned char h  = (op & 0xF0) >> 4;
        unsigned char l  = op & 0x0F;

        Instruction *ins = &insns[insn_count++];
        ins->ip = start_ip;

        if (h == H_BINOP) {
            static const char* binops[] = {"+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "||"};
            snprintf(ins->str, sizeof(ins->str), "BINOP %s", binops[l-1]);
        } 
        else if (h == H_LD || h == H_LDA || h == H_ST) {
            int idx = read_int32(bf, &ip);
            const char* op_name = (h == H_LD) ? "LD" : (h == H_LDA) ? "LDA" : "ST";
            const char* loc_name = (l == VAR_GLOBAL) ? "G" : (l == VAR_LOCAL) ? "L" : (l == VAR_ARG) ? "A" : "C";
            snprintf(ins->str, sizeof(ins->str), "%s %s[%d]", op_name, loc_name, idx);
        }
        else if (h == H_PATT) {
            snprintf(ins->str, sizeof(ins->str), "PATT %d", l);
        } 
        else {
            switch (op) {
                case OP_CONST: snprintf(ins->str, sizeof(ins->str), "CONST %d", read_int32(bf, &ip)); break;
                case OP_STRING: {
                    int offset = read_int32(bf, &ip);
                    const char *s = get_string(bf, offset, start_ip);
                    
                    // Экранируем \n, \t, \r
                    char esc[64];
                    int epos = 0;
                    for (int si = 0; s[si] != '\0' && epos < 30; ++si) {
                        if (s[si] == '\n')      { esc[epos++] = '\\'; if (epos < 30) esc[epos++] = 'n'; }
                        else if (s[si] == '\t') { esc[epos++] = '\\'; if (epos < 30) esc[epos++] = 't'; }
                        else if (s[si] == '\r') { esc[epos++] = '\\'; if (epos < 30) esc[epos++] = 'r'; }
                        else esc[epos++] = s[si];
                    }
                    esc[epos] = '\0';
                    snprintf(ins->str, sizeof(ins->str), "STRING '%s%s'", esc, strlen(s) > 30 ? "..." : "");
                    break;
                }
                case OP_SEXP: {
                    int tag_offset = read_int32(bf, &ip);
                    int n = read_int32(bf, &ip);
                    const char *tag = get_string(bf, tag_offset, start_ip);
                    snprintf(ins->str, sizeof(ins->str), "SEXP '%s' %d", tag, n);
                    break;
                }
                case OP_STI: snprintf(ins->str, sizeof(ins->str), "STI"); break;
                case OP_STA: snprintf(ins->str, sizeof(ins->str), "STA"); break;
                case OP_JMP: {
                    int target = read_int32(bf, &ip);
                    if (target >= 0 && target < bf->code_size) is_label_map[target] = 1;
                    ins->is_terminator = 1;
                    snprintf(ins->str, sizeof(ins->str), "JMP"); // target опускаем, чтобы одинаковые прыжки схлопывались
                    break;
                }
                case OP_END: ins->is_terminator = 1; snprintf(ins->str, sizeof(ins->str), "END"); break;
                case OP_RET: ins->is_terminator = 1; snprintf(ins->str, sizeof(ins->str), "RET"); break;
                case OP_DROP: snprintf(ins->str, sizeof(ins->str), "DROP"); break;
                case OP_DUP:  snprintf(ins->str, sizeof(ins->str), "DUP"); break;
                case OP_SWAP: snprintf(ins->str, sizeof(ins->str), "SWAP"); break;
                case OP_ELEM: snprintf(ins->str, sizeof(ins->str), "ELEM"); break;
                case OP_CJMPZ: 
                case OP_CJMPNZ: {
                    int target = read_int32(bf, &ip);
                    if (target >= 0 && target < bf->code_size) is_label_map[target] = 1;
                    ins->is_terminator = 1;
                    snprintf(ins->str, sizeof(ins->str), "CJMP%s", op == OP_CJMPZ ? "Z" : "NZ");
                    break;
                }
                case OP_BEGIN:
                case OP_CBEGIN: {
                    int nargs = read_int32(bf, &ip);
                    int nlocals = read_int32(bf, &ip);
                    snprintf(ins->str, sizeof(ins->str), "%s %d %d", op == OP_BEGIN ? "BEGIN" : "CBEGIN", nargs, nlocals);
                    break;
                }
                case OP_CLOSURE: {
                    int target = read_int32(bf, &ip);
                    int n = read_int32(bf, &ip);
                    if (target >= 0 && target < bf->code_size) is_label_map[target] = 1;
                    int len = snprintf(ins->str, sizeof(ins->str), "CLOSURE (arity: %d)", n);
                    for (int i = 0; i < n; ++i) {
                        unsigned char dtype = read_byte(bf, &ip);
                        int idx = read_int32(bf, &ip);
                        if (len < (int)sizeof(ins->str)) {
                            len += snprintf(ins->str + len, sizeof(ins->str) - len, " %d:%d", dtype, idx);
                        }
                    }
                    break;
                }
                case OP_CALLC: snprintf(ins->str, sizeof(ins->str), "CALLC %d", read_int32(bf, &ip)); break;
                case OP_CALL: {
                    int target = read_int32(bf, &ip);
                    int argc = read_int32(bf, &ip);
                    if (target >= 0 && target < bf->code_size) is_label_map[target] = 1;
                    snprintf(ins->str, sizeof(ins->str), "CALL (argc: %d)", argc);
                    break;
                }
                case OP_TAG: {
                    int tag_offset = read_int32(bf, &ip);
                    int n = read_int32(bf, &ip);
                    const char *tag = get_string(bf, tag_offset, start_ip);
                    snprintf(ins->str, sizeof(ins->str), "TAG '%s' %d", tag, n);
                    break;
                }
                case OP_ARRAY: snprintf(ins->str, sizeof(ins->str), "ARRAY %d", read_int32(bf, &ip)); break;
                case OP_FAIL: {
                    int line = read_int32(bf, &ip);
                    int col = read_int32(bf, &ip);
                    ins->is_terminator = 1;
                    snprintf(ins->str, sizeof(ins->str), "FAIL %d:%d", line, col);
                    break;
                }
                case OP_LINE: {
                    read_int32(bf, &ip);
                    snprintf(ins->str, sizeof(ins->str), "LINE");
                    ins->is_ignored = 1; // Пропускаем чтобы не рвать реальные идиомы
                    break;
                }
                case OP_CALL_READ:   snprintf(ins->str, sizeof(ins->str), "CALL_READ"); break;
                case OP_CALL_WRITE:  snprintf(ins->str, sizeof(ins->str), "CALL_WRITE"); break;
                case OP_CALL_LENGTH: snprintf(ins->str, sizeof(ins->str), "CALL_LENGTH"); break;
                case OP_CALL_STRING: snprintf(ins->str, sizeof(ins->str), "CALL_STRING"); break;
                case OP_CALL_ARRAY:  snprintf(ins->str, sizeof(ins->str), "CALL_ARRAY %d", read_int32(bf, &ip)); break;
                case OP_STOP: ins->is_terminator = 1; snprintf(ins->str, sizeof(ins->str), "STOP"); break;
                default: snprintf(ins->str, sizeof(ins->str), "UNKNOWN_0x%02x", op); break;
            }
        }
    }

    // Сбор n-грамм
    char **ngrams1 = malloc(insn_count * sizeof(char*));
    char **ngrams2 = malloc(insn_count * sizeof(char*));
    if (!ngrams1 || !ngrams2) vm_error("Out of memory for N-grams");
    
    int n1_count = 0, n2_count = 0;
    int last_valid_idx = -1;
    int propagate_label = 0;

    for (int i = 0; i < insn_count; ++i) {
        if (is_label_map[insns[i].ip]) propagate_label = 1;

        if (insns[i].is_ignored) continue;

        if (propagate_label) {
            insns[i].is_label = 1;
            propagate_label = 0;
        }

        ngrams1[n1_count++] = insns[i].str;

        if (last_valid_idx != -1) {
            if (!insns[last_valid_idx].is_terminator && !insns[i].is_label) {
                size_t len = strlen(insns[last_valid_idx].str) + strlen(insns[i].str) + 5;
                char *buf = malloc(len);
                if (buf) {
                    snprintf(buf, len, "%s -> %s", insns[last_valid_idx].str, insns[i].str);
                    ngrams2[n2_count++] = buf;
                }
            }
        }
        last_valid_idx = i;
    }

    count_and_print(ngrams1, n1_count, "Top 1-grams");
    count_and_print(ngrams2, n2_count, "Top 2-grams");

    for (int i = 0; i < n2_count; ++i) free(ngrams2[i]);
    free(ngrams1);
    free(ngrams2);
    free(insns);
    free(is_label_map);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.bc>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bytefile *bf = read_file(argv[1]);
    analyze_bytecode(bf);

    free(bf->raw_data);
    free(bf);
    return EXIT_SUCCESS;
}