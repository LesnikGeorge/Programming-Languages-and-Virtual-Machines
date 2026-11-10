#define _GNU_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>


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

static void *checked_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr && size != 0) vm_error("Out of memory");
    return ptr;
}

static void *checked_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (!ptr && count != 0 && size != 0) vm_error("Out of memory");
    return ptr;
}

static inline int32_t read_int32_at(const bytefile *bf, int offset, int insn_offset) {
    if (offset < 0 || (int64_t)offset + (int64_t)sizeof(int32_t) > bf->code_size) {
        vm_error("Unexpected end of bytecode while reading int32 at offset 0x%x (code size: %d)",
                 insn_offset, bf->code_size);
    }

    int32_t value;
    memcpy(&value, bf->code_ptr + offset, sizeof(value));
    return value;
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

    char *raw = (char *)checked_malloc((size_t)file_size);
    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        vm_error("Failed to read file '%s'", fname);
    }
    fclose(f);

    bytefile *bf = (bytefile *)checked_calloc(1, sizeof(bytefile));
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

// Учитываем все возможные одиночные ключи и пары байтовых ключей
#define NGRAM_KEY_COUNT (256 + 256 * 256)
#define NGRAM_PAIR_BASE 256

typedef struct {
    uint64_t count;
    uint8_t used;
} NgramFreq;

typedef struct {
    int ip;
    int next_ip;
    int target;
    uint8_t key;
    uint8_t is_branch;
    uint8_t is_conditional;
    uint8_t is_terminal;
    uint8_t has_target;
} DecodedInsn;

typedef struct {
    int *data;
    size_t count;
    size_t capacity;
} IntQueue;

static void queue_push(IntQueue *queue, int value) {
    if (queue->count == queue->capacity) {
        size_t new_capacity = queue->capacity == 0 ? 64 : queue->capacity * 2;
        if (new_capacity < queue->capacity ||
            new_capacity > SIZE_MAX / sizeof(int)) {
            vm_error("Too many reachable instructions");
        }

        int *new_data = (int *)realloc(queue->data, new_capacity * sizeof(int));
        if (!new_data) vm_error("Out of memory in analyzer");

        queue->data = new_data;
        queue->capacity = new_capacity;
    }

    queue->data[queue->count++] = value;
}

static int queue_pop(IntQueue *queue, size_t *head) {
    return queue->data[(*head)++];
}

static void check_target(const bytefile *bf, int target, int insn_ip) {
    if (target < 0 || target >= bf->code_size) {
        vm_error("Control-flow target %d out of bounds at instruction offset 0x%x",
                 target, insn_ip);
    }
}

// Читает только длину инструкции и необходимые для CFG адреса.
// Значения операндов не участвуют в ключе инструкции.
static DecodedInsn decode_instruction(const bytefile *bf, int ip) {
    if (ip < 0 || ip >= bf->code_size) {
        vm_error("Instruction offset 0x%x out of code bounds", ip);
    }

    DecodedInsn ins;
    memset(&ins, 0, sizeof(ins));
    ins.ip = ip;
    ins.target = -1;
    ins.key = (uint8_t)bf->code_ptr[ip];

    unsigned char op = (unsigned char)bf->code_ptr[ip];
    unsigned char h = (op & 0xF0) >> 4;
    unsigned char l = op & 0x0F;
    int cursor = ip + 1;

    if (h == H_BINOP) {
        if (l < 1 || l > 13) {
            vm_error("Unknown binary opcode 0x%02x at offset 0x%x", op, ip);
        }
    } else if (h == H_LD || h == H_LDA || h == H_ST) {
        if (l > VAR_CLOSURE) {
            vm_error("Unknown variable location in opcode 0x%02x at offset 0x%x", op, ip);
        }
        (void)read_int32_at(bf, cursor, ip);
        cursor += 4;
    } else if (h == H_PATT) {
        if (l > 6) {
            vm_error("Unknown pattern opcode 0x%02x at offset 0x%x", op, ip);
        }
    } else {
        switch (op) {
            case OP_CONST:
            case OP_STRING:
            case OP_JMP:
            case OP_CJMPZ:
            case OP_CJMPNZ:
            case OP_CALLC:
            case OP_ARRAY:
            case OP_LINE:
            case OP_CALL_ARRAY:
                (void)read_int32_at(bf, cursor, ip);
                if (op == OP_JMP || op == OP_CJMPZ || op == OP_CJMPNZ) {
                    ins.target = (int)read_int32_at(bf, cursor, ip);
                    ins.has_target = 1;
                    ins.is_branch = 1;
                    ins.is_conditional = (op != OP_JMP);
                    check_target(bf, ins.target, ip);
                }
                cursor += 4;
                break;

            case OP_SEXP:
            case OP_BEGIN:
            case OP_CBEGIN:
            case OP_TAG:
                (void)read_int32_at(bf, cursor, ip);
                (void)read_int32_at(bf, cursor + 4, ip);
                cursor += 8;
                break;

            case OP_CALL: {
                ins.target = (int)read_int32_at(bf, cursor, ip);
                (void)read_int32_at(bf, cursor + 4, ip);
                ins.has_target = 1;
                check_target(bf, ins.target, ip);
                cursor += 8;
                break;
            }

            case OP_CLOSURE: {
                int target = (int)read_int32_at(bf, cursor, ip);
                int n = (int)read_int32_at(bf, cursor + 4, ip);
                if (n < 0) vm_error("Negative closure size %d at offset 0x%x", n, ip);
                check_target(bf, target, ip);

                int64_t end = (int64_t)cursor + 8 + (int64_t)n * 5;
                if (end > bf->code_size) {
                    vm_error("Unexpected end of bytecode while reading CLOSURE at offset 0x%x",
                             ip);
                }

                ins.target = target;
                ins.has_target = 1;
                cursor = (int)end;
                break;
            }

            case OP_FAIL:
                (void)read_int32_at(bf, cursor, ip);
                (void)read_int32_at(bf, cursor + 4, ip);
                cursor += 8;
                ins.is_terminal = 1;
                break;

            case OP_END:
            case OP_RET:
            case OP_STOP:
                ins.is_terminal = 1;
                break;

            case OP_STI:
            case OP_STA:
            case OP_DROP:
            case OP_DUP:
            case OP_SWAP:
            case OP_ELEM:
            case OP_CALL_READ:
            case OP_CALL_WRITE:
            case OP_CALL_LENGTH:
            case OP_CALL_STRING:
                break;

            default:
                vm_error("Unknown opcode 0x%02x at offset 0x%x", op, ip);
        }
    }

    if (op == OP_JMP) ins.is_terminal = 1;

    if (cursor > bf->code_size) {
        vm_error("Instruction at offset 0x%x extends beyond code section", ip);
    }
    if (cursor == ip) {
        vm_error("Invalid instruction size at offset 0x%x", ip);
    }

    ins.next_ip = cursor;
    return ins;
}

// Обходит достижимый код от публичных символов и отмечает начала инструкций
static uint8_t *find_reachable_code(const bytefile *bf, uint8_t *labels) {
    uint8_t *starts = (uint8_t *)checked_calloc((size_t)bf->code_size, 1);
    IntQueue queue = {0};
    size_t head = 0;

    for (int i = 0; i < bf->public_symbols_number; ++i) {
        int offset = get_public_offset(bf, i);
        check_target(bf, offset, -1);
        labels[offset] = 1;
        queue_push(&queue, offset);
    }

    while (head < queue.count) {
        int ip = queue_pop(&queue, &head);
        if (starts[ip]) continue;

        DecodedInsn ins = decode_instruction(bf, ip);
        starts[ip] = 1;

        if (ins.has_target) {
            labels[ins.target] = 1;
            queue_push(&queue, ins.target);
        }

        if (ins.is_branch && !ins.is_conditional) {
            continue;
        }

        if (!ins.is_terminal && ins.next_ip < bf->code_size) {
            queue_push(&queue, ins.next_ip);
        }
    }

    free(queue.data);
    return starts;
}

static unsigned int make_pair_key(uint8_t first, uint8_t second) {
    return NGRAM_PAIR_BASE + ((unsigned int)first << 8) + second;
}

static void add_frequency(NgramFreq *freqs, unsigned int key) {
    if (key >= NGRAM_KEY_COUNT) {
        vm_error("Internal error: n-gram key out of range");
    }

    freqs[key].used = 1;
    if (freqs[key].count == UINT64_MAX) {
        vm_error("Frequency counter overflow");
    }
    freqs[key].count++;
}

static const char *opcode_name(unsigned char op) {
    static char name[32];

    unsigned char h = (op & 0xF0) >> 4;
    unsigned char l = op & 0x0F;

    if (h == H_BINOP) {
        static const char *binops[] = {
            "INVALID", "+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "||"
        };
        return binops[l];
    }

    if (h == H_LD || h == H_LDA || h == H_ST) {
        static const char *locations[] = {"G", "L", "A", "C"};
        const char *kind = h == H_LD ? "LD" : h == H_LDA ? "LDA" : "ST";
        snprintf(name, sizeof(name), "%s_%s", kind, locations[l]);
        return name;
    }

    if (h == H_PATT) {
        static const char *patterns[] = {
            "PATT_STRCMP", "PATT_STRING", "PATT_ARRAY", "PATT_SEXP",
            "PATT_BOXED", "PATT_UNBOXED", "PATT_CLOSURE"
        };
        return patterns[l];
    }

    switch (op) {
        case OP_CONST: return "CONST";
        case OP_STRING: return "STRING";
        case OP_SEXP: return "SEXP";
        case OP_STI: return "STI";
        case OP_STA: return "STA";
        case OP_JMP: return "JMP";
        case OP_END: return "END";
        case OP_RET: return "RET";
        case OP_DROP: return "DROP";
        case OP_DUP: return "DUP";
        case OP_SWAP: return "SWAP";
        case OP_ELEM: return "ELEM";
        case OP_CJMPZ: return "CJMPZ";
        case OP_CJMPNZ: return "CJMPNZ";
        case OP_BEGIN: return "BEGIN";
        case OP_CBEGIN: return "CBEGIN";
        case OP_CLOSURE: return "CLOSURE";
        case OP_CALLC: return "CALLC";
        case OP_CALL: return "CALL";
        case OP_TAG: return "TAG";
        case OP_ARRAY: return "ARRAY";
        case OP_FAIL: return "FAIL";
        case OP_LINE: return "LINE";
        case OP_CALL_READ: return "CALL_READ";
        case OP_CALL_WRITE: return "CALL_WRITE";
        case OP_CALL_LENGTH: return "CALL_LENGTH";
        case OP_CALL_STRING: return "CALL_STRING";
        case OP_CALL_ARRAY: return "CALL_ARRAY";
        case OP_STOP: return "STOP";
        default:
            snprintf(name, sizeof(name), "OP_0x%02X", op);
            return name;
    }
}

typedef struct {
    unsigned int key;
    uint64_t count;
} SortedFreq;

static int compare_freq(const void *a, const void *b) {
    const SortedFreq *fa = (const SortedFreq *)a;
    const SortedFreq *fb = (const SortedFreq *)b;

    if (fa->count < fb->count) return 1;
    if (fa->count > fb->count) return -1;
    if (fa->key < fb->key) return -1;
    if (fa->key > fb->key) return 1;
    return 0;
}

static void print_key(unsigned int key) {
    if (key < 256) {
        printf("%s", opcode_name((uint8_t)key));
        return;
    }

    unsigned int pair = key - NGRAM_PAIR_BASE;
    uint8_t first = (uint8_t)(pair >> 8);
    uint8_t second = (uint8_t)pair;
    printf("%s -> %s", opcode_name(first), opcode_name(second));
}

static void count_and_print(const bytefile *bf, const uint8_t *starts, uint8_t *labels) {
    NgramFreq *freqs = (NgramFreq *)checked_calloc(NGRAM_KEY_COUNT, sizeof(NgramFreq));

    int previous_valid = 0;
    uint8_t previous_key = 0;
    int previous_next_ip = -1;

    // Идём по адресам, но учитываем только достижимые инструкции
    for (int ip = 0; ip < bf->code_size; ++ip) {
        if (!starts[ip]) continue;

        DecodedInsn ins = decode_instruction(bf, ip);

        if (ins.key == OP_LINE) {
            if (labels[ip] && ins.next_ip < bf->code_size) {
                labels[ins.next_ip] = 1;
            }
            if (previous_valid && previous_next_ip == ip) {
                previous_next_ip = ins.next_ip;
            }
            continue;
        }


        add_frequency(freqs, ins.key);

        // Метка разрывает последовательность перед инструкцией
        if (labels[ip]) previous_valid = 0;

        if (previous_valid && previous_next_ip == ip) {
            add_frequency(freqs, make_pair_key(previous_key, ins.key));
        }

        previous_key = ins.key;
        previous_next_ip = ins.next_ip;
        previous_valid = !ins.is_terminal && !ins.is_branch;
    }

    size_t unique = 0;
    for (unsigned int key = 0; key < NGRAM_KEY_COUNT; ++key) {
        if (freqs[key].used) unique++;
    }

    SortedFreq *sorted = (SortedFreq *)checked_malloc(unique * sizeof(SortedFreq));
    size_t at = 0;
    for (unsigned int key = 0; key < NGRAM_KEY_COUNT; ++key) {
        if (freqs[key].used) {
            sorted[at].key = key;
            sorted[at].count = freqs[key].count;
            at++;
        }
    }

    qsort(sorted, unique, sizeof(SortedFreq), compare_freq);

    for (size_t i = 0; i < unique; ++i) {
        printf("%8llu  ", (unsigned long long)sorted[i].count);
        print_key(sorted[i].key);
        putchar('\n');
    }

    free(sorted);
    free(freqs);
}

static void analyze_bytecode(const bytefile *bf) {
    uint8_t *labels = (uint8_t *)checked_calloc((size_t)bf->code_size, 1);

    uint8_t *starts = find_reachable_code(bf, labels);
    count_and_print(bf, starts, labels);

    free(starts);
    free(labels);
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