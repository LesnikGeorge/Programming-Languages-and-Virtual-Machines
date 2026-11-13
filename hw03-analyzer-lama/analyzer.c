#include "byterun.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Оба бита пометки храним в одном байте
enum {
    FLAG_REACHABLE = 1u << 0,
    FLAG_LABEL     = 1u << 1
};

// Запись в хеш-таблице: храним смещение и длину прямо в bf->code_ptr, чтобы не копировать байты
typedef struct {
    uint32_t offset;
    uint32_t length;
    uint32_t count;
} SeqEntry;

typedef struct {
    SeqEntry *entries;
    size_t    capacity;
    size_t    size;
} SeqTable;

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

static inline uint32_t hash_bytes(const uint8_t *data, uint32_t len) {
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    return h;
}

static void table_init(SeqTable *ht, size_t initial_cap) {
    ht->capacity = initial_cap;
    ht->size     = 0;
    ht->entries  = (SeqEntry *)checked_calloc(initial_cap, sizeof(SeqEntry));
}

static void table_grow(SeqTable *ht, const uint8_t *code) {
    if (ht->capacity > SIZE_MAX / (2 * sizeof(SeqEntry))) {
        vm_error("Out of memory in analyzer");
    }
    size_t    new_cap     = ht->capacity * 2;
    SeqEntry *new_entries = (SeqEntry *)checked_calloc(new_cap, sizeof(SeqEntry));
    size_t    mask        = new_cap - 1;

    for (size_t i = 0; i < ht->capacity; ++i) {
        SeqEntry e = ht->entries[i];
        if (e.length == 0) continue;

        size_t idx = hash_bytes(code + e.offset, e.length) & mask;
        while (new_entries[idx].length != 0) {
            idx = (idx + 1) & mask;
        }
        new_entries[idx] = e;
    }

    free(ht->entries);
    ht->entries  = new_entries;
    ht->capacity = new_cap;
}

static void add_frequency(SeqTable *ht, const uint8_t *code, uint32_t offset, uint32_t length) {
    if (ht->size >= (ht->capacity >> 1) + (ht->capacity >> 2)) {
        table_grow(ht, code);
    }

    size_t         mask   = ht->capacity - 1;
    const uint8_t *needle = code + offset;
    size_t         idx    = hash_bytes(needle, length) & mask;

    for (;;) {
        SeqEntry *e = &ht->entries[idx];
        if (e->length == 0) {
            e->offset = offset;
            e->length = length;
            e->count  = 1;
            ht->size++;
            return;
        }
        if (e->length == length && memcmp(code + e->offset, needle, length) == 0) {
            if (e->count == UINT32_MAX) {
                vm_error("Frequency counter overflow");
            }
            e->count++;
            return;
        }
        idx = (idx + 1) & mask;
    }
}

// Помечаем до добавления в стек, чтобы не было дубликатов
static inline void mark_and_push(uint8_t *flags, uint32_t *worklist, size_t *sp,
                                 uint32_t offset, bool is_label) {
    if (is_label) {
        flags[offset] |= FLAG_LABEL;
    }
    if (!(flags[offset] & FLAG_REACHABLE)) {
        flags[offset] |= FLAG_REACHABLE;
        worklist[(*sp)++] = offset;
    }
}

// Обходит достижимый код от публичных символов и отмечает начала инструкций
static uint8_t *find_reachable_code(const bytefile *bf) {
    uint8_t  *flags    = (uint8_t *)checked_calloc(bf->code_size, 1);
    uint32_t *worklist = (uint32_t *)checked_malloc((size_t)bf->code_size * sizeof(uint32_t));
    size_t    sp       = 0;

    for (uint32_t i = 0; i < bf->public_symbols_number; ++i) {
        uint32_t offset = get_public_offset(bf, i);
        mark_and_push(flags, worklist, &sp, offset, true);
    }

    while (sp > 0) {
        uint32_t  ip   = worklist[--sp];
        insn_info info = decode_insn(bf, ip);

        if (info.has_target) {
            mark_and_push(flags, worklist, &sp, info.target, true);
        }

        if (info.falls_through) {
            if (ip + info.length >= bf->code_size) {
                vm_error("Control flow falls off the end of bytecode at offset 0x%x", ip);
            }
            uint32_t next_ip = ip + info.length;
            // Если это вызов, то возврат ставит метку на следующую инструкцию
            mark_and_push(flags, worklist, &sp, next_ip, info.is_call);
        }
    }

    free(worklist);
    return flags;
}

static const uint8_t *g_code_ptr = NULL;

static int compare_freq(const void *a, const void *b) {
    const SeqEntry *fa = (const SeqEntry *)a;
    const SeqEntry *fb = (const SeqEntry *)b;

    if (fa->count < fb->count) return 1;
    if (fa->count > fb->count) return -1;

    uint32_t min_len = fa->length < fb->length ? fa->length : fb->length;
    int      cmp     = memcmp(g_code_ptr + fa->offset, g_code_ptr + fb->offset, min_len);
    if (cmp != 0) return cmp;
    if (fa->length < fb->length) return -1;
    if (fa->length > fb->length) return 1;
    return 0;
}

static void count_and_print(const bytefile *bf, uint8_t *flags) {
    SeqTable ht;
    table_init(&ht, 1024);

    int      previous_valid  = 0;
    uint32_t previous_offset = 0;
    uint32_t previous_length = 0;

    // Идём по адресам, но учитываем только достижимые инструкции
    uint32_t ip = 0;
    while (ip < bf->code_size) {
        if (!(flags[ip] & FLAG_REACHABLE)) {
            previous_valid = 0;
            ip++;
            continue;
        }

        insn_info info = decode_insn(bf, ip);

        for (uint32_t inner = 1; inner < info.length; ++inner) {
            if (flags[ip + inner] != 0) {
                vm_error("Jump into the middle of instruction at offset 0x%x", ip);
            }
        }

        add_frequency(&ht, bf->code_ptr, ip, info.length);

        // Метка разрывает последовательность перед инструкцией
        if (flags[ip] & FLAG_LABEL) previous_valid = 0;

        if (previous_valid) {
            add_frequency(&ht, bf->code_ptr, previous_offset, previous_length + info.length);
        }

        if (info.falls_through) {
            previous_valid  = 1;
            previous_offset = ip;
            previous_length = info.length;
        } else {
            previous_valid = 0;
        }

        ip += info.length;
    }

    free(flags);

    size_t unique = 0;
    for (size_t i = 0; i < ht.capacity; ++i) {
        if (ht.entries[i].length != 0) {
            ht.entries[unique++] = ht.entries[i];
        }
    }

    g_code_ptr = bf->code_ptr;
    qsort(ht.entries, unique, sizeof(SeqEntry), compare_freq);

    for (size_t i = 0; i < unique; ++i) {
        const SeqEntry *e   = &ht.entries[i];
        uint32_t        cur = e->offset;
        uint32_t        end = e->offset + e->length;

        printf("%8u\t", e->count);
        int first = 1;
        while (cur < end) {
            if (!first) {
                fputs(" -> ", stdout);
            }
            cur   = disassemble_insn(stdout, bf, cur);
            first = 0;
        }
        putchar('\n');
    }

    free(ht.entries);
}

static void analyze_bytecode(const bytefile *bf) {
    uint8_t *flags = find_reachable_code(bf);
    count_and_print(bf, flags);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.bc>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bytefile *bf = read_file(argv[1]);
    analyze_bytecode(bf);
    close_file(bf);
    return EXIT_SUCCESS;
}