#define _GNU_SOURCE 1
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "/home/lesnik/Documents/YP_VM/Lama/runtime/runtime_common.h"

// Костыль для сборщика мусора
// Гарантирует, что секции custom_data не сдохнет при агрессивной оптимизации
__asm__(
    ".global __start_custom_data\n"
    ".global __stop_custom_data\n"
    ".section .data\n"
    ".balign 8\n"
    "__start_custom_data:\n"
    "__stop_custom_data:\n"
    ".quad 0\n"
);

extern size_t __gc_stack_top;
extern size_t __gc_stack_bottom;
extern void __gc_init(void);

extern void *Bstring(aint *args);
extern void *Lstring(aint *args);
extern aint  Llength(void *p);
extern void *Belem(void *p, aint i);
extern void *Bsta(void *x, aint i, void *v);
extern void *Barray(aint *args, aint bn);
extern void *Bclosure(aint *args, aint bn);
extern aint  Lread(void);
extern aint  Lwrite(aint n);
extern void *Bsexp(aint *args, aint bn);
extern aint  LtagHash(char *s);
extern aint  Btag(void *d, aint t, aint n);
extern aint  Barray_patt(void *d, aint n);
extern aint  Bstring_patt(void *x, void *y);
extern aint  Bclosure_tag_patt(void *x);
extern aint  Bboxed_patt(void *x);
extern aint  Bunboxed_patt(void *x);
extern aint  Barray_tag_patt(void *x);
extern aint  Bstring_tag_patt(void *x);
extern aint  Bsexp_tag_patt(void *x);
extern void  Bmatch_failure(void *v, char *fname, aint line, aint col);

#define PUBLIC_ENTRY_SIZE sizeof(public_entry)

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

static inline const char *get_public_name(const bytefile *bf, int i) {
    int32_t name_offset = get_public_entry(bf, i)->name_offset;
    if (name_offset < 0 || name_offset >= bf->stringtab_size) {
        vm_error("Corrupted header: public symbol %d name offset %d out of bounds [0, %d)",
                 i, (int)name_offset, bf->stringtab_size);
    }
    return &bf->string_ptr[name_offset];
}

static inline int get_public_offset(const bytefile *bf, int i) {
    return (int)get_public_entry(bf, i)->offset;
}

static inline unsigned char get_public_flag(const bytefile *bf, int i) {
    return get_public_entry(bf, i)->flag;
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

    // Страховка
    if (bf->stringtab_size > 0 && bf->string_ptr[bf->stringtab_size - 1] != '\0') {
        vm_error("Corrupted string table: not null-terminated");
    }

    return bf;
}

#define OPERAND_STACK_CAPACITY (256 * 1024)
#define CALL_STACK_CAPACITY    (64 * 1024)

// Группы инструкций по старшему полубайту (high nibble)
typedef enum {
    H_BINOP = 0x0,
    H_LD    = 0x2,
    H_LDA   = 0x3,
    H_ST    = 0x4,
    H_PATT  = 0x6
} insn_group_t;

// Коды бинарных операций (low nibble при H_BINOP)
typedef enum {
    BINOP_ADD = 1,
    BINOP_SUB = 2,
    BINOP_MUL = 3,
    BINOP_DIV = 4,
    BINOP_MOD = 5,
    BINOP_LT  = 6,
    BINOP_LE  = 7,
    BINOP_GT  = 8,
    BINOP_GE  = 9,
    BINOP_EQ  = 10,
    BINOP_NE  = 11,
    BINOP_AND = 12,
    BINOP_OR  = 13
} binop_code_t;

// Локация переменной (low nibble для LD/LDA/ST и байт спецификатора в CLOSURE)
typedef enum {
    VAR_GLOBAL  = 0,
    VAR_LOCAL   = 1,
    VAR_ARG     = 2,
    VAR_CLOSURE = 3
} var_loc_t;

// Виды сопоставления с образцом (low nibble при H_PATT)
typedef enum {
    PATT_STRCMP    = 0,
    PATT_STRING    = 1,
    PATT_ARRAY     = 2,
    PATT_SEXP      = 3,
    PATT_BOXED     = 4,
    PATT_UNBOXED   = 5,
    PATT_CLOSURE   = 6
} patt_code_t;

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
    int   ret_ip;
    int   argc;
    int   locals;
    aint *args_ptr;   // Отрицательная индексация для аргументов: arg[i] = args_ptr[-i]
    aint *locals_ptr; // Отрицательная индексация для локалок: local[i] = locals_ptr[-i]
    aint *saved_sp;   // Указатель вершины стека до вызова функции (для отката при RET/END)
    int   is_closure; // Если 1 — вызов через CALLC, замыкание лежит в args_ptr[1]
} call_frame;

static call_frame call_stack[CALL_STACK_CAPACITY];

static inline aint frame_get_closure(const call_frame *frame) {
    return frame->is_closure ? frame->args_ptr[1] : BOX(0);
}

static inline aint *get_closure_elem_ptr(aint closure, int idx, int insn_offset) {
    if (UNBOXED(closure) || closure == 0) vm_error("Closure access on non-closure value at 0x%x", insn_offset);
    data *d = TO_DATA((void *)closure);
    if (TAG(d->data_header) != CLOSURE_TAG) vm_error("Invalid closure tag at 0x%x", insn_offset);
    
    int len = LEN(d->data_header);
    if (idx < 0 || idx + 1 >= len) vm_error("Closure variable index %d out of bounds at 0x%x", idx, insn_offset);
    
    return &((aint *)closure)[1 + idx];
}

static inline aint get_closure_elem(aint closure, int idx, int insn_offset) {
    return *get_closure_elem_ptr(closure, idx, insn_offset);
}

// Инициализация нового кадра стека вызовов (общая функция для main, CALL и CALLC)
static inline void push_call_frame(int *csp, int ret_ip, int argc, aint *sp, int is_closure, int insn_offset) {
    if (*csp + 1 >= CALL_STACK_CAPACITY) {
        vm_error("Call stack overflow at 0x%x", insn_offset);
    }
    (*csp)++;
    call_stack[*csp].ret_ip     = ret_ip;
    call_stack[*csp].argc       = argc;
    call_stack[*csp].locals     = -1;
    call_stack[*csp].args_ptr   = sp + argc - 1;
    call_stack[*csp].locals_ptr = NULL;
    call_stack[*csp].saved_sp   = sp + argc + (is_closure ? 1 : 0);
    call_stack[*csp].is_closure = is_closure;
}

__attribute__((noinline))
static void eval(const bytefile *bf, int start_offset) {
    // Границы стека передаем сборщику напрямую.
    // Ассерт assert((__gc_stack_top & 0xF) == 0); выравнивания по 16 байт в runtime/runtime.c закоментил
    aint gc_operand_stack[OPERAND_STACK_CAPACITY];

    if (start_offset < 0 || start_offset >= bf->code_size) {
        vm_error("Entry point offset 0x%x is out of code bounds", start_offset);
    }
    if (bf->global_area_size + 1024 >= OPERAND_STACK_CAPACITY) {
        vm_error("Too many global variables (%d)", bf->global_area_size);
    }

    __gc_stack_bottom = (size_t)(gc_operand_stack + OPERAND_STACK_CAPACITY);

    // Глобальные переменные располагаются в самом низу стека операндов [globals_base, __gc_stack_bottom)
    aint *globals_base = (aint *)__gc_stack_bottom - bf->global_area_size;
    for (int i = 0; i < bf->global_area_size; ++i) {
        globals_base[i] = BOX(0);
    }

    aint *sp_base  = globals_base;
    aint *sp_limit = gc_operand_stack + 32;
    aint *sp       = sp_base;

    #define CHECK_PUSH(n) do { if (sp - (n) < sp_limit) vm_error("Operand stack overflow at 0x%x", insn_offset); } while(0)
    #define CHECK_POP(n)  do { if (sp + (n) > sp_base)  vm_error("Operand stack underflow at 0x%x", insn_offset); } while(0)

    #define PUSH(v) do { CHECK_PUSH(1); *(--sp) = (aint)(v); } while(0)
    #define POP()   ({ CHECK_POP(1); *(sp++); })
    #define PEEK()  ({ CHECK_POP(1); *sp; })

    // Фейковые аргументы для точки входа main
    const int main_argc = 2;
    int insn_offset = start_offset;
    for (int i = 0; i < main_argc; ++i) {
        PUSH(BOX(0));
    }

    int csp = -1;
    push_call_frame(&csp, -1, main_argc, sp, 0, start_offset);

    int ip = start_offset;

    while (1) {
        insn_offset = ip;
        unsigned char op = read_byte(bf, &ip);
        unsigned char h  = (op & 0xF0) >> 4;
        unsigned char l  = op & 0x0F;

        if (op == OP_STOP) break;

        if (h == H_BINOP) {
            aint y = POP();
            aint x = POP();

            if (l == BINOP_EQ) { // == (единственный бинарник, работающий с объектами)
                if (UNBOXED(x) && UNBOXED(y)) PUSH(BOX(UNBOX(x) == UNBOX(y)));
                else if (UNBOXED(x) || UNBOXED(y)) PUSH(BOX(0));
                else vm_error("Invalid operands for '==' at 0x%x: comparing two boxed values", insn_offset);
                continue;
            }

            if (!UNBOXED(x) || !UNBOXED(y)) {
                vm_error("Binary operator %d expects integer operands at 0x%x", l, insn_offset);
            }

            aint vx = UNBOX(x);
            aint vy = UNBOX(y);
            aint res = 0;

            switch (l) {
                case BINOP_ADD: res = vx + vy; break;
                case BINOP_SUB: res = vx - vy; break;
                case BINOP_MUL: res = vx * vy; break;
                case BINOP_DIV:
                    if (vy == 0) vm_error("Division by zero at 0x%x", insn_offset);
                    res = vx / vy;
                    break;
                case BINOP_MOD:
                    if (vy == 0) vm_error("Modulo by zero at 0x%x", insn_offset);
                    res = vx % vy;
                    break;
                case BINOP_LT:  res = vx <  vy; break;
                case BINOP_LE:  res = vx <= vy; break;
                case BINOP_GT:  res = vx >  vy; break;
                case BINOP_GE:  res = vx >= vy; break;
                case BINOP_NE:  res = vx != vy; break;
                case BINOP_AND: res = vx && vy; break;
                case BINOP_OR:  res = vx || vy; break;
                default: vm_error("Unknown binary operator 0x%02x at 0x%x", op, insn_offset);
            }
            PUSH(BOX(res));
            continue;
        }

        if (h == H_LD || h == H_LDA || h == H_ST) {
            int idx = read_int32(bf, &ip);
            call_frame *frame = &call_stack[csp];
            aint *slot_ptr = NULL;

            switch (l) {
                case VAR_GLOBAL:
                    if (idx < 0 || idx >= bf->global_area_size) vm_error("Global var out of bounds at 0x%x", insn_offset);
                    slot_ptr = &globals_base[idx];
                    break;
                case VAR_LOCAL:
                    if (idx < 0 || idx >= frame->locals) vm_error("Local var out of bounds at 0x%x", insn_offset);
                    slot_ptr = &frame->locals_ptr[-idx];
                    break;
                case VAR_ARG:
                    if (idx < 0 || idx >= frame->argc) vm_error("Arg out of bounds at 0x%x", insn_offset);
                    slot_ptr = &frame->args_ptr[-idx];
                    break;
                case VAR_CLOSURE:
                    slot_ptr = get_closure_elem_ptr(frame_get_closure(frame), idx, insn_offset);
                    break;
                default: vm_error("Unknown var designation in opcode 0x%02x at 0x%x", op, insn_offset);
            }

            if (h == H_LD) PUSH(*slot_ptr);
            else if (h == H_LDA) PUSH((aint)slot_ptr);
            else *slot_ptr = PEEK(); // H_ST
            
            continue;
        }

        if (h == H_PATT) {
            aint x, y;
            switch (l) {
                case PATT_STRCMP:  y = POP(); x = POP(); PUSH(Bstring_patt((void *)x, (void *)y)); break;
                case PATT_STRING:  x = POP(); PUSH(Bstring_tag_patt((void *)x)); break;
                case PATT_ARRAY:   x = POP(); PUSH(Barray_tag_patt((void *)x)); break;
                case PATT_SEXP:    x = POP(); PUSH(Bsexp_tag_patt((void *)x)); break;
                case PATT_BOXED:   x = POP(); PUSH(Bboxed_patt((void *)x)); break;
                case PATT_UNBOXED: x = POP(); PUSH(Bunboxed_patt((void *)x)); break;
                case PATT_CLOSURE: x = POP(); PUSH(Bclosure_tag_patt((void *)x)); break;
                default: vm_error("Unknown PATT code 0x%02x at 0x%x", op, insn_offset);
            }
            continue;
        }

        switch (op) {
            case OP_CONST: {
                PUSH(BOX(read_int32(bf, &ip)));
                break;
            }
            case OP_STRING: {
                const char *s = get_string(bf, read_int32(bf, &ip), insn_offset);
                aint arg = (aint)s;
                // Перед аллокацией в куче (Bstring, Bclosure, Bsexp, Barray) может сработать GC.
                // Стек растет вниз, поэтому выставляем __gc_stack_top = sp - 1, 
                // чтобы сборщик мусора просканировал все операнды на стеке как корни (roots).
                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                PUSH((aint)Bstring(&arg));
                break;
            }
            case OP_SEXP: {
                int tag_offset = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative SEXP arity %d at 0x%x", n, insn_offset);
                
                const char *tag_str = get_string(bf, tag_offset, insn_offset);
                CHECK_POP(n);

                
                for (int i = 0; i < n / 2; ++i) {
                    aint tmp = sp[i];
                    sp[i] = sp[n - 1 - i];
                    sp[n - 1 - i] = tmp;
                }
                
                CHECK_PUSH(1);
                sp--;
                for (int i = 0; i < n; ++i) sp[i] = sp[i + 1];
                sp[n] = LtagHash((char *)tag_str);

                // Аргументы остаются на стеке выше __gc_stack_top, чтобы GC видел их как корни
                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией 
                void *res = Bsexp(sp, BOX(n + 1));
                sp += (n + 1);
                PUSH((aint)res);
                break;
            }
            case OP_STI: {
                aint val = POP();
                aint ref = POP();
                if (UNBOXED(ref) || ref == 0) vm_error("Invalid reference in STI at 0x%x", insn_offset);
                *(aint *)ref = val;
                PUSH(val);
                break;
            }
            case OP_STA: {
                aint val = POP();
                aint idx = POP();
                if (UNBOXED(idx)) {
                    aint obj = POP();
                    __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                    PUSH((aint)Bsta((void *)obj, idx, (void *)val));
                } else {
                    if (idx == 0) vm_error("Null reference in STA at 0x%x", insn_offset);
                    __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                    PUSH((aint)Bsta(NULL, idx, (void *)val));
                }
                break;
            }
            case OP_JMP: {
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("JMP target out of bounds at 0x%x", insn_offset);
                ip = target;
                break;
            }
            case OP_END:
            case OP_RET: {
                aint ret_val = POP();
                call_frame *frame = &call_stack[csp];
                sp = frame->saved_sp;
                if (frame->ret_ip == -1) return; // Возврат из main

                ip = frame->ret_ip;
                csp--;
                PUSH(ret_val);
                break;
            }
            case OP_DROP: {
                (void)POP();
                break;
            }
            case OP_DUP: {
                PUSH(PEEK());
                break;
            }
            case OP_SWAP: {
                aint v1 = POP();
                aint v2 = POP();
                PUSH(v1);
                PUSH(v2);
                break;
            }
            case OP_ELEM: {
                aint idx = POP();
                aint obj = POP();
                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                PUSH((aint)Belem((void *)obj, idx));
                break;
            }
            case OP_CJMPZ: {
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CJMPz target out of bounds at 0x%x", insn_offset);
                if (UNBOX(POP()) == 0) ip = target;
                break;
            }
            case OP_CJMPNZ: {
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CJMPnz target out of bounds at 0x%x", insn_offset);
                if (UNBOX(POP()) != 0) ip = target;
                break;
            }
            case OP_BEGIN:
            case OP_CBEGIN: {
                int nargs = read_int32(bf, &ip);
                int nlocals = read_int32(bf, &ip);
                if (nargs < 0 || nlocals < 0) vm_error("Negative sizes in BEGIN at 0x%x", insn_offset);

                call_frame *frame = &call_stack[csp];
                if (frame->locals != -1) vm_error("BEGIN inside initialized frame at 0x%x", insn_offset);
                if (op == OP_CBEGIN && !frame->is_closure) vm_error("CBEGIN without a closure at 0x%x", insn_offset);
                if (frame->argc != nargs) vm_error("Arity mismatch: expected %d, got %d", nargs, frame->argc);

                frame->locals = nlocals;
                frame->locals_ptr = sp - 1;

                CHECK_PUSH(nlocals);
                for (int i = 0; i < nlocals; ++i) {
                    PUSH(BOX(0));
                }
                break;
            }
            case OP_CLOSURE: {
                int target = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CLOSURE target out of bounds at 0x%x", insn_offset);
                if (n < 0) vm_error("Negative closure size %d at 0x%x", n, insn_offset);

                call_frame *frame = &call_stack[csp];
                aint cur_closure = frame_get_closure(frame);
                CHECK_PUSH(n + 1);

                sp -= (n + 1);
                sp[0] = BOX(target);

                for (int i = 0; i < n; ++i) {
                    unsigned char dtype = read_byte(bf, &ip);
                    int idx = read_int32(bf, &ip);
                    aint val = BOX(0);
                    switch (dtype) {
                        case VAR_GLOBAL:
                            if (idx < 0 || idx >= bf->global_area_size) vm_error("Global var out of bounds in CLOSURE at 0x%x", insn_offset);
                            val = globals_base[idx];
                            break;
                        case VAR_LOCAL:
                            if (idx < 0 || idx >= frame->locals) vm_error("Local var out of bounds in CLOSURE at 0x%x", insn_offset);
                            val = frame->locals_ptr[-idx];
                            break;
                        case VAR_ARG:
                            if (idx < 0 || idx >= frame->argc) vm_error("Arg out of bounds in CLOSURE at 0x%x", insn_offset);
                            val = frame->args_ptr[-idx];
                            break;
                        case VAR_CLOSURE:
                            val = get_closure_elem(cur_closure, idx, insn_offset);
                            break;
                        default:
                            vm_error("Unknown designation %d in CLOSURE at 0x%x", dtype, insn_offset);
                    }
                    sp[i + 1] = val;
                }

                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                void *res = Bclosure(sp, BOX(n));
                sp += (n + 1);
                PUSH((aint)res);
                break;
            }
            case OP_CALLC: {
                int argc = read_int32(bf, &ip);
                if (argc < 0) vm_error("Negative arity %d in CALLC at 0x%x", argc, insn_offset);
                CHECK_POP(argc + 1);

                aint closure = sp[argc];
                if (UNBOXED(closure) || closure == 0) vm_error("CALLC on non-closure at 0x%x", insn_offset);
                if (TAG(TO_DATA((void *)closure)->data_header) != CLOSURE_TAG) vm_error("Not a closure at 0x%x", insn_offset);

                int target = (int)UNBOX(((aint *)closure)[0]);
                if (target < 0 || target >= bf->code_size) vm_error("Closure target out of bounds at 0x%x", insn_offset);

                push_call_frame(&csp, ip, argc, sp, 1, insn_offset);
                ip = target;
                break;
            }
            case OP_CALL: {
                int target = read_int32(bf, &ip);
                int argc = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CALL target out of bounds at 0x%x", insn_offset);
                if (argc < 0) vm_error("Negative arity in CALL at 0x%x", insn_offset);
                CHECK_POP(argc);

                push_call_frame(&csp, ip, argc, sp, 0, insn_offset);
                ip = target;
                break;
            }
            case OP_TAG: {
                int tag_offset = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative arity %d in TAG at 0x%x", n, insn_offset);
                
                const char *tag_str = get_string(bf, tag_offset, insn_offset);
                PUSH(Btag((void *)POP(), LtagHash((char *)tag_str), BOX(n)));
                break;
            }
            case OP_ARRAY: {
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative size %d in ARRAY at 0x%x", n, insn_offset);
                PUSH(Barray_patt((void *)POP(), BOX(n)));
                break;
            }
            case OP_FAIL: {
                int line = read_int32(bf, &ip);
                int col = read_int32(bf, &ip);
                Bmatch_failure((void *)POP(), (char *)bf->filename, BOX(line), BOX(col));
                exit(EXIT_FAILURE);
            }
            case OP_LINE: {
                (void)read_int32(bf, &ip); // Пропускаем номер строки
                break;
            }
            case OP_CALL_READ: {
                PUSH(Lread());
                break;
            }
            case OP_CALL_WRITE: {
                aint v = POP();
                if (!UNBOXED(v)) vm_error("write expects integer at 0x%x", insn_offset);
                PUSH(Lwrite(v));
                break;
            }
            case OP_CALL_LENGTH: {
                aint v = POP();
                PUSH(Llength((void *)v));
                break;
            }
            case OP_CALL_STRING: {
                CHECK_POP(1);
                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                void *res = Lstring(sp);
                sp[0] = (aint)res;
                break;
            }
            case OP_CALL_ARRAY: {
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative size %d in .array at 0x%x", n, insn_offset);
                CHECK_POP(n);

                for (int i = 0; i < n / 2; ++i) {
                    aint tmp = sp[i];
                    sp[i] = sp[n - 1 - i];
                    sp[n - 1 - i] = tmp;
                }

                __gc_stack_top = (size_t)(sp - 1); // Регистрируем корни стека для GC перед аллокацией
                void *res = Barray(sp, BOX(n));
                sp += n;
                PUSH((aint)res);
                break;
            }
            default:
                vm_error("Unimplemented opcode 0x%02x at 0x%x", op, insn_offset);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.bc>\n", argv[0]);
        return EXIT_FAILURE;
    }

    __gc_init();
    bytefile *bf = read_file(argv[1]);

    int main_offset = -1;
    for (int i = 0; i < bf->public_symbols_number; ++i) {
        if (strcmp(get_public_name(bf, i), "main") == 0 && get_public_flag(bf, i) == 0) {
            main_offset = get_public_offset(bf, i);
            break;
        }
    }

    if (main_offset == -1) vm_error("Public function 'main' not found");

    eval(bf, main_offset);

    free(bf->raw_data);
    free(bf);
    return EXIT_SUCCESS;
}