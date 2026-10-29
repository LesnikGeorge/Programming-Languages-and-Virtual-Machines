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

#define PUBLIC_ENTRY_SIZE 9

typedef struct {
    const char *filename;
    int   stringtab_size;
    int   global_area_size;
    int   public_symbols_number;
    char *public_ptr;
    char *string_ptr;
    char *code_ptr;
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

static inline unsigned char read_byte(bytefile *bf, int *ip_offset) {
    if (*ip_offset < 0 || *ip_offset >= bf->code_size) {
        vm_error("Unexpected end of bytecode at offset 0x%x (code size: %d)",
                 *ip_offset, bf->code_size);
    }
    unsigned char b = (unsigned char)bf->code_ptr[*ip_offset];
    (*ip_offset) += 1;
    return b;
}

static inline int read_int32(bytefile *bf, int *ip_offset) {
    if (*ip_offset < 0 || *ip_offset + (int)sizeof(int32_t) > bf->code_size) {
        vm_error("Unexpected end of bytecode while reading int32 at offset 0x%x (code size: %d)",
                 *ip_offset, bf->code_size);
    }
    int32_t val = 0;
    memcpy(&val, bf->code_ptr + *ip_offset, sizeof(int32_t));
    (*ip_offset) += (int)sizeof(int32_t);
    return (int)val;
}

static inline char *get_string(bytefile *bf, int offset, int insn_offset) {
    if (offset < 0 || offset >= bf->stringtab_size) {
        vm_error("String offset %d out of bounds [0, %d) at instruction offset 0x%x",
                 offset, bf->stringtab_size, insn_offset);
    }
    return &bf->string_ptr[offset];
}

static inline char *get_public_name(bytefile *bf, int i) {
    int32_t name_offset = 0;
    memcpy(&name_offset, bf->public_ptr + (size_t)i * PUBLIC_ENTRY_SIZE, sizeof(int32_t));
    if (name_offset < 0 || name_offset >= bf->stringtab_size) {
        vm_error("Corrupted header: public symbol %d name offset %d out of bounds [0, %d)",
                 i, (int)name_offset, bf->stringtab_size);
    }
    return &bf->string_ptr[name_offset];
}

static inline int get_public_offset(bytefile *bf, int i) {
    int32_t offset = 0;
    memcpy(&offset, bf->public_ptr + (size_t)i * PUBLIC_ENTRY_SIZE + sizeof(int32_t), sizeof(int32_t));
    return (int)offset;
}

static inline unsigned char get_public_flag(bytefile *bf, int i) {
    return (unsigned char)bf->public_ptr[(size_t)i * PUBLIC_ENTRY_SIZE + 2 * sizeof(int32_t)];
}

// Загружает файл целиком и парсит смещения секций
static bytefile *read_file(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (!f) vm_error("Cannot open file '%s': %s", fname, strerror(errno));

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (file_size < (long)(3 * sizeof(int32_t))) {
        vm_error("Corrupted file '%s': size (%ld bytes) is smaller than header (12 bytes)", fname, file_size);
    }

    char *raw = (char *)malloc((size_t)file_size);
    if (!raw) vm_error("Out of memory allocating %ld bytes", file_size);

    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        vm_error("Failed to read file '%s'", fname);
    }
    fclose(f);

    bytefile *bf = (bytefile *)calloc(1, sizeof(bytefile));
    if (!bf) vm_error("Out of memory");

    bf->filename = fname;
    bf->raw_data = raw;

    int32_t st_size = 0, glob_size = 0, pub_num = 0;
    memcpy(&st_size,   raw + 0, sizeof(int32_t));
    memcpy(&glob_size, raw + 4, sizeof(int32_t));
    memcpy(&pub_num,   raw + 8, sizeof(int32_t));

    if (st_size < 0 || glob_size < 0 || pub_num < 0) {
        vm_error("Corrupted header: negative field (stringtab=%d, globals=%d, publics=%d)", 
                 (int)st_size, (int)glob_size, (int)pub_num);
    }

    // Защита от краша при переполнении int, если файл битый
    int64_t pub_bytes = (int64_t)pub_num * PUBLIC_ENTRY_SIZE;
    int64_t header_and_tables = (int64_t)(3 * sizeof(int32_t)) + pub_bytes + (int64_t)st_size;

    if (header_and_tables > (int64_t)file_size) {
        vm_error("Corrupted header: tables size (%lld) exceeds file size (%ld)", 
                 (long long)header_and_tables, file_size);
    }

    bf->stringtab_size        = (int)st_size;
    bf->global_area_size      = (int)glob_size;
    bf->public_symbols_number = (int)pub_num;
    bf->public_ptr            = raw + 3 * sizeof(int32_t);
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

typedef struct {
    int   ret_ip;
    int   argc;
    int   locals;
    aint *args_ptr;   // Отрицательная индексация для аргументов: arg[i] = args_ptr[-i]
    aint *locals_ptr; // Отрицательная индексация для локалок: local[i] = locals_ptr[-i]
    aint *saved_sp;   // Для отката стека при возврате
    int   is_closure; // Если 1 — вызов через CALLC, замыкание лежит в args_ptr[1]
} call_frame;

static call_frame call_stack[CALL_STACK_CAPACITY];

static inline void sync_gc_stack(aint *sp) {
    aint *cand = sp - 1;
    // GC рантайма крашится, если указатели не выровнены по 16 байт
    if (((uintptr_t)cand & 0xF) != 0) {
        *cand = BOX(0);
        cand--;
    }
    __gc_stack_top = (size_t)cand;
}

static inline aint frame_get_closure(call_frame *frame) {
    return frame->is_closure ? frame->args_ptr[1] : BOX(0);
}

static inline aint get_closure_elem(aint closure, int idx, int insn_offset) {
    if (UNBOXED(closure) || closure == 0) vm_error("Closure access on non-closure value at 0x%x", insn_offset);
    data *d = TO_DATA((void *)closure);
    if (TAG(d->data_header) != CLOSURE_TAG) vm_error("Invalid closure tag at 0x%x", insn_offset);
    
    int len = LEN(d->data_header);
    if (idx < 0 || idx + 1 >= len) vm_error("Closure variable index %d out of bounds at 0x%x", idx, insn_offset);
    
    return ((aint *)closure)[1 + idx];
}

static inline aint *get_closure_elem_ptr(aint closure, int idx, int insn_offset) {
    if (UNBOXED(closure) || closure == 0) vm_error("Closure access on non-closure value at 0x%x", insn_offset);
    data *d = TO_DATA((void *)closure);
    if (TAG(d->data_header) != CLOSURE_TAG) vm_error("Invalid closure tag at 0x%x", insn_offset);
    
    int len = LEN(d->data_header);
    if (idx < 0 || idx + 1 >= len) vm_error("Closure variable index %d out of bounds at 0x%x", idx, insn_offset);
    
    return &((aint *)closure)[1 + idx];
}

__attribute__((noinline))
static void eval(bytefile *bf, int start_offset) {
    // Выделяем стек прямо на C-стеке (важно для производительности)
    aint gc_operand_stack[OPERAND_STACK_CAPACITY] __attribute__((aligned(16)));

    if (start_offset < 0 || start_offset >= bf->code_size) {
        vm_error("Entry point offset 0x%x is out of code bounds", start_offset);
    }
    if (bf->global_area_size + 1024 >= OPERAND_STACK_CAPACITY) {
        vm_error("Too many global variables (%d)", bf->global_area_size);
    }

    aint *stack_bottom = gc_operand_stack + OPERAND_STACK_CAPACITY;
    stack_bottom = (aint *)((uintptr_t)stack_bottom & ~(uintptr_t)0xF);
    __gc_stack_bottom = (size_t)stack_bottom;

    // Глобальные переменные живут прямо на дне стека операндов
    aint *globals_base = stack_bottom - bf->global_area_size;
    for (int i = 0; i < bf->global_area_size; ++i) {
        globals_base[i] = BOX(0);
    }

    aint *sp_base  = globals_base;
    aint *sp_limit = gc_operand_stack + 32;
    aint *sp       = sp_base;

    // Фейковые аргументы для main, чтобы он не улетел за границы стека
    const int main_argc = 2;
    for (int i = 0; i < main_argc; ++i) *(--sp) = BOX(0);

    int csp = 0;
    call_stack[0].ret_ip     = -1;
    call_stack[0].argc       = main_argc;
    call_stack[0].locals     = -1;
    call_stack[0].args_ptr   = sp_base - 1;
    call_stack[0].locals_ptr = NULL;
    call_stack[0].saved_sp   = sp_base;
    call_stack[0].is_closure = 0;

    int ip = start_offset;

    #define CHECK_PUSH(n) do { if (sp - (n) < sp_limit) vm_error("Operand stack overflow at 0x%x", insn_offset); } while(0)
    #define CHECK_POP(n)  do { if (sp + (n) > sp_base)  vm_error("Operand stack underflow at 0x%x", insn_offset); } while(0)

    #define PUSH(v) do { CHECK_PUSH(1); *(--sp) = (aint)(v); } while(0)
    #define POP()   ({ CHECK_POP(1); *(sp++); })
    #define PEEK()  ({ CHECK_POP(1); *sp; })

    while (1) {
        int insn_offset = ip;
        unsigned char op = read_byte(bf, &ip);
        unsigned char h  = (op & 0xF0) >> 4;
        unsigned char l  = op & 0x0F;

        if (op == 0xFF) break; // STOP

        if (h == 0) { // BINOP
            aint y = POP();
            aint x = POP();

            if (l == 10) { // == (единственный бинарник, работающий с объектами)
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
                case 1:  res = vx + vy; break;
                case 2:  res = vx - vy; break;
                case 3:  res = vx * vy; break;
                case 4:
                    if (vy == 0) vm_error("Division by zero at 0x%x", insn_offset);
                    res = vx / vy;
                    break;
                case 5:
                    if (vy == 0) vm_error("Modulo by zero at 0x%x", insn_offset);
                    res = vx % vy;
                    break;
                case 6:  res = vx <  vy; break;
                case 7:  res = vx <= vy; break;
                case 8:  res = vx >  vy; break;
                case 9:  res = vx >= vy; break;
                case 11: res = vx != vy; break;
                case 12: res = vx && vy; break;
                case 13: res = vx || vy; break;
                default: vm_error("Unknown binary operator 0x%02x at 0x%x", op, insn_offset);
            }
            PUSH(BOX(res));
            continue;
        }

        if (h == 2 || h == 3 || h == 4) { // LD (2x), LDA (3x), ST (4x)
            int idx = read_int32(bf, &ip);
            call_frame *frame = &call_stack[csp];
            aint *slot_ptr = NULL;

            switch (l) {
                case 0: // Global
                    if (idx < 0 || idx >= bf->global_area_size) vm_error("Global var out of bounds at 0x%x", insn_offset);
                    slot_ptr = &globals_base[idx];
                    break;
                case 1: // Local
                    if (idx < 0 || idx >= frame->locals) vm_error("Local var out of bounds at 0x%x", insn_offset);
                    slot_ptr = &frame->locals_ptr[-idx];
                    break;
                case 2: // Arg
                    if (idx < 0 || idx >= frame->argc) vm_error("Arg out of bounds at 0x%x", insn_offset);
                    slot_ptr = &frame->args_ptr[-idx];
                    break;
                case 3: // Access (closure)
                    slot_ptr = get_closure_elem_ptr(frame_get_closure(frame), idx, insn_offset);
                    break;
                default: vm_error("Unknown var designation in opcode 0x%02x at 0x%x", op, insn_offset);
            }

            if (h == 2) PUSH(*slot_ptr);       // LD
            else if (h == 3) PUSH((aint)slot_ptr); // LDA
            else *slot_ptr = PEEK();           // ST
            
            continue;
        }

        if (h == 6) { // PATT (Pattern matching)
            aint x, y;
            switch (l) {
                case 0: y = POP(); x = POP(); PUSH(Bstring_patt((void *)x, (void *)y)); break; // StrCmp
                case 1: x = POP(); PUSH(Bstring_tag_patt((void *)x)); break; // String
                case 2: x = POP(); PUSH(Barray_tag_patt((void *)x)); break;  // Array
                case 3: x = POP(); PUSH(Bsexp_tag_patt((void *)x)); break;   // Sexp
                case 4: x = POP(); PUSH(Bboxed_patt((void *)x)); break;      // Boxed
                case 5: x = POP(); PUSH(Bunboxed_patt((void *)x)); break;    // UnBoxed
                case 6: x = POP(); PUSH(Bclosure_tag_patt((void *)x)); break;// Closure
                default: vm_error("Unknown PATT code 0x%02x at 0x%x", op, insn_offset);
            }
            continue;
        }

        switch (op) {
            case 0x10: { // CONST
                PUSH(BOX(read_int32(bf, &ip)));
                break;
            }
            case 0x11: { // STRING
                char *s = get_string(bf, read_int32(bf, &ip), insn_offset);
                sync_gc_stack(sp);
                aint arg = (aint)s;
                PUSH((aint)Bstring(&arg));
                break;
            }
            case 0x12: { // SEXP
                int tag_offset = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative SEXP arity %d at 0x%x", n, insn_offset);
                
                char *tag_str = get_string(bf, tag_offset, insn_offset);
                CHECK_POP(n);

                // Реверсим элементы прямо на стеке перед передачей в Bsexp
                for (int i = 0; i < n / 2; ++i) {
                    aint tmp = sp[i];
                    sp[i] = sp[n - 1 - i];
                    sp[n - 1 - i] = tmp;
                }
                
                CHECK_PUSH(1);
                sp--;
                for (int i = 0; i < n; ++i) sp[i] = sp[i + 1];
                sp[n] = LtagHash(tag_str);

                sync_gc_stack(sp);
                void *res = Bsexp(sp, BOX(n + 1));
                sp += (n + 1);
                PUSH((aint)res);
                break;
            }
            case 0x13: { // STI
                aint val = POP();
                aint ref = POP();
                if (UNBOXED(ref) || ref == 0) vm_error("Invalid reference in STI at 0x%x", insn_offset);
                *(aint *)ref = val;
                PUSH(val);
                break;
            }
            case 0x14: { // STA
                aint val = POP();
                aint idx = POP();
                if (UNBOXED(idx)) {
                    aint obj = POP();
                    sync_gc_stack(sp);
                    PUSH((aint)Bsta((void *)obj, idx, (void *)val));
                } else {
                    if (idx == 0) vm_error("Null reference in STA at 0x%x", insn_offset);
                    PUSH((aint)Bsta(NULL, idx, (void *)val));
                }
                break;
            }
            case 0x15: { // JMP
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("JMP target out of bounds at 0x%x", insn_offset);
                ip = target;
                break;
            }
            case 0x16: // END
            case 0x17: { // RET
                aint ret_val = POP();
                call_frame *frame = &call_stack[csp];
                sp = frame->saved_sp;
                if (frame->ret_ip == -1) return; // Возврат из main

                ip = frame->ret_ip;
                csp--;
                PUSH(ret_val);
                break;
            }
            case 0x18: { // DROP
                (void)POP();
                break;
            }
            case 0x19: { // DUP
                PUSH(PEEK());
                break;
            }
            case 0x1A: { // SWAP
                aint v1 = POP();
                aint v2 = POP();
                PUSH(v1);
                PUSH(v2);
                break;
            }
            case 0x1B: { // ELEM
                aint idx = POP();
                aint obj = POP();
                sync_gc_stack(sp);
                PUSH((aint)Belem((void *)obj, idx));
                break;
            }
            case 0x50: { // CJMPz
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CJMPz target out of bounds at 0x%x", insn_offset);
                if (UNBOX(POP()) == 0) ip = target;
                break;
            }
            case 0x51: { // CJMPnz
                int target = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CJMPnz target out of bounds at 0x%x", insn_offset);
                if (UNBOX(POP()) != 0) ip = target;
                break;
            }
            case 0x52: // BEGIN
            case 0x53: { // CBEGIN
                int nargs = read_int32(bf, &ip);
                int nlocals = read_int32(bf, &ip);
                if (nargs < 0 || nlocals < 0) vm_error("Negative sizes in BEGIN at 0x%x", insn_offset);

                call_frame *frame = &call_stack[csp];
                if (frame->locals != -1) vm_error("BEGIN inside initialized frame at 0x%x", insn_offset);
                if (op == 0x53 && !frame->is_closure) vm_error("CBEGIN without a closure at 0x%x", insn_offset);
                if (frame->argc != nargs) vm_error("Arity mismatch: expected %d, got %d", nargs, frame->argc);

                frame->locals = nlocals;
                frame->locals_ptr = sp - 1;

                CHECK_PUSH(nlocals);
                for (int i = 0; i < nlocals; ++i) *(--sp) = BOX(0);
                break;
            }
            case 0x54: { // CLOSURE
                int target = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CLOSURE target out of bounds at 0x%x", insn_offset);
                if (n < 0) vm_error("Negative closure size %d at 0x%x", n, insn_offset);

                call_frame *frame = &call_stack[csp];
                aint cur_closure = frame_get_closure(frame);
                CHECK_PUSH(n + 1);

                sp -= (n + 1);
                sp[0] = BOX(target);

                // Собираем переменные для замыкания по их типам
                for (int i = 0; i < n; ++i) {
                    unsigned char dtype = read_byte(bf, &ip);
                    int idx = read_int32(bf, &ip);
                    aint val = BOX(0);
                    switch (dtype) {
                        case 0: val = globals_base[idx]; break;
                        case 1: val = frame->locals_ptr[-idx]; break;
                        case 2: val = frame->args_ptr[-idx]; break;
                        case 3: val = get_closure_elem(cur_closure, idx, insn_offset); break;
                        default: vm_error("Unknown designation %d in CLOSURE at 0x%x", dtype, insn_offset);
                    }
                    sp[i + 1] = val;
                }

                sync_gc_stack(sp);
                void *res = Bclosure(sp, BOX(n));
                sp += (n + 1);
                PUSH((aint)res);
                break;
            }
            case 0x55: { // CALLC
                int argc = read_int32(bf, &ip);
                if (argc < 0) vm_error("Negative arity %d in CALLC at 0x%x", argc, insn_offset);
                CHECK_POP(argc + 1);

                aint closure = sp[argc];
                if (UNBOXED(closure) || closure == 0) vm_error("CALLC on non-closure at 0x%x", insn_offset);
                if (TAG(TO_DATA((void *)closure)->data_header) != CLOSURE_TAG) vm_error("Not a closure at 0x%x", insn_offset);

                int target = (int)UNBOX(((aint *)closure)[0]);
                if (target < 0 || target >= bf->code_size) vm_error("Closure target out of bounds at 0x%x", insn_offset);
                if (csp + 1 >= CALL_STACK_CAPACITY) vm_error("Call stack overflow at 0x%x", insn_offset);

                csp++;
                call_stack[csp].ret_ip = ip;
                call_stack[csp].argc = argc;
                call_stack[csp].locals = -1;
                call_stack[csp].args_ptr = sp + argc - 1;
                call_stack[csp].locals_ptr = NULL;
                call_stack[csp].saved_sp = sp + argc + 1;
                call_stack[csp].is_closure = 1;

                ip = target;
                break;
            }
            case 0x56: { // CALL
                int target = read_int32(bf, &ip);
                int argc = read_int32(bf, &ip);
                if (target < 0 || target >= bf->code_size) vm_error("CALL target out of bounds at 0x%x", insn_offset);
                if (argc < 0) vm_error("Negative arity in CALL at 0x%x", insn_offset);
                CHECK_POP(argc);
                if (csp + 1 >= CALL_STACK_CAPACITY) vm_error("Call stack overflow at 0x%x", insn_offset);

                csp++;
                call_stack[csp].ret_ip = ip;
                call_stack[csp].argc = argc;
                call_stack[csp].locals = -1;
                call_stack[csp].args_ptr = sp + argc - 1;
                call_stack[csp].locals_ptr = NULL;
                call_stack[csp].saved_sp = sp + argc;
                call_stack[csp].is_closure = 0;

                ip = target;
                break;
            }
            case 0x57: { // TAG
                int tag_offset = read_int32(bf, &ip);
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative arity %d in TAG at 0x%x", n, insn_offset);
                
                char *tag_str = get_string(bf, tag_offset, insn_offset);
                PUSH(Btag((void *)POP(), LtagHash(tag_str), BOX(n)));
                break;
            }
            case 0x58: { // ARRAY
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative size %d in ARRAY at 0x%x", n, insn_offset);
                PUSH(Barray_patt((void *)POP(), BOX(n)));
                break;
            }
            case 0x59: { // FAIL
                int line = read_int32(bf, &ip);
                int col = read_int32(bf, &ip);
                Bmatch_failure((void *)POP(), (char *)bf->filename, BOX(line), BOX(col));
                exit(EXIT_FAILURE);
            }
            case 0x5A: { // LINE
                (void)read_int32(bf, &ip); // Пропускаем отладочную инфу
                break;
            }
            case 0x70: { // CALL read
                sync_gc_stack(sp);
                PUSH(Lread());
                break;
            }
            case 0x71: { // CALL write
                aint v = POP();
                if (!UNBOXED(v)) vm_error("write expects integer at 0x%x", insn_offset);
                sync_gc_stack(sp);
                PUSH(Lwrite(v));
                break;
            }
            case 0x72: { // CALL length
                aint v = POP();
                sync_gc_stack(sp);
                PUSH(Llength((void *)v));
                break;
            }
            case 0x73: { // CALL string
                CHECK_POP(1);
                sync_gc_stack(sp);
                sp[0] = (aint)Lstring(sp);
                break;
            }
            case 0x74: { // CALL .array
                int n = read_int32(bf, &ip);
                if (n < 0) vm_error("Negative size %d in .array at 0x%x", n, insn_offset);
                CHECK_POP(n);

                for (int i = 0; i < n / 2; ++i) {
                    aint tmp = sp[i];
                    sp[i] = sp[n - 1 - i];
                    sp[n - 1 - i] = tmp;
                }

                sync_gc_stack(sp);
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