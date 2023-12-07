#include "y64asm.h"

#include <assert.h>
#include <stdint-gcc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

line_t *line_head = NULL;
line_t *line_tail = NULL;
int lineno = 0;
int max_byte = 0;

#define err_print(_s, _a...)       \
    do {                           \
        if (lineno < 0)            \
            fprintf(stderr,        \
                    "[--]: "_s     \
                    "\n",          \
                    ##_a);         \
        else                       \
            fprintf(stderr,        \
                    "[L%d]: "_s    \
                    "\n",          \
                    lineno, ##_a); \
    } while (0);

// void set_n_val(byte_t *dest, long val, int bytes)
// {
// 	for (int i = 0; i < bytes; i++) {
// 		dest[i] = val & 0xFF;
// 		val >>= 8;
// 	}
// }

int64_t vmaddr = 0; /* vm addr */

/* register table */
const reg_t reg_table[REG_NONE] = {
    {"%rax", REG_RAX, 4},
    {"%rcx", REG_RCX, 4},
    {"%rdx", REG_RDX, 4},
    {"%rbx", REG_RBX, 4},
    {"%rsp", REG_RSP, 4},
    {"%rbp", REG_RBP, 4},
    {"%rsi", REG_RSI, 4},
    {"%rdi", REG_RDI, 4},
    {"%r8", REG_R8, 3},
    {"%r9", REG_R9, 3},
    {"%r10", REG_R10, 4},
    {"%r11", REG_R11, 4},
    {"%r12", REG_R12, 4},
    {"%r13", REG_R13, 4},
    {"%r14", REG_R14, 4}};
const reg_t *find_register(char *name) {
    int i;
    for (i = 0; i < REG_NONE; i++)
        if (!strncmp(name, reg_table[i].name, reg_table[i].namelen))
            return &reg_table[i];
    return NULL;
}

/* instruction set */
instr_t instr_set[] = {
    {"nop", 3, HPACK(I_NOP, F_NONE), 1},
    {"halt", 4, HPACK(I_HALT, F_NONE), 1},
    {"rrmovq", 6, HPACK(I_RRMOVQ, F_NONE), 2},
    {"cmovle", 6, HPACK(I_RRMOVQ, C_LE), 2},
    {"cmovl", 5, HPACK(I_RRMOVQ, C_L), 2},
    {"cmove", 5, HPACK(I_RRMOVQ, C_E), 2},
    {"cmovne", 6, HPACK(I_RRMOVQ, C_NE), 2},
    {"cmovge", 6, HPACK(I_RRMOVQ, C_GE), 2},
    {"cmovg", 5, HPACK(I_RRMOVQ, C_G), 2},
    {"irmovq", 6, HPACK(I_IRMOVQ, F_NONE), 10},
    {"rmmovq", 6, HPACK(I_RMMOVQ, F_NONE), 10},
    {"mrmovq", 6, HPACK(I_MRMOVQ, F_NONE), 10},
    {"addq", 4, HPACK(I_ALU, A_ADD), 2},
    {"subq", 4, HPACK(I_ALU, A_SUB), 2},
    {"andq", 4, HPACK(I_ALU, A_AND), 2},
    {"xorq", 4, HPACK(I_ALU, A_XOR), 2},
    {"jmp", 3, HPACK(I_JMP, C_YES), 9},
    {"jle", 3, HPACK(I_JMP, C_LE), 9},
    {"jl", 2, HPACK(I_JMP, C_L), 9},
    {"je", 2, HPACK(I_JMP, C_E), 9},
    {"jne", 3, HPACK(I_JMP, C_NE), 9},
    {"jge", 3, HPACK(I_JMP, C_GE), 9},
    {"jg", 2, HPACK(I_JMP, C_G), 9},
    {"call", 4, HPACK(I_CALL, F_NONE), 9},
    {"ret", 3, HPACK(I_RET, F_NONE), 1},
    {"pushq", 5, HPACK(I_PUSHQ, F_NONE), 2},
    {"popq", 4, HPACK(I_POPQ, F_NONE), 2},
    {".byte", 5, HPACK(I_DIRECTIVE, D_DATA), 1},
    {".word", 5, HPACK(I_DIRECTIVE, D_DATA), 2},
    {".long", 5, HPACK(I_DIRECTIVE, D_DATA), 4},
    {".quad", 5, HPACK(I_DIRECTIVE, D_DATA), 8},
    {".pos", 4, HPACK(I_DIRECTIVE, D_POS), 0},
    {".align", 6, HPACK(I_DIRECTIVE, D_ALIGN), 0},
    {NULL, 1, 0, 0}  // end
};

instr_t *find_instr(char *name) {
    int i;
    for (i = 0; instr_set[i].name; i++)
        if (strncmp(instr_set[i].name, name, instr_set[i].len) == 0)
            return &instr_set[i];
    return NULL;
}

/* symbol table (don't forget to init and finit it) */
symbol_t *symtab = NULL;

/*
 * find_symbol: scan table to find the symbol
 * args
 *     name: the name of symbol
 *
 * return
 *     symbol_t: the 'name' symbol
 *     NULL: not exist
 */
symbol_t *find_symbol(char *name) {
    symbol_t *current_symbol = symtab->next;
    while (current_symbol != NULL) {
        int target_name_len = strlen(current_symbol->name);
        if (strncmp(current_symbol->name, name, target_name_len) == 0) {
            return current_symbol;
        }
        current_symbol = current_symbol->next;
    }
    return NULL;
}

/*
 * add_symbol: add a new symbol to the symbol table
 * args
 *     name: the name of symbol
 *
 * return
 *     0: success
 *     -1: error, the symbol has exist
 */
int add_symbol(char *name) {
    /* check duplicate */
    if (find_symbol(name) == NULL) {
        /* create new symbol_t (don't forget to free it)*/
        symbol_t *new_symbol = (symbol_t *)malloc(sizeof(symbol_t));
        /* add the new symbol_t to symbol table */
        new_symbol->name = strdup(name);
        new_symbol->next = symtab->next;
        new_symbol->addr = vmaddr;
        symtab->next = new_symbol;
        return 0;
    }
    return -1;
}

/* relocation table (don't forget to init and finit it) */
reloc_t *reltab = NULL;

/*
 * add_reloc: add a new relocation to the relocation table
 * args
 *     name: the name of symbol
 *
 * return
 *     0: success
 *     -1: error, the symbol has exist
 */
void add_reloc(char *name, bin_t *bin) {
    /* create new reloc_t (don't forget to free it)*/
    reloc_t *new_reloc = (reloc_t *)malloc(sizeof(reloc_t));
    /* add the new reloc_t to relocation table */
    new_reloc->y64bin = bin;
    new_reloc->name = name;
    new_reloc->next = reltab->next;
    reltab->next = new_reloc;
}

/* macro for parsing y64 assembly code */
#define IS_DIGIT(s) ((*(s) >= '0' && *(s) <= '9') || *(s) == '-' || *(s) == '+')
#define IS_LETTER(s) ((*(s) >= 'a' && *(s) <= 'z') || (*(s) >= 'A' && *(s) <= 'Z'))
#define IS_COMMENT(s) (*(s) == '#')
#define IS_REG(s) (*(s) == '%')
#define IS_IMM(s) (*(s) == '$')

#define IS_BLANK(s) (*(s) == ' ' || *(s) == '\t')
#define IS_END(s) (*(s) == '\0')

#define SKIP_BLANK(s)                     \
    do {                                  \
        while (!IS_END(s) && IS_BLANK(s)) \
            (s)++;                        \
    } while (0);
/* return value from different parse_xxx function */
typedef enum { PARSE_ERR = -1,
               PARSE_REG,
               PARSE_DIGIT,
               PARSE_SYMBOL,
               PARSE_MEM,
               PARSE_DELIM,
               PARSE_INSTR,
               PARSE_LABEL } parse_t;

/*
 * parse_instr: parse an expected data token (e.g., 'rrmovq')
 * args
 *     ptr: point to the start of string
 *     inst: point to the inst_t within instr_set
 *
 * return
 *     PARSE_INSTR: success, move 'ptr' to the first char after token,
 *                            and store the pointer of the instruction to 'inst'
 *     PARSE_ERR: error, the value of 'ptr' and 'inst' are undefined
 */
// v

parse_t parse_instr(char **ptr, instr_t **inst) {
    char *instruction_string = *ptr;
    /* skip the blank */
    SKIP_BLANK(instruction_string);
    /* find_instr and check end */
    instr_t *found_inst = find_instr(instruction_string);
    if (found_inst) {
        instruction_string += found_inst->len;  // ?
        // check end
        if (!(IS_END(instruction_string) || IS_BLANK(instruction_string))) {
            return PARSE_ERR;
        }
    } else
        return PARSE_ERR;
    /* set 'ptr' and 'inst' */
    *inst = found_inst;
    *ptr = instruction_string;
    return PARSE_INSTR;
}

/*
 * parse_delim: parse an expected delimiter token (e.g., ',')
 * args
 *     ptr: point to the start of string
 *
 * return
 *     PARSE_DELIM: success, move 'ptr' to the first char after token
 *     PARSE_ERR: error, the value of 'ptr' and 'delim' are undefined
 */

parse_t parse_delim(char **ptr, char delim) {
    /* skip the blank and check */
    char *delim_string = *ptr;
    SKIP_BLANK(delim_string);
    // Check if the following delim is not excpected, or it has come to an end
    if ((*delim_string != delim) || IS_END(delim_string)) {
        err_print("Invalid \'%c\'", delim);
        return PARSE_ERR;
    }
    /* set 'ptr' */
    delim_string++;  // move 'ptr' to the first char after token
    *ptr = delim_string;
    return PARSE_DELIM;
}

/*
 * parse_reg: parse an expected register token (e.g., '%rax')
 * args
 *     ptr: point to the start of string
 *     regid: point to the regid of register
 *
 * return
 *     PARSE_REG: success, move 'ptr' to the first char after token,
 *                         and store the regid to 'regid'
 *     PARSE_ERR: error, the value of 'ptr' and 'regid' are undefined
 */
//
parse_t parse_reg(char **ptr, regid_t *regid) {
    char *curr_str = *ptr;
    /* skip the blank and check */
    SKIP_BLANK(curr_str);
    /* find register */
    // if not register or come to the end
    const reg_t *found_reg = find_register(curr_str);  //
    if (!found_reg || IS_END(curr_str)) {
        err_print("Invalid REG") return PARSE_ERR;
    }
    /* set 'ptr' and 'regid' */
    /* Move the string pointer past the register name and set the register ID */
    curr_str += found_reg->namelen;
    *ptr = curr_str;
    *regid = found_reg->id;
    return PARSE_REG;
}

/*
 * parse_symbol: parse an expected symbol token (e.g., 'Main')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *
 * return
 *     PARSE_SYMBOL: success, move 'ptr' to the first char after token,
 *                               and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr' and 'name' are undefined
 */

parse_t parse_symbol(char **ptr, char **name) {
    /* skip the blank and check */
    char *curr_str = *ptr;
    SKIP_BLANK(curr_str);
    if (IS_END(curr_str)) {
        err_print("Invalid SYMBOL") return PARSE_ERR;
    }
    /* allocate name and copy to it */
    char *symbol_name = (char *)malloc(40 * sizeof(char));

    char *cur = symbol_name;  // need stat pointer of symbol_name later
    while (IS_LETTER(curr_str) || (cur != symbol_name && IS_DIGIT(curr_str))) {
        *cur = *curr_str;
        cur++;
        curr_str++;  // update the pointer
    }
    *cur = '\0';
    /* set 'ptr' and 'name' */
    *name = symbol_name;
    *ptr = curr_str;
    // if the str doesn't correspond to the regulation listed above,there
    //  could be no symbolName eg. start with digit. So we need to check it.
    if (strlen(symbol_name) == 0) {
        return PARSE_ERR;
    }
    return PARSE_SYMBOL;
}

/*
 * parse_digit: parse an expected digit token (e.g., '0x100')
 * args
 *     ptr: point to the start of string
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, move 'ptr' to the first char after token
 *                            and store the value of digit to 'value'
 *     PARSE_ERR: error, the value of 'ptr' and 'value' are undefined
 */
parse_t parse_digit(char **ptr, long *value) {
    /* skip the blank and check */
    char *str = *ptr;
    SKIP_BLANK(str);
    if (IS_END(str) || !IS_DIGIT(str)) {
        return PARSE_ERR;
    }

    char *end_ptr = str;
    /* calculate the digit, (NOTE: see strtoll()) */
    long val = strtoll(str, &end_ptr, 0);
    /* set 'ptr' and 'value' */
    *value = val;
    *ptr = end_ptr;
    return PARSE_DIGIT;
}

/*
 * parse_imm: parse an expected immediate token (e.g., '$0x100' or 'STACK')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, the immediate token is a digit,
 *                            move 'ptr' to the first char after token,
 *                            and store the value of digit to 'value'
 *     PARSE_SYMBOL: success, the immediate token is a symbol,
 *                            move 'ptr' to the first char after token,
 *                            and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
 */

parse_t parse_imm(char **ptr, char **name, long *value) {
    /* skip the blank and check */
    char *input = *ptr;
    parse_t result;

    SKIP_BLANK(input);
    if (IS_END(input)) {
        return PARSE_ERR;
    }
    /* if IS_IMM, then parse the digit */
    if (*input == '$') {
        input++;
        if (!IS_DIGIT(input)) {
            err_print("Invalid Immediate");
            return PARSE_ERR;
        }
        result = parse_digit(&input, value); //  change value directly
    }
    /* if IS_LETTER, then parse the symbol */
    else {
        result = parse_symbol(&input, name); // change name directly
    }

    /* set 'ptr' and 'name' or 'value' */
    *ptr = input; 
    return result;
}

/*
 * parse_mem: parse an expected memory token (e.g., '8(%rbp)')
 * args
 *     ptr: point to the start of string
 *     value: point to the value of digit
 *     regid: point to the regid of register
 *
 * return
 *     PARSE_MEM: success, move 'ptr' to the first char after token,
 *                          and store the value of digit to 'value',
 *                          and store the regid to 'regid'
 *     PARSE_ERR: error, the value of 'ptr', 'value' and 'regid' are undefined
 */
// V
parse_t parse_mem(char **ptr, long *offset, regid_t *regid) {
    /* skip the blank and check */
    char *input = *ptr;
    long offset_value = 0;
    parse_t result;
    SKIP_BLANK(input);

    if (IS_END(input)) {
        err_print("Invalid MEM");
        return PARSE_ERR;
    }

    /* calculate the digit and register, (ex: (%rbp) or 8(%rbp)) */
    if (IS_DIGIT(input) || *input == '-') { 
        result = parse_digit(&input, &offset_value);
        if (result == PARSE_ERR) {
            err_print("Invalid MEM");
            return PARSE_ERR;
        }
    } else {
        offset_value = 0;
    }
    if (*input != '(') {
        err_print("Invalid MEM");
        return PARSE_ERR;
    }
    input++;
    result = parse_reg(&input, regid);
    if (result == PARSE_ERR || *input != ')') {
        err_print("Invalid MEM");
        return PARSE_ERR;
    }
    input++;

    /* set 'ptr', 'value' and 'regid' */
    *ptr = input;
    *offset = offset_value;
    return result;
}
/*
 * parse_data: parse an expected data token (e.g., '0x100' or 'array')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *     value: point to the value of digit
 *
 * return
 *     PARSE_DIGIT: success, data token is a digit,
 *                            and move 'ptr' to the first char after token,
 *                            and store the value of digit to 'value'
 *     PARSE_SYMBOL: success, data token is a symbol,
 *                            and move 'ptr' to the first char after token,
 *                            and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr', 'name' and 'value' are undefined
 */

parse_t parse_data(char **ptr, char **name, long *value) {
    /* skip the blank and check */
    char *str_ptr = *ptr;
    parse_t parse_type = PARSE_ERR;
    SKIP_BLANK(str_ptr);
    if (IS_END(str_ptr)) {
        err_print("Invalid DATA");
        return PARSE_ERR;
    }
    /* if IS_DIGIT, then parse the digit */
    if (IS_DIGIT(str_ptr)) {
        parse_type = parse_digit(&str_ptr, value);
        if (parse_type == PARSE_ERR) {
            err_print("Invalid DATA");
            return PARSE_ERR;
        }
    }
    /* if IS_LETTER, then parse the symbol */
    if (IS_LETTER(str_ptr)) {
        parse_type = parse_symbol(&str_ptr, name);
        if (parse_type == PARSE_ERR) {
            err_print("Invalid DATA");
            return PARSE_ERR;
        }
    }
    /* set 'ptr', 'name' and 'value' */
    *ptr = str_ptr;
    return parse_type;
}
/*
 * parse_label: parse an expected label token (e.g., 'Loop:')
 * args
 *     ptr: point to the start of string
 *     name: point to the name of symbol (should be allocated in this function)
 *
 * return
 *     PARSE_LABEL: success, move 'ptr' to the first char after token
 *                            and allocate and store name to 'name'
 *     PARSE_ERR: error, the value of 'ptr' is undefined
 */
parse_t parse_label(char **ptr, char **name) {
    char *str = *ptr;
    SKIP_BLANK(str);
    if (IS_END(str)) {
        err_print("Invalid LABEL");
        return PARSE_ERR;
    }
    if (parse_symbol(&str, name) == PARSE_ERR && *(str) != ':') {
        err_print("Invalid LABEL");
        return PARSE_ERR;
    }
    str++;
    *ptr = str;
    return PARSE_LABEL;
}

/*
 * parse_line: parse a line of y64 code (e.g., 'Loop: mrmovq (%rcx), %rsi')
 * (you could combine above parse_xxx functions to do it)
 * args
 *     line: point to a line_t data with a line of y64 assembly code
 *
 * return
 *     PARSE_XXX: success, fill line_t with assembled y64 code
 *     PARSE_ERR: error, try to print err information (e.g., instr type and line number)
 */
type_t parse_line(line_t *line)
{

/* when finish parse an instruction or lable, we still need to continue check 
* e.g., 
*  Loop: mrmovl (%rbp), %rcx
*           call SUM  #invoke SUM function */

    char* str = line->y64asm;
    char* name;
    long value;

    instr_t *instr_type;

    regid_t reg_b;
	regid_t reg_a;

    bin_t bin;

    /* skip blank and check IS_END */
    SKIP_BLANK(str);
    if(IS_END(str))
        return line->type;

    /* is a comment ? */
    if(IS_COMMENT(str))
        return line->type;

    if(IS_LETTER(str) || *str=='.')
    {
        char* buffer = str;
        if(parse_instr(&str, &instr_type)==PARSE_ERR){
            str=buffer;
            if(parse_label(&str, &name) == PARSE_ERR)
            {
                line->type=TYPE_ERR;
                return line->type;
            }
            if(add_symbol(name)!=0)
            {
                line->type=TYPE_ERR;
                return line->type;
            }
            SKIP_BLANK(str);
            if(IS_END(str) || IS_COMMENT(str))
            {
                line->y64bin.addr = vmaddr;
                line->y64bin.bytes = 0;
                line->type=TYPE_INS;
                return line->type;
            }
            if(parse_instr(&str, &instr_type)==PARSE_ERR)
            {
                line->type=TYPE_ERR;
                return TYPE_ERR;
            }
        }
        switch(HIGH(instr_type->code)){

            case I_HALT:
            case I_NOP:
            case I_DIRECTIVE:
            case I_RET:
                break;
            case I_RRMOVQ:
            case I_ALU:{
                if(parse_reg(&str, &reg_a)==PARSE_ERR
                || parse_delim(&str, ',')==PARSE_ERR
                || parse_reg(&str, &reg_b)==PARSE_ERR){
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }
                bin.codes[1] = HPACK(reg_a,reg_b);
                break;
            }
            case I_MRMOVQ:
            {
                if(parse_mem(&str, &value, &reg_b) == PARSE_ERR
                || parse_delim(&str,  ',') == PARSE_ERR
                || parse_reg(&str, &reg_a) == PARSE_ERR)
                {
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }
                bin.codes[1]=HPACK(reg_a,reg_b);
                for(int i=0; i<8;i++)
                {
                    bin.codes[i+2]=value & 0xFF;
                    value = value>>8;
                }
                break;
            }
            case I_RMMOVQ:
            {
                if(parse_reg(&str, &reg_a) == PARSE_ERR
                || parse_delim(&str, ',') == PARSE_ERR
                || parse_mem(&str, &value, &reg_b) == PARSE_ERR)
                {
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }
                bin.codes[1] = HPACK(reg_a, reg_b);
                for(int i = 0; i <8; i++){
                    bin.codes[i+2] = value & 0xFF;
                    value = value >> 8;
                }
                break;
            }
            case I_IRMOVQ:
            {
                parse_t condition = parse_imm(&str, &name, &value);
                if(condition == PARSE_ERR
                || parse_delim(&str,  ',') == PARSE_ERR
                || parse_reg(&str, &reg_b) == PARSE_ERR)
                {
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }

                bin.codes[1]=HPACK(REG_NONE, reg_b);

                if(condition == PARSE_SYMBOL){
                    add_reloc(name, &line->y64bin);
                }

                if(condition == PARSE_DIGIT){
                    for(int i = 0; i<8; i++)
                    {
                        bin.codes[i+2] = value & 0xFF;
                        value = value >> 8;
                    }
                }

                break;
            }
            case I_JMP:
            case I_CALL:
            {
                if(parse_symbol(&str, &name) == PARSE_ERR ){
                    err_print("Invalid DEST");
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }
                add_reloc(name, &(line->y64bin));
                break;
            }
            case I_POPQ:
            case I_PUSHQ:
            {
                if(parse_reg(&str, &reg_a) == PARSE_ERR)
                {
                    line->type=TYPE_ERR;
                    return TYPE_ERR;
                }
                bin.codes[1] = HPACK(reg_a, REG_NONE);
                break;
            }
            default: break;
        }
        if(HIGH(instr_type->code) != I_DIRECTIVE)
        {
            bin.addr = vmaddr;
            bin.bytes = instr_type->bytes;
            bin.codes[0] = instr_type->code;
            line->type=TYPE_INS;
            line->y64bin=bin;
            vmaddr += instr_type->bytes;
        }
        else {
            switch(LOW(instr_type->code))
            {
                case D_ALIGN:
                {
                    if(parse_digit(&str, &value) == PARSE_ERR)
                    {
                        line->type=TYPE_ERR;
                        return TYPE_ERR;
                    }
                    vmaddr = (vmaddr + value - 1) / value * value;
                    line->y64bin.addr=vmaddr;
                    line->type=TYPE_INS;
                    line->y64bin.bytes = 0;

                    break;
                }
                case D_POS:
					if (parse_digit(&str, &value) == PARSE_ERR) {
						line->type = TYPE_ERR;
						return line->type;
					}
					vmaddr = value;
                    line->y64bin.addr = vmaddr;
					line->type = TYPE_INS;
					line->y64bin.bytes = 0;
					break;
                case D_DATA:
                {
                    int bytes = instr_type->bytes;
                    parse_t condition = parse_data(&str, &name, &value);
                    if(condition == PARSE_ERR)
                    {
                        line->type=TYPE_ERR;
                        return TYPE_ERR;
                    }
                    if(condition == PARSE_DIGIT)
                    {
                        for (int i = 0; i < bytes; i++)
                        {
                            /* code */
                            line->y64bin.codes[i] = value & 0xFF;
                            value = value>>8;
                        }
                    }
                    if(condition == PARSE_SYMBOL){
                        add_reloc(name, &line->y64bin);
                    }
                    line->y64bin.addr = vmaddr;
                    line->y64bin.bytes = bytes;
					line->type = TYPE_INS;
					vmaddr += bytes;

					break;
                }
                default: break;
            }
        }
    }
    return line->type;
}

/*
 * assemble: assemble an y64 file (e.g., 'asum.ys')
 * args
 *     in: point to input file (an y64 assembly file)
 *
 * return
 *     0: success, assmble the y64 file to a list of line_t
 *     -1: error, try to print err information (e.g., instr type and line number)
 */
int assemble(FILE *in) {
    static char asm_buf[MAX_INSLEN]; /* the current line of asm code */
    line_t *line;
    int slen;
    char *y64asm;

    /* read y64 code line-by-line, and parse them to generate raw y64 binary code list */
    while (fgets(asm_buf, MAX_INSLEN, in) != NULL) {
        slen = strlen(asm_buf);
        while ((asm_buf[slen - 1] == '\n') || (asm_buf[slen - 1] == '\r')) {
            asm_buf[--slen] = '\0'; /* replace terminator */
        }

        /* store y64 assembly code */
        y64asm = (char *)malloc(sizeof(char) * (slen + 1));  // free in finit
        strcpy(y64asm, asm_buf);

        line = (line_t *)malloc(sizeof(line_t));  // free in finit
        memset(line, '\0', sizeof(line_t));

        line->type = TYPE_COMM;  // 默认值是comment
        line->y64asm = y64asm;
        line->next = NULL;

        line_tail->next = line;  // 在尾部插入新line
        line_tail = line;
        lineno++;

        if (parse_line(line) == TYPE_ERR) {
            return -1;
        }
        if (line->type == TYPE_INS) {
            bin_t bin = line->y64bin;
            if (bin.bytes > 0) {
                int byte = bin.addr + bin.bytes;
                if (byte > max_byte) {
                    max_byte = byte;
                }
            }
        }
    }
    lineno = -1;
    return 0;
}

/*
 * relocate: relocate the raw y64 binary code with symbol address
 *
 * return
 *     0: success
 *     -1: error, try to print err information (e.g., addr and symbol)
 */

void saveVal(byte_t *ptr, long value, int bytes) {
    for (int i = 0; i < bytes; ++i) {
        ptr[i] = ((value >> (i * 8)) & 0xff);
    }
}

int relocate(void) {
    reloc_t *tempVal = NULL;

    tempVal = reltab->next;
    while (tempVal) {
        /* find symbol */
        char *tempname = (char *)malloc(strlen(tempVal->name) + 1);
        memcpy(tempname, tempVal->name, strlen(tempVal->name) + 1);
        symbol_t *tempsymbol = find_symbol(tempname);
        if (NULL == tempsymbol) {
            err_print("Unknown symbol:'%s'", tempname);
            return -1;
        }
        /* relocate y64bin according itype */
        byte_t *value;
        switch (HIGH(tempVal->y64bin->codes[0])) {
            case I_IRMOVQ:
                value = &tempVal->y64bin->codes[2];
                break;
            case I_JMP:
            case I_CALL:
                value = &tempVal->y64bin->codes[1];
                break;
            default:
                value = &tempVal->y64bin->codes[0];
                break;
        }
        saveVal(value, tempsymbol->addr, 8);
        /* next */
        tempVal = tempVal->next;
    }
    return 0;
}

/*
 * binfile: generate the y64 binary file
 * args
 *     out: point to output file (an y64 binary file)
 *
 * return
 *     0: success
 *     -1: error
 */
int binfile(FILE *out) {
    /* prepare image with y64 binary code */
    line_t *tmp = line_head->next;
    byte_t *buf = (byte_t *)calloc(max_byte, sizeof(byte_t));
    while (tmp) {
        bin_t bin = tmp->y64bin;
        if (tmp->type == TYPE_INS) {
            memcpy(buf + bin.addr, bin.codes, bin.bytes);
        }
        tmp = tmp->next;
    }

    /* binary write y64 code to output file (NOTE: see fwrite()) */
    fwrite(buf, sizeof(byte_t), max_byte, out);
    free(buf);
    return 0;
}

/* whether print the readable output to screen or not ? */
bool_t screen = FALSE;

static void hexstuff(char *dest, int value, int len) {
    int i;
    for (i = 0; i < len; i++) {
        char c;
        int h = (value >> 4 * i) & 0xF;
        c = h < 10 ? h + '0' : h - 10 + 'a';
        dest[len - i - 1] = c;
    }
}

void print_line(line_t *line) {
    char buf[64];

    /* line format: 0xHHH: cccccccccccc | <line> */
    if (line->type == TYPE_INS) {
        bin_t *y64bin = &line->y64bin;
        int i;

        strcpy(buf, "  0x000:                      | ");

        hexstuff(buf + 4, y64bin->addr, 3);
        if (y64bin->bytes > 0)
            for (i = 0; i < y64bin->bytes; i++)
                hexstuff(buf + 9 + 2 * i, y64bin->codes[i] & 0xFF, 2);
    } else {
        strcpy(buf, "                              | ");
    }

    printf("%s%s\n", buf, line->y64asm);
}

/*
 * print_screen: dump readable binary and assembly code to screen
 * (e.g., Figure 4.8 in ICS book)
 */
void print_screen(void) {
    line_t *tmp = line_head->next;
    while (tmp != NULL) {
        print_line(tmp);
        tmp = tmp->next;
    }
}

/* init and finit */
void init(void) {
    reltab = (reloc_t *)malloc(sizeof(reloc_t));  // free in finit
    memset(reltab, 0, sizeof(reloc_t));

    symtab = (symbol_t *)malloc(sizeof(symbol_t));  // free in finit
    memset(symtab, 0, sizeof(symbol_t));

    line_head = (line_t *)malloc(sizeof(line_t));  // free in finit
    memset(line_head, 0, sizeof(line_t));
    line_tail = line_head;
    lineno = 0;
}

void finit(void) {
    reloc_t *tempVal = NULL;
    do {
        tempVal = reltab->next;
        if (reltab->name)
            free(reltab->name);
        free(reltab);
        reltab = tempVal;
    } while (reltab);

    symbol_t *stmp = NULL;
    do {
        stmp = symtab->next;
        if (symtab->name)
            free(symtab->name);
        free(symtab);
        symtab = stmp;
    } while (symtab);

    line_t *ltmp = NULL;
    do {
        ltmp = line_head->next;
        if (line_head->y64asm)
            free(line_head->y64asm);
        free(line_head);
        line_head = ltmp;
    } while (line_head);
}

static void usage(char *pname) {
    printf("Usage: %s [-v] file.ys\n", pname);
    printf("   -v print the readable output to screen\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    int rootlen;
    char infname[512];
    char outfname[512];
    int nextarg = 1;
    FILE *in = NULL, *out = NULL;

    if (argc < 2)
        usage(argv[0]);

    if (argv[nextarg][0] == '-') {
        char flag = argv[nextarg][1];
        switch (flag) {
            case 'v':
                screen = TRUE;
                nextarg++;
                break;
            default:
                usage(argv[0]);
        }
    }

    /* parse input file name */
    rootlen = strlen(argv[nextarg]) - 3;
    /* only support the .ys file */
    if (strcmp(argv[nextarg] + rootlen, ".ys"))
        usage(argv[0]);

    if (rootlen > 500) {
        err_print("File name too long");
        exit(1);
    }

    /* init */
    init();

    /* assemble .ys file */
    strncpy(infname, argv[nextarg], rootlen);
    strcpy(infname + rootlen, ".ys");
    in = fopen(infname, "r");
    if (!in) {
        err_print("Can't open input file '%s'", infname);
        exit(1);
    }

    if (assemble(in) < 0) {
        err_print("Assemble y64 code error");
        fclose(in);
        exit(1);
    }
    fclose(in);

    /* relocate binary code */
    if (relocate() < 0) {
        err_print("Relocate binary code error");
        exit(1);
    }

    /* generate .bin file */
    strncpy(outfname, argv[nextarg], rootlen);
    strcpy(outfname + rootlen, ".bin");
    out = fopen(outfname, "wb");
    if (!out) {
        err_print("Can't open output file '%s'", outfname);
        exit(1);
    }

    if (binfile(out) < 0) {
        err_print("Generate binary file error");
        fclose(out);
        exit(1);
    }
    fclose(out);

    /* print to screen (.yo file) */
    if (screen)
        print_screen();

    /* finit */
    finit();
    return 0;
}