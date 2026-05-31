import { Instruction, Operand } from './types.js';

export interface CilOpcode {
  op1: number;
  op2: number | null;
  mnemonic: string;
  operandType: 'none' | 'brtarget_s' | 'brtarget' | 'i1' | 'i2' | 'i4' | 'i8' | 'r4' | 'r8' | 'tok' | 'var_s' | 'var' | 'switch';
  description: string;
}

const OPCODES: CilOpcode[] = [
  {
    op1: 88,
    op2: null,
    mnemonic: 'add',
    operandType: 'none',
    description: "Add two values, returning a new value."
  },
  {
    op1: 214,
    op2: null,
    mnemonic: 'add.ovf',
    operandType: 'none',
    description: "Add signed integer values with overflow check."
  },
  {
    op1: 215,
    op2: null,
    mnemonic: 'add.ovf.un',
    operandType: 'none',
    description: "Add unsigned integer values with overflow check."
  },
  {
    op1: 95,
    op2: null,
    mnemonic: 'and',
    operandType: 'none',
    description: "Bitwise AND of two integral values, returns an integral value."
  },
  {
    op1: 254,
    op2: 0,
    mnemonic: 'arglist',
    operandType: 'none',
    description: "Return argument list handle for the current method."
  },
  {
    op1: 59,
    op2: null,
    mnemonic: 'beq',
    operandType: 'brtarget',
    description: "Branch to target if equal."
  },
  {
    op1: 46,
    op2: null,
    mnemonic: 'beq.s',
    operandType: 'brtarget_s',
    description: "Branch to target if equal, short form."
  },
  {
    op1: 60,
    op2: null,
    mnemonic: 'bge',
    operandType: 'brtarget',
    description: "Branch to target if greater than or equal to."
  },
  {
    op1: 47,
    op2: null,
    mnemonic: 'bge.s',
    operandType: 'brtarget_s',
    description: "Branch to target if greater than or equal to, short form."
  },
  {
    op1: 65,
    op2: null,
    mnemonic: 'bge.un',
    operandType: 'brtarget',
    description: "Branch to target if greater than or equal to (unsigned or unordered)."
  },
  {
    op1: 52,
    op2: null,
    mnemonic: 'bge.un.s',
    operandType: 'brtarget_s',
    description: "Branch to target if greater than or equal to (unsigned or unordered), short form."
  },
  {
    op1: 61,
    op2: null,
    mnemonic: 'bgt',
    operandType: 'brtarget',
    description: "Branch to target if greater than."
  },
  {
    op1: 48,
    op2: null,
    mnemonic: 'bgt.s',
    operandType: 'brtarget_s',
    description: "Branch to target if greater than, short form."
  },
  {
    op1: 66,
    op2: null,
    mnemonic: 'bgt.un',
    operandType: 'brtarget',
    description: "Branch to target if greater than (unsigned or unordered)."
  },
  {
    op1: 53,
    op2: null,
    mnemonic: 'bgt.un.s',
    operandType: 'brtarget_s',
    description: "Branch to target if greater than (unsigned or unordered), short form."
  },
  {
    op1: 62,
    op2: null,
    mnemonic: 'ble',
    operandType: 'brtarget',
    description: "Branch to target if less than or equal to."
  },
  {
    op1: 49,
    op2: null,
    mnemonic: 'ble.s',
    operandType: 'brtarget_s',
    description: "Branch to target if less than or equal to, short form."
  },
  {
    op1: 67,
    op2: null,
    mnemonic: 'ble.un',
    operandType: 'brtarget',
    description: "Branch to target if less than or equal to (unsigned or unordered)."
  },
  {
    op1: 54,
    op2: null,
    mnemonic: 'ble.un.s',
    operandType: 'brtarget_s',
    description: "Branch to target if less than or equal to (unsigned or unordered), short form."
  },
  {
    op1: 63,
    op2: null,
    mnemonic: 'blt',
    operandType: 'brtarget',
    description: "Branch to target if less than."
  },
  {
    op1: 50,
    op2: null,
    mnemonic: 'blt.s',
    operandType: 'brtarget_s',
    description: "Branch to target if less than, short form."
  },
  {
    op1: 68,
    op2: null,
    mnemonic: 'blt.un',
    operandType: 'brtarget',
    description: "Branch to target if less than (unsigned or unordered)."
  },
  {
    op1: 55,
    op2: null,
    mnemonic: 'blt.un.s',
    operandType: 'brtarget_s',
    description: "Branch to target if less than (unsigned or unordered), short form."
  },
  {
    op1: 64,
    op2: null,
    mnemonic: 'bne.un',
    operandType: 'brtarget',
    description: "Branch to target if unequal or unordered."
  },
  {
    op1: 51,
    op2: null,
    mnemonic: 'bne.un.s',
    operandType: 'brtarget_s',
    description: "Branch to target if unequal or unordered, short form."
  },
  {
    op1: 140,
    op2: null,
    mnemonic: 'box',
    operandType: 'tok',
    description: "Convert a boxable value to its boxed form."
  },
  {
    op1: 56,
    op2: null,
    mnemonic: 'br',
    operandType: 'brtarget',
    description: "Branch to target."
  },
  {
    op1: 43,
    op2: null,
    mnemonic: 'br.s',
    operandType: 'brtarget_s',
    description: "Branch to target, short form."
  },
  {
    op1: 1,
    op2: null,
    mnemonic: 'break',
    operandType: 'none',
    description: "Inform a debugger that a breakpoint has been reached."
  },
  {
    op1: 57,
    op2: null,
    mnemonic: 'brfalse',
    operandType: 'brtarget',
    description: "Branch to target if value is zero (false)."
  },
  {
    op1: 44,
    op2: null,
    mnemonic: 'brfalse.s',
    operandType: 'brtarget_s',
    description: "Branch to target if value is zero (false), short form."
  },
  {
    op1: 58,
    op2: null,
    mnemonic: 'brinst',
    operandType: 'brtarget',
    description: "Branch to target if value is a non-null object reference (alias for brtrue)."
  },
  {
    op1: 45,
    op2: null,
    mnemonic: 'brinst.s',
    operandType: 'brtarget_s',
    description: "Branch to target if value is a non-null object reference, short form (alias for brtrue.s)."
  },
  {
    op1: 57,
    op2: null,
    mnemonic: 'brnull',
    operandType: 'brtarget',
    description: "Branch to target if value is null (alias for brfalse)."
  },
  {
    op1: 44,
    op2: null,
    mnemonic: 'brnull.s',
    operandType: 'brtarget_s',
    description: "Branch to target if value is null (alias for brfalse.s), short form."
  },
  {
    op1: 58,
    op2: null,
    mnemonic: 'brtrue',
    operandType: 'brtarget',
    description: "Branch to target if value is non-zero (true)."
  },
  {
    op1: 45,
    op2: null,
    mnemonic: 'brtrue.s',
    operandType: 'brtarget_s',
    description: "Branch to target if value is non-zero (true), short form."
  },
  {
    op1: 57,
    op2: null,
    mnemonic: 'brzero',
    operandType: 'brtarget',
    description: "Branch to target if value is zero (alias for brfalse)."
  },
  {
    op1: 44,
    op2: null,
    mnemonic: 'brzero.s',
    operandType: 'brtarget_s',
    description: "Branch to target if value is zero (alias for brfalse.s), short form."
  },
  {
    op1: 40,
    op2: null,
    mnemonic: 'call',
    operandType: 'tok',
    description: "Call method described by method."
  },
  {
    op1: 41,
    op2: null,
    mnemonic: 'calli',
    operandType: 'tok',
    description: "Call method indicated on the stack with arguments described by callsitedescr."
  },
  {
    op1: 111,
    op2: null,
    mnemonic: 'callvirt',
    operandType: 'tok',
    description: "Call a method associated with an object."
  },
  {
    op1: 116,
    op2: null,
    mnemonic: 'castclass',
    operandType: 'tok',
    description: "Cast obj to class."
  },
  {
    op1: 254,
    op2: 1,
    mnemonic: 'ceq',
    operandType: 'none',
    description: "Push 1 (of type int32) if value1 equals value2, else push 0."
  },
  {
    op1: 254,
    op2: 2,
    mnemonic: 'cgt',
    operandType: 'none',
    description: "Push 1 (of type int32) if value1 greater than value2, else push 0."
  },
  {
    op1: 254,
    op2: 3,
    mnemonic: 'cgt.un',
    operandType: 'none',
    description: "Push 1 (of type int32) if value1 greater than value2, unsigned or unordered, else push 0."
  },
  {
    op1: 195,
    op2: null,
    mnemonic: 'ckfinite',
    operandType: 'none',
    description: "Throw ArithmeticException if value is not a finite number."
  },
  {
    op1: 254,
    op2: 4,
    mnemonic: 'clt',
    operandType: 'none',
    description: "Push 1 (of type int32) if value1 lower than value2, else push 0."
  },
  {
    op1: 254,
    op2: 5,
    mnemonic: 'clt.un',
    operandType: 'none',
    description: "Push 1 (of type int32) if value1 lower than value2, unsigned or unordered, else push 0."
  },
  {
    op1: 254,
    op2: 22,
    mnemonic: 'constrained.',
    operandType: 'tok',
    description: "Call a virtual method on a type constrained to be type T."
  },
  {
    op1: 211,
    op2: null,
    mnemonic: 'conv.i',
    operandType: 'none',
    description: "Convert to native int, pushing native int on stack."
  },
  {
    op1: 103,
    op2: null,
    mnemonic: 'conv.i1',
    operandType: 'none',
    description: "Convert to int8, pushing int32 on stack."
  },
  {
    op1: 104,
    op2: null,
    mnemonic: 'conv.i2',
    operandType: 'none',
    description: "Convert to int16, pushing int32 on stack."
  },
  {
    op1: 105,
    op2: null,
    mnemonic: 'conv.i4',
    operandType: 'none',
    description: "Convert to int32, pushing int32 on stack."
  },
  {
    op1: 106,
    op2: null,
    mnemonic: 'conv.i8',
    operandType: 'none',
    description: "Convert to int64, pushing int64 on stack."
  },
  {
    op1: 212,
    op2: null,
    mnemonic: 'conv.ovf.i',
    operandType: 'none',
    description: "Convert to a native int (on the stack as native int) and throw an exception on overflow."
  },
  {
    op1: 138,
    op2: null,
    mnemonic: 'conv.ovf.i.un',
    operandType: 'none',
    description: "Convert unsigned to a native int (on the stack as native int) and throw an exception on overflow."
  },
  {
    op1: 179,
    op2: null,
    mnemonic: 'conv.ovf.i1',
    operandType: 'none',
    description: "Convert to an int8 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 130,
    op2: null,
    mnemonic: 'conv.ovf.i1.un',
    operandType: 'none',
    description: "Convert unsigned to an int8 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 181,
    op2: null,
    mnemonic: 'conv.ovf.i2',
    operandType: 'none',
    description: "Convert to an int16 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 131,
    op2: null,
    mnemonic: 'conv.ovf.i2.un',
    operandType: 'none',
    description: "Convert unsigned to an int16 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 183,
    op2: null,
    mnemonic: 'conv.ovf.i4',
    operandType: 'none',
    description: "Convert to an int32 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 132,
    op2: null,
    mnemonic: 'conv.ovf.i4.un',
    operandType: 'none',
    description: "Convert unsigned to an int32 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 185,
    op2: null,
    mnemonic: 'conv.ovf.i8',
    operandType: 'none',
    description: "Convert to an int64 (on the stack as int64) and throw an exception on overflow."
  },
  {
    op1: 133,
    op2: null,
    mnemonic: 'conv.ovf.i8.un',
    operandType: 'none',
    description: "Convert unsigned to an int64 (on the stack as int64) and throw an exception on overflow."
  },
  {
    op1: 213,
    op2: null,
    mnemonic: 'conv.ovf.u',
    operandType: 'none',
    description: "Convert to a native unsigned int (on the stack as native int) and throw an exception on overflow."
  },
  {
    op1: 139,
    op2: null,
    mnemonic: 'conv.ovf.u.un',
    operandType: 'none',
    description: "Convert unsigned to a native unsigned int (on the stack as native int) and throw an exception on overflow."
  },
  {
    op1: 180,
    op2: null,
    mnemonic: 'conv.ovf.u1',
    operandType: 'none',
    description: "Convert to an unsigned int8 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 134,
    op2: null,
    mnemonic: 'conv.ovf.u1.un',
    operandType: 'none',
    description: "Convert unsigned to an unsigned int8 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 182,
    op2: null,
    mnemonic: 'conv.ovf.u2',
    operandType: 'none',
    description: "Convert to an unsigned int16 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 135,
    op2: null,
    mnemonic: 'conv.ovf.u2.un',
    operandType: 'none',
    description: "Convert unsigned to an unsigned int16 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 184,
    op2: null,
    mnemonic: 'conv.ovf.u4',
    operandType: 'none',
    description: "Convert to an unsigned int32 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 136,
    op2: null,
    mnemonic: 'conv.ovf.u4.un',
    operandType: 'none',
    description: "Convert unsigned to an unsigned int32 (on the stack as int32) and throw an exception on overflow."
  },
  {
    op1: 186,
    op2: null,
    mnemonic: 'conv.ovf.u8',
    operandType: 'none',
    description: "Convert to an unsigned int64 (on the stack as int64) and throw an exception on overflow."
  },
  {
    op1: 137,
    op2: null,
    mnemonic: 'conv.ovf.u8.un',
    operandType: 'none',
    description: "Convert unsigned to an unsigned int64 (on the stack as int64) and throw an exception on overflow."
  },
  {
    op1: 118,
    op2: null,
    mnemonic: 'conv.r.un',
    operandType: 'none',
    description: "Convert unsigned integer to floating-point, pushing F on stack."
  },
  {
    op1: 107,
    op2: null,
    mnemonic: 'conv.r4',
    operandType: 'none',
    description: "Convert to float32, pushing F on stack."
  },
  {
    op1: 108,
    op2: null,
    mnemonic: 'conv.r8',
    operandType: 'none',
    description: "Convert to float64, pushing F on stack."
  },
  {
    op1: 224,
    op2: null,
    mnemonic: 'conv.u',
    operandType: 'none',
    description: "Convert to native unsigned int, pushing native int on stack."
  },
  {
    op1: 210,
    op2: null,
    mnemonic: 'conv.u1',
    operandType: 'none',
    description: "Convert to unsigned int8, pushing int32 on stack."
  },
  {
    op1: 209,
    op2: null,
    mnemonic: 'conv.u2',
    operandType: 'none',
    description: "Convert to unsigned int16, pushing int32 on stack."
  },
  {
    op1: 109,
    op2: null,
    mnemonic: 'conv.u4',
    operandType: 'none',
    description: "Convert to unsigned int32, pushing int32 on stack."
  },
  {
    op1: 110,
    op2: null,
    mnemonic: 'conv.u8',
    operandType: 'none',
    description: "Convert to unsigned int64, pushing int64 on stack."
  },
  {
    op1: 254,
    op2: 23,
    mnemonic: 'cpblk',
    operandType: 'none',
    description: "Copy data from memory to memory."
  },
  {
    op1: 112,
    op2: null,
    mnemonic: 'cpobj',
    operandType: 'tok',
    description: "Copy a value type from src to dest."
  },
  {
    op1: 91,
    op2: null,
    mnemonic: 'div',
    operandType: 'none',
    description: "Divide two values to return a quotient or floating-point result."
  },
  {
    op1: 92,
    op2: null,
    mnemonic: 'div.un',
    operandType: 'none',
    description: "Divide two values, unsigned, returning a quotient."
  },
  {
    op1: 37,
    op2: null,
    mnemonic: 'dup',
    operandType: 'none',
    description: "Duplicate the value on the top of the stack."
  },
  {
    op1: 220,
    op2: null,
    mnemonic: 'endfault',
    operandType: 'none',
    description: "End fault clause of an exception block."
  },
  {
    op1: 254,
    op2: 17,
    mnemonic: 'endfilter',
    operandType: 'none',
    description: "End an exception handling filter clause."
  },
  {
    op1: 220,
    op2: null,
    mnemonic: 'endfinally',
    operandType: 'none',
    description: "End finally clause of an exception block."
  },
  {
    op1: 254,
    op2: 24,
    mnemonic: 'initblk',
    operandType: 'none',
    description: "Set all bytes in a block of memory to a given byte value."
  },
  {
    op1: 254,
    op2: 21,
    mnemonic: 'initobj',
    operandType: 'tok',
    description: "Initialize the value at address dest."
  },
  {
    op1: 117,
    op2: null,
    mnemonic: 'isinst',
    operandType: 'tok',
    description: "Test if obj is an instance of class, returning null or an instance of that class or interface."
  },
  {
    op1: 39,
    op2: null,
    mnemonic: 'jmp',
    operandType: 'tok',
    description: "Exit current method and jump to the specified method."
  },
  {
    op1: 254,
    op2: 9,
    mnemonic: 'ldarg',
    operandType: 'var',
    description: "Load argument numbered num onto the stack."
  },
  {
    op1: 2,
    op2: null,
    mnemonic: 'ldarg.0',
    operandType: 'var',
    description: "Load argument 0 onto the stack."
  },
  {
    op1: 3,
    op2: null,
    mnemonic: 'ldarg.1',
    operandType: 'var',
    description: "Load argument 1 onto the stack."
  },
  {
    op1: 4,
    op2: null,
    mnemonic: 'ldarg.2',
    operandType: 'var',
    description: "Load argument 2 onto the stack."
  },
  {
    op1: 5,
    op2: null,
    mnemonic: 'ldarg.3',
    operandType: 'var',
    description: "Load argument 3 onto the stack."
  },
  {
    op1: 14,
    op2: null,
    mnemonic: 'ldarg.s',
    operandType: 'var_s',
    description: "Load argument numbered num onto the stack, short form."
  },
  {
    op1: 254,
    op2: 10,
    mnemonic: 'ldarga',
    operandType: 'var',
    description: "Fetch the address of argument argNum."
  },
  {
    op1: 15,
    op2: null,
    mnemonic: 'ldarga.s',
    operandType: 'var_s',
    description: "Fetch the address of argument argNum, short form."
  },
  {
    op1: 32,
    op2: null,
    mnemonic: 'ldc.i4',
    operandType: 'i4',
    description: "Push num of type int32 onto the stack as int32."
  },
  {
    op1: 22,
    op2: null,
    mnemonic: 'ldc.i4.0',
    operandType: 'i4',
    description: "Push 0 onto the stack as int32."
  },
  {
    op1: 23,
    op2: null,
    mnemonic: 'ldc.i4.1',
    operandType: 'i4',
    description: "Push 1 onto the stack as int32."
  },
  {
    op1: 24,
    op2: null,
    mnemonic: 'ldc.i4.2',
    operandType: 'i4',
    description: "Push 2 onto the stack as int32."
  },
  {
    op1: 25,
    op2: null,
    mnemonic: 'ldc.i4.3',
    operandType: 'i4',
    description: "Push 3 onto the stack as int32."
  },
  {
    op1: 26,
    op2: null,
    mnemonic: 'ldc.i4.4',
    operandType: 'i4',
    description: "Push 4 onto the stack as int32."
  },
  {
    op1: 27,
    op2: null,
    mnemonic: 'ldc.i4.5',
    operandType: 'i4',
    description: "Push 5 onto the stack as int32."
  },
  {
    op1: 28,
    op2: null,
    mnemonic: 'ldc.i4.6',
    operandType: 'i4',
    description: "Push 6 onto the stack as int32."
  },
  {
    op1: 29,
    op2: null,
    mnemonic: 'ldc.i4.7',
    operandType: 'i4',
    description: "Push 7 onto the stack as int32."
  },
  {
    op1: 30,
    op2: null,
    mnemonic: 'ldc.i4.8',
    operandType: 'i4',
    description: "Push 8 onto the stack as int32."
  },
  {
    op1: 21,
    op2: null,
    mnemonic: 'ldc.i4.m1',
    operandType: 'i4',
    description: "Push -1 onto the stack as int32."
  },
  {
    op1: 21,
    op2: null,
    mnemonic: 'ldc.i4.M1',
    operandType: 'i4',
    description: "Push -1 onto the stack as int32 (alias for ldc.i4.m1)."
  },
  {
    op1: 31,
    op2: null,
    mnemonic: 'ldc.i4.s',
    operandType: 'i1',
    description: "Push num onto the stack as int32, short form."
  },
  {
    op1: 33,
    op2: null,
    mnemonic: 'ldc.i8',
    operandType: 'i8',
    description: "Push num of type int64 onto the stack as int64."
  },
  {
    op1: 34,
    op2: null,
    mnemonic: 'ldc.r4',
    operandType: 'r4',
    description: "Push num of type float32 onto the stack as F."
  },
  {
    op1: 35,
    op2: null,
    mnemonic: 'ldc.r8',
    operandType: 'r8',
    description: "Push num of type float64 onto the stack as F."
  },
  {
    op1: 163,
    op2: null,
    mnemonic: 'ldelem',
    operandType: 'tok',
    description: "Load the element at index onto the top of the stack."
  },
  {
    op1: 151,
    op2: null,
    mnemonic: 'ldelem.i',
    operandType: 'none',
    description: "Load the element with type native int at index onto the top of the stack as a native int."
  },
  {
    op1: 144,
    op2: null,
    mnemonic: 'ldelem.i1',
    operandType: 'none',
    description: "Load the element with type int8 at index onto the top of the stack as an int32."
  },
  {
    op1: 146,
    op2: null,
    mnemonic: 'ldelem.i2',
    operandType: 'none',
    description: "Load the element with type int16 at index onto the top of the stack as an int32."
  },
  {
    op1: 148,
    op2: null,
    mnemonic: 'ldelem.i4',
    operandType: 'none',
    description: "Load the element with type int32 at index onto the top of the stack as an int32."
  },
  {
    op1: 150,
    op2: null,
    mnemonic: 'ldelem.i8',
    operandType: 'none',
    description: "Load the element with type int64 at index onto the top of the stack as an int64."
  },
  {
    op1: 152,
    op2: null,
    mnemonic: 'ldelem.r4',
    operandType: 'none',
    description: "Load the element with type float32 at index onto the top of the stack as an F."
  },
  {
    op1: 153,
    op2: null,
    mnemonic: 'ldelem.r8',
    operandType: 'none',
    description: "Load the element with type float64 at index onto the top of the stack as an F."
  },
  {
    op1: 154,
    op2: null,
    mnemonic: 'ldelem.ref',
    operandType: 'none',
    description: "Load the element at index onto the top of the stack as an O. The type of the O is the same as the element type of the array pushed on the CIL stack."
  },
  {
    op1: 145,
    op2: null,
    mnemonic: 'ldelem.u1',
    operandType: 'none',
    description: "Load the element with type unsigned int8 at index onto the top of the stack as an int32."
  },
  {
    op1: 147,
    op2: null,
    mnemonic: 'ldelem.u2',
    operandType: 'none',
    description: "Load the element with type unsigned int16 at index onto the top of the stack as an int32."
  },
  {
    op1: 149,
    op2: null,
    mnemonic: 'ldelem.u4',
    operandType: 'none',
    description: "Load the element with type unsigned int32 at index onto the top of the stack as an int32."
  },
  {
    op1: 150,
    op2: null,
    mnemonic: 'ldelem.u8',
    operandType: 'none',
    description: "Load the element with type unsigned int64 at index onto the top of the stack as an int64 (alias for ldelem.i8)."
  },
  {
    op1: 143,
    op2: null,
    mnemonic: 'ldelema',
    operandType: 'tok',
    description: "Load the address of element at index onto the top of the stack."
  },
  {
    op1: 123,
    op2: null,
    mnemonic: 'ldfld',
    operandType: 'tok',
    description: "Push the value of field of object (or value type) obj, onto the stack."
  },
  {
    op1: 124,
    op2: null,
    mnemonic: 'ldflda',
    operandType: 'tok',
    description: "Push the address of field of object obj on the stack."
  },
  {
    op1: 254,
    op2: 6,
    mnemonic: 'ldftn',
    operandType: 'tok',
    description: "Push a pointer to a method referenced by method, on the stack."
  },
  {
    op1: 77,
    op2: null,
    mnemonic: 'ldind.i',
    operandType: 'none',
    description: "Indirect load value of type native int as native int on the stack."
  },
  {
    op1: 70,
    op2: null,
    mnemonic: 'ldind.i1',
    operandType: 'none',
    description: "Indirect load value of type int8 as int32 on the stack."
  },
  {
    op1: 72,
    op2: null,
    mnemonic: 'ldind.i2',
    operandType: 'none',
    description: "Indirect load value of type int16 as int32 on the stack."
  },
  {
    op1: 74,
    op2: null,
    mnemonic: 'ldind.i4',
    operandType: 'none',
    description: "Indirect load value of type int32 as int32 on the stack."
  },
  {
    op1: 76,
    op2: null,
    mnemonic: 'ldind.i8',
    operandType: 'none',
    description: "Indirect load value of type int64 as int64 on the stack."
  },
  {
    op1: 78,
    op2: null,
    mnemonic: 'ldind.r4',
    operandType: 'none',
    description: "Indirect load value of type float32 as F on the stack."
  },
  {
    op1: 79,
    op2: null,
    mnemonic: 'ldind.r8',
    operandType: 'none',
    description: "Indirect load value of type float64 as F on the stack."
  },
  {
    op1: 80,
    op2: null,
    mnemonic: 'ldind.ref',
    operandType: 'none',
    description: "Indirect load value of type object ref as O on the stack."
  },
  {
    op1: 71,
    op2: null,
    mnemonic: 'ldind.u1',
    operandType: 'none',
    description: "Indirect load value of type unsigned int8 as int32 on the stack."
  },
  {
    op1: 73,
    op2: null,
    mnemonic: 'ldind.u2',
    operandType: 'none',
    description: "Indirect load value of type unsigned int16 as int32 on the stack."
  },
  {
    op1: 75,
    op2: null,
    mnemonic: 'ldind.u4',
    operandType: 'none',
    description: "Indirect load value of type unsigned int32 as int32 on the stack."
  },
  {
    op1: 76,
    op2: null,
    mnemonic: 'ldind.u8',
    operandType: 'none',
    description: "Indirect load value of type unsigned int64 as int64 on the stack (alias for ldind.i8)."
  },
  {
    op1: 142,
    op2: null,
    mnemonic: 'ldlen',
    operandType: 'none',
    description: "Push the length (of type native unsigned int) of array on the stack."
  },
  {
    op1: 254,
    op2: 12,
    mnemonic: 'ldloc',
    operandType: 'var',
    description: "Load local variable of index indx onto stack."
  },
  {
    op1: 6,
    op2: null,
    mnemonic: 'ldloc.0',
    operandType: 'var',
    description: "Load local variable 0 onto stack."
  },
  {
    op1: 7,
    op2: null,
    mnemonic: 'ldloc.1',
    operandType: 'var',
    description: "Load local variable 1 onto stack."
  },
  {
    op1: 8,
    op2: null,
    mnemonic: 'ldloc.2',
    operandType: 'var',
    description: "Load local variable 2 onto stack."
  },
  {
    op1: 9,
    op2: null,
    mnemonic: 'ldloc.3',
    operandType: 'var',
    description: "Load local variable 3 onto stack."
  },
  {
    op1: 17,
    op2: null,
    mnemonic: 'ldloc.s',
    operandType: 'var_s',
    description: "Load local variable of index indx onto stack, short form."
  },
  {
    op1: 254,
    op2: 13,
    mnemonic: 'ldloca',
    operandType: 'var',
    description: "Load address of local variable with index indx."
  },
  {
    op1: 18,
    op2: null,
    mnemonic: 'ldloca.s',
    operandType: 'var_s',
    description: "Load address of local variable with index indx, short form."
  },
  {
    op1: 20,
    op2: null,
    mnemonic: 'ldnull',
    operandType: 'none',
    description: "Push a null reference on the stack."
  },
  {
    op1: 113,
    op2: null,
    mnemonic: 'ldobj',
    operandType: 'tok',
    description: "Copy the value stored at address src to the stack."
  },
  {
    op1: 126,
    op2: null,
    mnemonic: 'ldsfld',
    operandType: 'tok',
    description: "Push the value of the static field on the stack."
  },
  {
    op1: 127,
    op2: null,
    mnemonic: 'ldsflda',
    operandType: 'tok',
    description: "Push the address of the static field, field, on the stack."
  },
  {
    op1: 114,
    op2: null,
    mnemonic: 'ldstr',
    operandType: 'tok',
    description: "Push a string object for the literal string."
  },
  {
    op1: 208,
    op2: null,
    mnemonic: 'ldtoken',
    operandType: 'tok',
    description: "Convert metadata token to its runtime representation."
  },
  {
    op1: 254,
    op2: 7,
    mnemonic: 'ldvirtftn',
    operandType: 'tok',
    description: "Push address of virtual method on the stack."
  },
  {
    op1: 221,
    op2: null,
    mnemonic: 'leave',
    operandType: 'brtarget',
    description: "Exit a protected region of code."
  },
  {
    op1: 222,
    op2: null,
    mnemonic: 'leave.s',
    operandType: 'brtarget_s',
    description: "Exit a protected region of code, short form."
  },
  {
    op1: 254,
    op2: 15,
    mnemonic: 'localloc',
    operandType: 'none',
    description: "Allocate space from the local memory pool."
  },
  {
    op1: 198,
    op2: null,
    mnemonic: 'mkrefany',
    operandType: 'tok',
    description: "Push a typed reference to ptr of type class onto the stack."
  },
  {
    op1: 90,
    op2: null,
    mnemonic: 'mul',
    operandType: 'none',
    description: "Multiply values."
  },
  {
    op1: 216,
    op2: null,
    mnemonic: 'mul.ovf',
    operandType: 'none',
    description: "Multiply signed integer values. Signed result shall fit in same size."
  },
  {
    op1: 217,
    op2: null,
    mnemonic: 'mul.ovf.un',
    operandType: 'none',
    description: "Multiply unsigned integer values. Unsigned result shall fit in same size."
  },
  {
    op1: 101,
    op2: null,
    mnemonic: 'neg',
    operandType: 'none',
    description: "Negate value."
  },
  {
    op1: 141,
    op2: null,
    mnemonic: 'newarr',
    operandType: 'tok',
    description: "Create a new array with elements of type etype."
  },
  {
    op1: 115,
    op2: null,
    mnemonic: 'newobj',
    operandType: 'tok',
    description: "Allocate an uninitialized object or value type and call ctor."
  },
  {
    op1: 254,
    op2: 25,
    mnemonic: 'no.',
    operandType: 'none',
    description: "The specified fault check(s) normally performed as part of the execution of the subsequent instruction can/shall be skipped."
  },
  {
    op1: 0,
    op2: null,
    mnemonic: 'nop',
    operandType: 'none',
    description: "Do nothing (No operation)."
  },
  {
    op1: 102,
    op2: null,
    mnemonic: 'not',
    operandType: 'none',
    description: "Bitwise complement."
  },
  {
    op1: 96,
    op2: null,
    mnemonic: 'or',
    operandType: 'none',
    description: "Bitwise OR of two integer values, returns an integer."
  },
  {
    op1: 38,
    op2: null,
    mnemonic: 'pop',
    operandType: 'none',
    description: "Pop value from the stack."
  },
  {
    op1: 254,
    op2: 30,
    mnemonic: 'readonly.',
    operandType: 'none',
    description: "Specify that the subsequent array address operation performs no type check at runtime, and that it returns a controlled-mutability managed pointer."
  },
  {
    op1: 254,
    op2: 29,
    mnemonic: 'refanytype',
    operandType: 'none',
    description: "Push the type token stored in a typed reference."
  },
  {
    op1: 194,
    op2: null,
    mnemonic: 'refanyval',
    operandType: 'none',
    description: "Push the address stored in a typed reference."
  },
  {
    op1: 93,
    op2: null,
    mnemonic: 'rem',
    operandType: 'none',
    description: "Remainder when dividing one value by another."
  },
  {
    op1: 94,
    op2: null,
    mnemonic: 'rem.un',
    operandType: 'none',
    description: "Remainder when dividing one unsigned value by another."
  },
  {
    op1: 42,
    op2: null,
    mnemonic: 'ret',
    operandType: 'none',
    description: "Return from method, possibly with a value."
  },
  {
    op1: 254,
    op2: 26,
    mnemonic: 'rethrow',
    operandType: 'none',
    description: "Rethrow the current exception."
  },
  {
    op1: 98,
    op2: null,
    mnemonic: 'shl',
    operandType: 'none',
    description: "Shift an integer left (shifting in zeros), return an integer."
  },
  {
    op1: 99,
    op2: null,
    mnemonic: 'shr',
    operandType: 'none',
    description: "Shift an integer right (shift in sign), return an integer."
  },
  {
    op1: 100,
    op2: null,
    mnemonic: 'shr.un',
    operandType: 'none',
    description: "Shift an integer right (shift in zero), return an integer."
  },
  {
    op1: 254,
    op2: 28,
    mnemonic: 'sizeof',
    operandType: 'tok',
    description: "Push the size, in bytes, of a type as an unsigned int32."
  },
  {
    op1: 254,
    op2: 11,
    mnemonic: 'starg',
    operandType: 'var',
    description: "Store value to the argument numbered num."
  },
  {
    op1: 16,
    op2: null,
    mnemonic: 'starg.s',
    operandType: 'var_s',
    description: "Store value to the argument numbered num, short form."
  },
  {
    op1: 164,
    op2: null,
    mnemonic: 'stelem',
    operandType: 'tok',
    description: "Replace array element at index with the value on the stack."
  },
  {
    op1: 155,
    op2: null,
    mnemonic: 'stelem.i',
    operandType: 'none',
    description: "Replace array element at index with the native int value on the stack."
  },
  {
    op1: 156,
    op2: null,
    mnemonic: 'stelem.i1',
    operandType: 'none',
    description: "Replace array element at index with the int8 value on the stack."
  },
  {
    op1: 157,
    op2: null,
    mnemonic: 'stelem.i2',
    operandType: 'none',
    description: "Replace array element at index with the int16 value on the stack."
  },
  {
    op1: 158,
    op2: null,
    mnemonic: 'stelem.i4',
    operandType: 'none',
    description: "Replace array element at index with the int32 value on the stack."
  },
  {
    op1: 159,
    op2: null,
    mnemonic: 'stelem.i8',
    operandType: 'none',
    description: "Replace array element at index with the int64 value on the stack."
  },
  {
    op1: 160,
    op2: null,
    mnemonic: 'stelem.r4',
    operandType: 'none',
    description: "Replace array element at index with the float32 value on the stack."
  },
  {
    op1: 161,
    op2: null,
    mnemonic: 'stelem.r8',
    operandType: 'none',
    description: "Replace array element at index with the float64 value on the stack."
  },
  {
    op1: 162,
    op2: null,
    mnemonic: 'stelem.ref',
    operandType: 'none',
    description: "Replace array element at index with the ref value on the stack."
  },
  {
    op1: 125,
    op2: null,
    mnemonic: 'stfld',
    operandType: 'tok',
    description: "Replace the value of field of the object obj with value."
  },
  {
    op1: 223,
    op2: null,
    mnemonic: 'stind.i',
    operandType: 'none',
    description: "Store value of type native int into memory at address."
  },
  {
    op1: 82,
    op2: null,
    mnemonic: 'stind.i1',
    operandType: 'none',
    description: "Store value of type int8 into memory at address."
  },
  {
    op1: 83,
    op2: null,
    mnemonic: 'stind.i2',
    operandType: 'none',
    description: "Store value of type int16 into memory at address."
  },
  {
    op1: 84,
    op2: null,
    mnemonic: 'stind.i4',
    operandType: 'none',
    description: "Store value of type int32 into memory at address."
  },
  {
    op1: 85,
    op2: null,
    mnemonic: 'stind.i8',
    operandType: 'none',
    description: "Store value of type int64 into memory at address."
  },
  {
    op1: 86,
    op2: null,
    mnemonic: 'stind.r4',
    operandType: 'none',
    description: "Store value of type float32 into memory at address."
  },
  {
    op1: 87,
    op2: null,
    mnemonic: 'stind.r8',
    operandType: 'none',
    description: "Store value of type float64 into memory at address."
  },
  {
    op1: 81,
    op2: null,
    mnemonic: 'stind.ref',
    operandType: 'none',
    description: "Store value of type object ref (type O) into memory at address."
  },
  {
    op1: 254,
    op2: 14,
    mnemonic: 'stloc',
    operandType: 'var',
    description: "Pop a value from stack into local variable indx."
  },
  {
    op1: 10,
    op2: null,
    mnemonic: 'stloc.0',
    operandType: 'var',
    description: "Pop a value from stack into local variable 0."
  },
  {
    op1: 11,
    op2: null,
    mnemonic: 'stloc.1',
    operandType: 'var',
    description: "Pop a value from stack into local variable 1."
  },
  {
    op1: 12,
    op2: null,
    mnemonic: 'stloc.2',
    operandType: 'var',
    description: "Pop a value from stack into local variable 2."
  },
  {
    op1: 13,
    op2: null,
    mnemonic: 'stloc.3',
    operandType: 'var',
    description: "Pop a value from stack into local variable 3."
  },
  {
    op1: 19,
    op2: null,
    mnemonic: 'stloc.s',
    operandType: 'var_s',
    description: "Pop a value from stack into local variable indx, short form."
  },
  {
    op1: 129,
    op2: null,
    mnemonic: 'stobj',
    operandType: 'tok',
    description: "Store a value of type typeTok at an address."
  },
  {
    op1: 128,
    op2: null,
    mnemonic: 'stsfld',
    operandType: 'tok',
    description: "Replace the value of the static field with val."
  },
  {
    op1: 89,
    op2: null,
    mnemonic: 'sub',
    operandType: 'none',
    description: "Subtract value2 from value1, returning a new value."
  },
  {
    op1: 218,
    op2: null,
    mnemonic: 'sub.ovf',
    operandType: 'none',
    description: "Subtract native int from a native int. Signed result shall fit in same size."
  },
  {
    op1: 219,
    op2: null,
    mnemonic: 'sub.ovf.un',
    operandType: 'none',
    description: "Subtract native unsigned int from a native unsigned int. Unsigned result shall fit in same size."
  },
  {
    op1: 69,
    op2: null,
    mnemonic: 'switch',
    operandType: 'switch',
    description: "Jump to one of n values."
  },
  {
    op1: 254,
    op2: 20,
    mnemonic: 'tail.',
    operandType: 'none',
    description: "Subsequent call terminates current method."
  },
  {
    op1: 122,
    op2: null,
    mnemonic: 'throw',
    operandType: 'none',
    description: "Throw an exception."
  },
  {
    op1: 254,
    op2: 18,
    mnemonic: 'unaligned.',
    operandType: 'i1',
    description: "Subsequent pointer instruction might be unaligned."
  },
  {
    op1: 121,
    op2: null,
    mnemonic: 'unbox',
    operandType: 'tok',
    description: "Extract a value-type from obj, its boxed representation, and push a controlled-mutability managed pointer to it to the top of the stack."
  },
  {
    op1: 165,
    op2: null,
    mnemonic: 'unbox.any',
    operandType: 'tok',
    description: "Extract a value-type from obj, its boxed representation, and copy to the top of the stack."
  },
  {
    op1: 254,
    op2: 19,
    mnemonic: 'volatile.',
    operandType: 'none',
    description: "Subsequent pointer reference is volatile."
  },
  {
    op1: 97,
    op2: null,
    mnemonic: 'xor',
    operandType: 'none',
    description: "Bitwise XOR of integer values, returns an integer."
  }
];

// Quick lookup maps
const singleByteOpcodes = new Map<number, CilOpcode>();
const twoByteOpcodes = new Map<number, CilOpcode>();

for (const op of OPCODES) {
  if (op.op2 === null) {
    singleByteOpcodes.set(op.op1, op);
  } else {
    twoByteOpcodes.set(op.op2, op);
  }
}

export function disassembleCil(
  data: Uint8Array,
  baseAddress: number
): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  function getInt8(offset: number): number {
    const val = data[offset];
    return val >= 128 ? val - 256 : val;
  }

  function getUint8(offset: number): number {
    return data[offset];
  }

  function getUint16(offset: number): number {
    return data[offset] | (data[offset + 1] << 8);
  }

  function getInt32(offset: number): number {
    const val = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
    return val | 0;
  }

  function getUint32(offset: number): number {
    return (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
  }

  function getBigInt64(offset: number): bigint {
    const low = getUint32(offset);
    const high = getUint32(offset + 4);
    return (BigInt(high) << 32n) | BigInt(low);
  }

  function getFloat32(offset: number): number {
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    for (let k = 0; k < 4; k++) {
      view.setUint8(k, data[offset + k]);
    }
    return view.getFloat32(0, true);
  }

  function getFloat64(offset: number): number {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    for (let k = 0; k < 8; k++) {
      view.setUint8(k, data[offset + k]);
    }
    return view.getFloat64(0, true);
  }

  while (i < data.length) {
    const addr = baseAddress + i;
    const startIdx = i;

    let op1 = data[i];
    let op2: number | null = null;
    let opcodeInfo: CilOpcode | undefined;

    if (op1 === 0xFE && i + 1 < data.length) {
      op2 = data[i + 1];
      opcodeInfo = twoByteOpcodes.get(op2);
    } else {
      opcodeInfo = singleByteOpcodes.get(op1);
    }

    if (!opcodeInfo) {
      // Unknown opcode, treat byte as raw data
      const rawByte = data[i];
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: `0x${rawByte.toString(16).padStart(2, '0')}`,
        operands: [],
        size: 1,
      });
      i++;
      continue;
    }

    const opSize = opcodeInfo.op2 === null ? 1 : 2;
    i += opSize;

    let opStr = '';
    const operands: Operand[] = [];
    let valid = true;

    switch (opcodeInfo.operandType) {
      case 'none': {
        break;
      }
      case 'brtarget_s': {
        if (i < data.length) {
          const offset = getInt8(i);
          i += 1;
          const target = addr + opSize + 1 + offset;
          opStr = `0x${target.toString(16).padStart(8, '0')}`;
          operands.push({ type: 'imm', imm: target });
        } else {
          valid = false;
        }
        break;
      }
      case 'brtarget': {
        if (i + 4 <= data.length) {
          const offset = getInt32(i);
          i += 4;
          const target = addr + opSize + 4 + offset;
          opStr = `0x${target.toString(16).padStart(8, '0')}`;
          operands.push({ type: 'imm', imm: target });
        } else {
          valid = false;
        }
        break;
      }
      case 'i1': {
        if (i < data.length) {
          const val = getInt8(i);
          i += 1;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i2': {
        if (i + 2 <= data.length) {
          const val = getUint16(i);
          i += 2;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i4': {
        if (i + 4 <= data.length) {
          const val = getInt32(i);
          i += 4;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'i8': {
        if (i + 8 <= data.length) {
          const val = getBigInt64(i);
          i += 8;
          opStr = val.toString() + 'n';
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'r4': {
        if (i + 4 <= data.length) {
          const val = getFloat32(i);
          i += 4;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'r8': {
        if (i + 8 <= data.length) {
          const val = getFloat64(i);
          i += 8;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'tok': {
        if (i + 4 <= data.length) {
          const val = getUint32(i);
          i += 4;
          opStr = `0x${val.toString(16).padStart(8, '0')}`;
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'var_s': {
        if (i < data.length) {
          const val = getUint8(i);
          i += 1;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'var': {
        if (i + 2 <= data.length) {
          const val = getUint16(i);
          i += 2;
          opStr = val.toString();
          operands.push({ type: 'imm', imm: val });
        } else {
          valid = false;
        }
        break;
      }
      case 'switch': {
        if (i + 4 <= data.length) {
          const count = getUint32(i);
          i += 4;
          if (i + count * 4 <= data.length) {
            const targets: number[] = [];
            const targetStrings: string[] = [];
            const instrAfterSwitch = addr + opSize + 4 + count * 4;
            for (let c = 0; c < count; c++) {
              const offset = getInt32(i + c * 4);
              const target = instrAfterSwitch + offset;
              targets.push(target);
              targetStrings.push(`0x${target.toString(16).padStart(8, '0')}`);
              operands.push({ type: 'imm', imm: target });
            }
            i += count * 4;
            opStr = `(${targetStrings.join(', ')})`;
          } else {
            valid = false;
          }
        } else {
          valid = false;
        }
        break;
      }
    }

    if (!valid) {
      // If we don't have enough bytes, roll back and treat remaining bytes as db
      i = startIdx;
      const rawByte = data[i];
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: `0x${rawByte.toString(16).padStart(2, '0')}`,
        operands: [],
        size: 1,
      });
      i++;
      continue;
    }

    instructions.push({
      address: addr,
      bytes: data.slice(startIdx, i),
      mnemonic: opcodeInfo.mnemonic,
      opStr,
      operands,
      size: i - startIdx,
    });
  }

  return instructions;
}
