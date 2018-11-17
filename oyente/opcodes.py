# list of all opcodes except the PUSHi and DUPi
# opcodes[name] has a list of [value (index), no. of items removed from stack, no. of items added to stack]
opcodes = {
    "STOP": [0x00, 0, 0],
    "ADD": [0x01, 2, 1],
    "MUL": [0x02, 2, 1],
    "SUB": [0x03, 2, 1],
    "DIV": [0x04, 2, 1],
    "SDIV": [0x05, 2, 1],
    "MOD": [0x06, 2, 1],
    "SMOD": [0x07, 2, 1],
    "ADDMOD": [0x08, 3, 1],
    "MULMOD": [0x09, 3, 1],
    "EXP": [0x0a, 2, 1],
    "SIGNEXTEND": [0x0b, 2, 1],
    "LT": [0x10, 2, 1],
    "GT": [0x11, 2, 1],
    "SLT": [0x12, 2, 1],
    "SGT": [0x13, 2, 1],
    "EQ": [0x14, 2, 1],
    "ISZERO": [0x15, 1, 1],
    "AND": [0x16, 2, 1],
    "OR": [0x17, 2, 1],
    "XOR": [0x18, 2, 1],
    "NOT": [0x19, 1, 1],
    "BYTE": [0x1a, 2, 1],
    "SHA3": [0x20, 2, 1],
    "ADDRESS": [0x30, 0, 1],
    "BALANCE": [0x31, 1, 1],
    "ORIGIN": [0x32, 0, 1],
    "CALLER": [0x33, 0, 1],
    "CALLVALUE": [0x34, 0, 1],
    "CALLDATALOAD": [0x35, 1, 1],
    "CALLDATASIZE": [0x36, 0, 1],
    "CALLDATACOPY": [0x37, 3, 0],
    "CODESIZE": [0x38, 0, 1],
    "CODECOPY": [0x39, 3, 0],
    "GASPRICE": [0x3a, 0, 1],
    "EXTCODESIZE": [0x3b, 1, 1],
    "EXTCODECOPY": [0x3c, 4, 0],
    "MCOPY": [0x3d, 3, 0],
    "BLOCKHASH": [0x40, 1, 1],
    "COINBASE": [0x41, 0, 1],
    "TIMESTAMP": [0x42, 0, 1],
    "NUMBER": [0x43, 0, 1],
    "DIFFICULTY": [0x44, 0, 1],
    "GASLIMIT": [0x45, 0, 1],
    "POP": [0x50, 1, 0],
    "MLOAD": [0x51, 1, 1],
    "MSTORE": [0x52, 2, 0],
    "MSTORE8": [0x53, 2, 0],
    "SLOAD": [0x54, 1, 1],
    "SSTORE": [0x55, 2, 0],
    "JUMP": [0x56, 1, 0],
    "JUMPI": [0x57, 2, 0],
    "PC": [0x58, 0, 1],
    "MSIZE": [0x59, 0, 1],
    "GAS": [0x5a, 0, 1],
    "JUMPDEST": [0x5b, 0, 0],
    "SLOADEXT": [0x5c, 2, 1],
    "SSTOREEXT": [0x5d, 3, 0],
    "SLOADBYTESEXT": [0x5c, 4, 0],
    "SSTOREBYTESEXT": [0x5d, 4, 0],
    "LOG0": [0xa0, 2, 0],
    "LOG1": [0xa1, 3, 0],
    "LOG2": [0xa2, 4, 0],
    "LOG3": [0xa3, 5, 0],
    "LOG4": [0xa4, 6, 0],
    "CREATE": [0xf0, 3, 1],
    "CALL": [0xf1, 7, 1],
    "CALLCODE": [0xf2, 7, 1],
    "RETURN": [0xf3, 2, 0],
    "REVERT": [0xfd, 2, 0],
    "ASSERTFAIL": [0xfe, 0, 0],
    "DELEGATECALL": [0xf4, 6, 1],
    "BREAKPOINT": [0xf5, 0, 0],
    "RNGSEED": [0xf6, 1, 1],
    "SSIZEEXT": [0xf7, 2, 1],
    "SLOADBYTES": [0xf8, 3, 0],
    "SSTOREBYTES": [0xf9, 3, 0],
    "SSIZE": [0xfa, 1, 1],
    "STATEROOT": [0xfb, 1, 1],
    "TXEXECGAS": [0xfc, 0, 1],
    "CALLSTATIC": [0xfd, 7, 1],
    "INVALID": [0xfe, 0, 0],  # Not an opcode use to cause an exception
    "SUICIDE": [0xff, 1, 0],
    "---END---": [0x00, 0, 0]
}

stack_v = opcodes.copy()
# new name of SUICIDE
stack_v["SELFDESTRUCT"] = [0xff, 1, 0]
stack_v["RETURNDATASIZE"] = [0x3d, 0, 1]
stack_v["RETURNDATACOPY"] = [0x3e, 3, 0]
stack_v["PUSH1"]          = [0x60, 0, 1]
stack_v["PUSH2"]          = [0x61, 0, 1]
stack_v["PUSH3"]          = [0x62, 0, 1]
stack_v["PUSH4"]          = [0x63, 0, 1]
stack_v["PUSH5"]          = [0x64, 0, 1]
stack_v["PUSH6"]          = [0x65, 0, 1]
stack_v["PUSH7"]          = [0x66, 0, 1]
stack_v["PUSH8"]          = [0x67, 0, 1]
stack_v["PUSH9"]          = [0x68, 0, 1]
stack_v["PUSH10"]         = [0x69, 0, 1]
stack_v["PUSH11"]         = [0x6a, 0, 1]
stack_v["PUSH12"]         = [0x6b, 0, 1]
stack_v["PUSH13"]         = [0x6c, 0, 1]
stack_v["PUSH14"]         = [0x6d, 0, 1]
stack_v["PUSH15"]         = [0x6e, 0, 1]
stack_v["PUSH16"]         = [0x6f, 0, 1]
stack_v["PUSH17"]         = [0x70, 0, 1]
stack_v["PUSH18"]         = [0x71, 0, 1]
stack_v["PUSH19"]         = [0x72, 0, 1]
stack_v["PUSH20"]         = [0x73, 0, 1]
stack_v["PUSH21"]         = [0x74, 0, 1]
stack_v["PUSH22"]         = [0x75, 0, 1]
stack_v["PUSH23"]         = [0x76, 0, 1]
stack_v["PUSH24"]         = [0x77, 0, 1]
stack_v["PUSH25"]         = [0x78, 0, 1]
stack_v["PUSH26"]         = [0x79, 0, 1]
stack_v["PUSH27"]         = [0x7a, 0, 1]
stack_v["PUSH28"]         = [0x7b, 0, 1]
stack_v["PUSH29"]         = [0x7c, 0, 1]
stack_v["PUSH30"]         = [0x7d, 0, 1]
stack_v["PUSH31"]         = [0x7e, 0, 1]
stack_v["PUSH32"]         = [0x7f, 0, 1]
stack_v["DUP1"]           = [0x80,  1,  2]
stack_v["DUP2"]           = [0x81,  2,  3]
stack_v["DUP3"]           = [0x82,  3,  4]
stack_v["DUP4"]           = [0x83,  4,  5]
stack_v["DUP5"]           = [0x84,  5,  6]
stack_v["DUP6"]           = [0x85,  6,  7]
stack_v["DUP7"]           = [0x86,  7,  8]
stack_v["DUP8"]           = [0x87,  8,  9]
stack_v["DUP9"]           = [0x88,  9, 10]
stack_v["DUP10"]          = [0x89, 10, 11]
stack_v["DUP11"]          = [0x8a, 11, 12]
stack_v["DUP12"]          = [0x8b, 12, 13]
stack_v["DUP13"]          = [0x8c, 13, 14]
stack_v["DUP14"]          = [0x8d, 14, 15]
stack_v["DUP15"]          = [0x8e, 15, 16]
stack_v["DUP16"]          = [0x8f, 16, 17]
stack_v["SWAP1"]          = [0x90,  2,  2]
stack_v["SWAP2"]          = [0x91,  3,  3]
stack_v["SWAP3"]          = [0x92,  4,  4]
stack_v["SWAP4"]          = [0x93,  5,  5]
stack_v["SWAP5"]          = [0x94,  6,  6]
stack_v["SWAP6"]          = [0x95,  7,  7]
stack_v["SWAP7"]          = [0x96,  8,  8]
stack_v["SWAP8"]          = [0x97,  9,  9]
stack_v["SWAP9"]          = [0x98, 10, 10]
stack_v["SWAP10"]         = [0x99, 11, 11]
stack_v["SWAP11"]         = [0x9a, 12, 12]
stack_v["SWAP12"]         = [0x9b, 13, 13]
stack_v["SWAP13"]         = [0x9c, 14, 14]
stack_v["SWAP14"]         = [0x9d, 15, 15]
stack_v["SWAP15"]         = [0x9e, 16, 16]
stack_v["SWAP16"]         = [0x9f, 17, 17]
stack_v["DELEGATECALL"]   = [0xf4,  6,  1]

# TO BE UPDATED IF ETHEREUM VM CHANGES their fee structure

# update BYZANTIUM VERSION 2d0661f - 2018-11-0825
# https://ethereum.github.io/yellowpaper/paper.pdf
# appendix G
GCOST = {
    "Gzero": 0,
    "Gbase": 2,
    "Gverylow": 3,
    "Glow": 5,
    "Gmid": 8,
    "Ghigh": 10,

    # "Gextcode": 20,
    "Gextcode": 700, # update

    "Gbalance": 400,

    # "Gsload": 50,
    "Gsload": 200,   # update

    "Gjumpdest": 1,
    "Gsset": 20000,
    "Gsreset": 5000,
    "Rsclear": 15000,

    "Rselfdestruct" : 24000, # new Refund given

    "Rsuicide": 24000, # not exist in new version
                       # shold I comment it ?

    "Gselfdestruct" : 5000, # new gas cost

    "Gsuicide": 5000, # not exist in new version
                      # shold I comment it ?

    "Gcreate": 32000,
    "Gcodedeposit": 200,

    # "Gcall": 40,
    "Gcall" : 700,   # update

    "Gcallvalue": 9000,
    "Gcallstipend": 2300,
    "Gnewaccount": 25000,
    "Gexp": 10,

    # "Gexpbyte": 10,
    "Gexpbyte": 50,  # update

    "Gmemory": 3,
    "Gtxcreate": 32000,
    "Gtxdatazero": 4,
    "Gtxdatanonzero": 68,
    "Gtransaction": 21000,
    "Glog": 375,
    "Glogdata": 8,
    "Glogtopic": 375,
    "Gsha3": 30,
    "Gsha3word": 6,
    "Gcopy": 3,
    "Gblockhash": 20,
    "Gquaddivisor" : 100 # new gas cost
}

Wzero = ("STOP", "RETURN", "REVERT", "ASSERTFAIL")

Wbase = ("ADDRESS", "ORIGIN", "CALLER", "CALLVALUE", "CALLDATASIZE",
         "CODESIZE", "GASPRICE", "COINBASE", "TIMESTAMP", "NUMBER",
         "DIFFICULTY", "GASLIMIT", "POP", "PC", "MSIZE", "GAS")

Wverylow = ("ADD", "SUB", "NOT", "LT", "GT", "SLT", "SGT", "EQ",
            "ISZERO", "AND", "OR", "XOR", "BYTE", "CALLDATALOAD",
            "MLOAD", "MSTORE", "MSTORE8", "PUSH", "DUP", "SWAP")

Wlow = ("MUL", "DIV", "SDIV", "MOD", "SMOD", "SIGNEXTEND")

Wmid = ("ADDMOD", "MULMOD", "JUMP")

Whigh = ("JUMPI")

Wext = ("EXTCODESIZE")

def get_opcode(opcode):
    if opcode in opcodes:
        return opcodes[opcode]
    # check PUSHi
    for i in range(32):
        if opcode == 'PUSH' + str(i + 1):
            return [hex(0x60 + i), 0, 1]

    # check DUPi
    for i in range(16):
        if opcode == 'DUP' + str(i + 1):
            return [hex(0x80 + i), i + 1, i + 2]

    # check SWAPi
    for i in range(16):
        if opcode == 'SWAP' + str(i + 1):
            return [hex(0x90 + i), i + 2, i + 2]
    raise ValueError('Bad Opcode' + opcode)


def get_ins_cost(opcode):
    if opcode in Wzero:
        return GCOST["Gzero"]
    elif opcode in Wbase:
        return GCOST["Gbase"]
    elif opcode in Wverylow or opcode.startswith("PUSH") or opcode.startswith("DUP") or opcode.startswith("SWAP"):
        return GCOST["Gverylow"]
    elif opcode in Wlow:
        return GCOST["Glow"]
    elif opcode in Wmid:
        return GCOST["Gmid"]
    elif opcode in Whigh:
        return GCOST["Ghigh"]
    elif opcode in Wext:
        return GCOST["Gextcode"]
    elif opcode == "EXP":
        return GCOST["Gexp"]
    elif opcode == "SLOAD":
        return GCOST["Gsload"]
    elif opcode == "JUMPDEST":
        return GCOST["Gjumpdest"]
    elif opcode == "SHA3":
        return GCOST["Gsha3"]
    elif opcode == "CREATE":
        return GCOST["Gcreate"]
    elif opcode in ("CALL", "CALLCODE"):
        return GCOST["Gcall"]
    elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
        num_topics = int(opcode[3:])
        return GCOST["Glog"] + num_topics * GCOST["Glogtopic"]
    elif opcode == "EXTCODECOPY":
        return GCOST["Gextcode"]
    elif opcode in ("CALLDATACOPY", "CODECOPY", "RETURNDATACOPY"):
        return GCOST["Gverylow"]
    elif opcode == "BALANCE":
        return GCOST["Gbalance"]
    elif opcode == "BLOCKHASH":
        return GCOST["Gblockhash"]
    return 0
