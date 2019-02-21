from os import listdir
from subprocess import Popen, PIPE

TEST_DIR = 'core/'
EWASM_DIR = 'ewasm/'
TEMPLATE = 'fillerTemplate.yml'
A_MALFORMED = 'assert_malformed'
A_RETURN = 'assert_return'
A_TRAP = 'assert_trap'

F_EXPORT = '(func (export'

avoid = ['token.wast', 'call_indirect.wast', # not working
         ]
         #'i64.wast', 'loop.wast' ] # working

def read_file(fname):
    wast_file = open(fname, 'r')
    content = wast_file.read()
    wast_file.close()

    return content

def write_file(fname, content):
    ofile = open(fname, 'w')
    ofile.write(content)
    ofile.close()

# Convert a string of characters into a list of tokens
def tokenize(chars):
    # Tokenize:
    return chars.replace('(', ' ( ').replace (')', ' ) ').split()


# Numbers become numbers; every other token is a symbol.
def atom(token):
    try:
        return int(token)
    except ValueError:
        try: return float(token)
        except ValueError:
            return token

# Read an expression from a sequence of tokens.
def read_from_tokens(tokens):
    if len(tokens) == 0:
        print('unexpected EOF')
        exit(1)
    token = tokens.pop(0)
    if token == '(':
        L = []
        while tokens[0] != ')':
            L.append(read_from_tokens(tokens))
        tokens.pop(0) # pop off ')'
        return L
    elif token == ')':
        print('unexpected )')
    elif token == ';;':
        L = []
        while tokens[0] != '\n':
            tokens.pop(0)
        L.append(read_from_tokens(tokens))
        return L
    else:
        return atom(token)

def remove_comments(chars):
    # Remove comments
    start = chars.find(';')
    while start >= 0:
        eol = chars[start:].find('\n')
        chars = chars[:start] + chars[start+eol:]
        start = chars.find(';')
    return chars
    
def parse(program):
    program = remove_comments(program)
    program = '(' + program + ')'
    return read_from_tokens(tokenize(program))


def get_memory(module):
    for element in module:
        if element[0] == 'memory':
            return '(memory ' + str(element[1]) + ')\n  '
    return "(memory 1)\n  "

def ast2wast(ast):
    res = ''
    index = 0
    for element in ast:
        if type(element) is int or type(element) is float:
            element = str(element)
            
        if type(element) is list:
            res += ast2wast(element)
        else:
            if index == 0:
                res += '(' + element + ' '
            else:
                res += ' ' + element + ' '
        index += 1
    res += ')'
    return res
def unquote(string):
    while string.find('"') >= 0:
        string = string.replace('"', '')
    return string

def get_typedef(module):
    typedefs = []

    for element in module:
        tdef = {}        
        if element[0] == 'type':
            tdef['name'] = element[1]
            tdef['content'] = element[2]
            typedefs.append(tdef)
    return typedefs

def get_globals(module):
    globals = []
    for element in module:
        glob = {}
        if element[0] == 'global':
            glob['name'] = element[1]
            glob['content'] = element[2:]
            globals.append(glob)
    return globals

def get_tables(module):
    tables = []
    for element in module:
        table = {}
        if element[0] == 'table':
            table['type'] = element[1]
            table['content'] = element[2]
            tables.append(table)
    return tables

def get_assertions(assertions):
    result = []
    
    for a in assertions:
        assertion = {}
        if a[0] == A_RETURN:
            assertion['kind'] = A_RETURN
            if a[1][0] == 'invoke':
                assertion['func'] = unquote(a[1][1])
            assertion['params'] = a[1][2:]
            if len(a) > 2:
                assertion['expect'] = a[2]
            result.append(assertion)
    return result

def clean_content(content):
    result = []
    for element in content:
        if type(element) is list:
            element = clean_content(element)
        if element == 'local.get': element = 'get_local'
        result.append(element)
    return result

def uses_globals(func, content):
    globs = []
    glob = {}
    for block in content:
        if type(block) != str and type(block) != list:
            continue
        if block[0] == 'global.set' or block[0] == 'global.get':
            glob['func'] = func
            glob['name'] = block[1]

            # Checks if global variable has been used and added before:
            found = False
            for g in globs:
                if glob['name'] == g['name']:
                    found = True
                    break
            if not found:
                globs.append(glob)
        if type(block) is list:
            globs += uses_globals(func, block)

    return globs

def get_functions(module):
    functions = []

    for element in module:
        #print('Element: ', element)
        func = {}
        params = []
        restyp = None
        cont = []
        if element[0] == 'func':
            
            for content in element:
                if content[0] == 'export':
                    name = unquote(content[1])

                elif content[0] == 'param':
                    var = ''
                    typ = ''
                    if len(content) > 2:
                        var = content[1]
                        typ = content[2]
                    else:
                        var = ' '
                        typ = content[1]
                    param = (var, typ)
                    params.append(param)

                elif content[0] == 'result':
                    restyp = content[1]
                else:
                    if type(content) is not list:
                        name = unquote(content)
                    else:
                        cont.append(content)
                        
            if name[0] == '$':
                name = name.replace('$', '')
            func['name'] = name
            func['params'] = params
            if restyp:
                func['result'] = restyp
            if type(cont) is list:
                func['content'] = clean_content(cont)
            elif cont != None:
                func['content'] = cont
            globs = uses_globals(func['name'], func['content'])
            if len(globs) > 0:
                func['globals'] = globs
            functions.append(func)
    return functions

def get_function_type(func, functions):
    for f in functions:
        if f['name'] == func and 'result' in f.keys():
            return f['result']
    return None

def generate_storage_key(index):
    index = hex(index)
    index = str(index)
    index = index.replace('0x', '')
    key = index.zfill(64)
    result = ''
    i = 0
    while i < len(key):
        result += '\\' + key[i:i+2]
        i += 2
    return result

def add8(module):
    lines = module.split('\n')
    eight = ' ' * 8
    module = ""
    for line in lines:
        module += eight + line + '\n'
    return module

def build_module(data):
    module = data[0]
    assertions = get_assertions(data[1:])
    functions = get_functions(module)
    types = get_typedef(module)
    tables = get_tables(module)
    globalvars = get_globals(module)
    
    module_header = "(module\n  "
    memory = get_memory(module)
    imports = '(import "ethereum" "storageStore" (func $storageStore (param i32 i32)))\n  '
    exports = '(export "memory" (memory 0))\n  (export "main" (func $main))\n    '
    main_function = "\n  ;;=========== MAIN FUNCTION===================\n  (func $main\n    "
    close_module = "\n   ))"
    data = ""
    calls = ""
    exp = ""
    typedefs = ""
    tabledefs = ""
    
    function_defs = "\n  ;;;;;; Function definitions ;;;;;;\n  "
    for function in functions:
        #
        fdef = ''
        if 'globals' in function.keys():
            for gf in function['globals']:
                for gb in globalvars:
                    if gb['name'] == gf['name']:
                        fdef += "(global " + gb['name'] + ' '
                        for co in gb['content']:
                            fdef += ast2wast(co)
                        fdef += ')\n  '
                        break
        # Generate function definitions
        # function name
        fdef += "(func $" + function['name'] + " "

        # function params
        for param in function['params']:
            fdef += '(param ' + param[0] + ' ' + param[1] + ') '

        # function result
        if 'result' in function.keys():
            fdef += '(result ' + function['result'] + ')'

        # function body
        for cont in function['content']:
            fdef += '\n    ' + ast2wast(cont) 

        fdef += ')\n  '

        function_defs += fdef

    for tp in types:
        typedefs += "(type " + tp['name'] + ' ' + ast2wast(tp['content']) + ')\n  '

    for table in tables:
        tabledefs += "(table " + table['type'] + ' ' + ast2wast(table['content']) + ')\n  '
        
    index = 0
    for assertion in assertions:
        key = generate_storage_key(index)
        data += '(data (i32.const ' + str(index * 32) + ') "' + key + '")\n  '

        # generate calls
        if assertion['kind'] == A_RETURN:
            ftype = get_function_type(assertion['func'], functions)
            if 'expect' in assertion.keys(): 
                calls += '(if (' + ftype + '.eq '
                calls += '(call $' + assertion['func'] + ' '
                for param in assertion['params']:
                    calls += ast2wast(param) + ' '
                calls += ') '
                calls += '(' + assertion['expect'][0] + ' ' + str(assertion['expect'][1]) + '))\n      '
                calls += '(call $storageStore (i32.const %s) (i32.const 32))\n      ' % (str(index * 32))
                calls += '(call $storageStore (i32.const %s) (i32.const 64)))\n    '  % (str(index * 32))
                exp += "            %s: '0x0000000000000000000000000000000000000000000000000000000000000001',\n" % index
            else:
                calls += '(call $' + assertion['func'] + ')\n    '
            index += 1
    module = module_header + imports + memory + data + exports + function_defs + typedefs + tabledefs + main_function + calls + close_module
    #module = add8(module)
    exp = exp[:-2]
    return module, exp

def comment_wast(wast):
    old_wast = wast.split('\n')
    wast = ''
    for line in old_wast:
        wast += '# ' + line + '\n'
    return wast

def generate_filler(name, wasm, wast, exp):
    name = name.split('.')[0]
    filler_name = name + 'Filler.yml'
    template = read_file(TEMPLATE)
    template = template.replace('{fillerName}', name)
    template = template.replace('{module}', wasm)
    template = template.replace('{expect}', exp)
    template = template.replace('{wast}', comment_wast(wast))

    write_file(EWASM_DIR + filler_name, template)


def call_program(arguments):
    process = Popen(arguments, stdout=PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()
    return output, err, exit_code

def compile2wasm(name, wasm):
    (_, err, _) = call_program(['wat2wasm', name, '-o', wasm])
    return err

def getHex(name):
    (output, err, exit_code) = call_program(['binary2hex', name])
    return output, err

def convert_file(fname):
    print('>>> processing', fname)
    content = read_file(TEST_DIR + fname)
    result = parse(content)
    wast, exp = build_module(result)
    write_file('module.wast', wast)
    err = compile2wasm('module.wast', 'module.wasm')
    wasm = ''
    if err == None:
        (wasm, err) = getHex('module.wasm')
        if err != None:
            print('ERROR: ', err)
            exit(2)
        else:
            wasm = '0x' + wasm.decode('utf-8')
            
    generate_filler(fname, wasm, wast, exp)


def main():    
    wast_files = listdir(TEST_DIR)

    for wfile in wast_files:
        if wfile in avoid:
            continue
        convert_file(wfile)
        print('>>> finished ', wfile)
        input()
        #exit()

main()

