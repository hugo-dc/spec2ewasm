#!/bin/python

from os import listdir

TEST_DIR = 'core/'
EWASM_DIR = 'ewasm/'
TEMPLATE = 'fillerTemplate.yml'
A_MALFORMED = 'assert_malformed'
A_RETURN = 'assert_return'
A_TRAP = 'assert_trap'

F_EXPORT = '(func (export'

avoid = ['token.wast', 'call_indirect.wast']

def read_file(fname):
    wast_file = open(fname, 'r')
    content = wast_file.read()
    wast_file.close()

    return content

def write_file(fname, content):
    ofile = open(fname, 'w')
    ofile.write(content)
    ofile.close()

def get_function_name(line):
    #print('>> get_function_name [' + line + ']')
    name = extract_quoted(line)[0]
    return name

def get_function_content(line):
    start = line.find('") ') + 3
    end = len(line) - 1
    content = line[start:end]
    content = content.replace('local.get', 'get_local')
    return content

def extract_quoted(line):
    #print('>> extract_quoted [' + line + ']')
    quoted = []
    value = ''
    in_word = False
    for c in line:
        if c == '"' and in_word == True:
            in_word = False
            quoted.append(value)
            value = ''
            continue
        if c == '"' and in_word == False:
            in_word = True
            continue
        if in_word:
            value += c

    return quoted

def extract_code_blocks(line):
    #print('>> extract_code_blocks [' + line + ']')
    line = line.strip()
    balance = 0
    blocks = []
    block = ""
    for c in line:
        if c == ' ' and balance == 0:
            continue
        if c == '(':
            balance += 1
        if c == ')':
            balance -= 1
        if balance > 0 or c == ')':
            block += c
        if balance == 0 and block != '':
            blocks.append(block)
            block = ""

    return blocks
    
def get_invoke_params(line):
    #print('>> get_invoke_params (' + line + ')')
    name = extract_quoted(line)[0]
    target = '(invoke "' + name + '"'
    line = line.replace(target, '').strip()
    start = 0
    params = extract_code_blocks(line[start:])

    return params

def extract_value(kind, line):
    line = line.strip()
    line = line.split(' ')
    return line[1]

def format_assertion(raw_assertion):
    #print('->> format_assertion [' + raw_assertion + ']')
    assertion = {}
    if raw_assertion.find('invoke') >= 0:
        assertion['kind'] = 'invoke'
        assertion['func'] = extract_quoted(raw_assertion)[0]
        assertion['params'] = get_invoke_params(raw_assertion)
        return assertion
    if raw_assertion.find('i64.const') >= 0:
        assertion['kind'] = 'i64'
        assertion['value'] = extract_value('i64', raw_assertion)
        return assertion
    if raw_assertion.find('i32.const') >= 0:
        assertion['kind'] = 'i32'
        assertion['value'] = extract_value('i32', raw_assertion)
        return assertion
    assertion['kind'] = 'unknown'
    assertion['value'] = raw_assertion
    return assertion

def get_assertion_block(line, index):
    #print('>> get_assertion_block [' + line + ', ' + str(index) + ']')
    line = line.replace('(' + A_RETURN, '')
    line = line.replace('(' + A_TRAP, '')
    line = line.strip()
    assertion = {}

    blocks = extract_code_blocks(line)
    left = blocks[index]
    assertion = format_assertion(left)
    return assertion
    
def get_assertion_left(line):
    #print('\n>> get_assertion_left [' + line + ']')
    return get_assertion_block(line, 0)

def get_assertion_right(line):
    #print('>> get_assertion_right [' + line + ']')
    return get_assertion_block(line, 1)

def get_assertion_exception(line):
    excep = extract_quoted(line)[1]
    return excep

def get_function_result(line):
    start = line.find('(result')
    end = line[start:].find(')') + start
    result = (line[start + 7: end]).strip()
    return result
    
    
def parse_content(content):
    content = content.split('\n')
    test_type = ''
    module = ''
    functions = []
    assertions = []

    for line in content:
        assertion = {}
        function =  {}
        line = line.strip()
        if line[:2] == ';;': # ignore comments
            continue
        if line == "":       # ignore blank lines
            continue
        if test_type == A_MALFORMED:
            if line.find('(module quote') >= 0:
                module_start = line.find('"') + 1
                module_end = line[module_start + 1:].find('"') + module_start + 1
                module = line[module_start:module_end]
                #print('MODULE: ', module)
        if line.find('(assert_malformed') >= 0:
            #print('...assert_maldofmed')
            test_type = A_MALFORMED
            
        if line.find(F_EXPORT) >= 0:
            function["name"] = get_function_name(line)
            function["content"] = get_function_content(line)
            function["result"] = get_function_result(line)
            functions.append(function)
            #print('Functions: ' + str(functions))

        if line.find(A_RETURN) >= 0:
            assertion['kind'] = A_RETURN
            assertion['left'] = get_assertion_left(line)
            assertion['right'] = get_assertion_right(line)
            assertions.append(assertion)
            #print(line)
            #print(assertion)
            #input()

        if line.find(A_TRAP) >= 0:
            assertion['kind'] = A_TRAP
            assertion['left'] = get_assertion_left(line)
            assertion['exception'] = get_assertion_exception(line)
            assertions.append(assertion)
        #print(line)

    result = {}
    result['functions'] = functions
    result['assertions'] = assertions
    return result

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

def get_function_type(func, functions):
    for f in functions:
        if f['name'] == func:
            return f['result']
    return 'i64' # TODO: Fix

def add8(module):
    lines = module.split('\n')
    eight = ' ' * 8
    module = ""
    for line in lines:
        module += eight + line + '\n'
    return module
def build_module(main_data):
    functions = main_data['functions']
    assertions = main_data['assertions']
    module_header = "(module\n  "
    memory = "(memory 1)"
    data = ""
    imports = '(import "ethereum" "storageStore" (func $storageStore (param i32 i32)))\n  '
    exports = '(export "memory" (memory 0))\n  (export "main" (func $main))\n    '
    module = ""
    close_module = '\n))'
    calls = ""
    function_defs = ""
    expectation = ""

    main_function = "\n    ;;=========== MAIN FUNCTION===================\n    (func $main\n      "

    function_defs = "\n    ;;;;;; Function definitions ;;;;;;\n    "
    for function in functions:
        # generate function definitions
        fdef = "(func $" + function['name'] + "\n      " + function['content'] + ')\n    '
        #print(fdef)
        function_defs += fdef
        
    index = 0
    for assertion in assertions:
        # generate storage keys
        key = generate_storage_key(index)
        data += '(data (i32.const ' + str(index * 32) + ') "' + key + '")\n  '

        # generate calls
        if assertion['kind'] == A_RETURN:
            #print(assertion)
            #input()
            ftype = get_function_type(assertion['left']['func'], functions)
            calls += '(if (' + ftype + '.eq '
            calls += '(call $' + (assertion['left'])['func'] + ' '
            for param in assertion['left']['params']:
                calls += param + ' '
            calls += ') '
            calls += '(' + assertion['right']['kind'] + '.const ' + assertion['right']['value'] + ')\n        '
            calls += '(call $storageStore (i32.const %s) (i32.const 32))\n        ' % (str(index * 32))
            calls += '(call $storageStore (i32.const %s) (i32.const 64)))\n      '  % (str(index * 32))

            exp = "            %s: '0x0000000000000000000000000000000000000000000000000000000000000001',\n" % index
            expectation += exp
            #print(exp)

        index += 1
    calls = calls[:-7]
    module = module_header + imports + memory + data + exports + function_defs + main_function + calls + close_module
    expectation = expectation[:-2] # remove last comma and  \n
    module = add8(module)
    return module, expectation

def generate_filler(name, module, exp):
    name = name.split('.')[0]
    filler_name = name + 'Filler.yml'
    template = read_file(TEMPLATE)
    template = template.replace('{fillerName}', name)
    template = template.replace('{module}', module)
    template = template.replace('{expect}', exp)
    write_file(EWASM_DIR + filler_name, template)
    
def convert_file(fname):
    print('>>> ', fname)
    content = read_file(TEST_DIR + fname)
    result = parse_content(content)
    module, exp = build_module(result)
    write_file('module.wast', module)
    filler = generate_filler(fname, module, exp)
    return filler

wast_files = listdir(TEST_DIR)


for wfile in wast_files:
    if wfile in avoid:
        continue
    convert_file(wfile)
    exit()
