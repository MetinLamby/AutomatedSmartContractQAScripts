import sys
from slither.slither import Slither
from typing import List
from slither.core.declarations import Function, Contract, FunctionContract
from slither.core.expressions import BinaryOperationType
from slither.core.variables.state_variable import StateVariable

if len(sys.argv) != 2:
    print("python variable_in_condition.py variable_in_condition.sol")
    sys.exit(-1)
    
# Init slither
slither = Slither(sys.argv[1])

# Get the contract
contract = slither.contracts[0]

# 1) get all functions that are protected 

# functions can be protected by onlyOwner() modifiers
def get_onlyOwner_protected_functions(contract: Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        if len(f.nodes) != 0:
            for n in f.nodes:
                if str(n.expression) == "onlyOwner()":
                    protected_functions.append(f)
    return protected_functions

# functions can be protected by require statement that directly compares two state variables that are both addresses
def get_directRequire_protected_functions(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        for n in f.nodes:
            if (("require" in str(n.expression)) or ("assert" in str(n.expression))) and len(n.variables_read) != 0:
                read_address_variables = []
                for v in n.variables_read:
                    # check if variables read in require/assert are Ethereum addresses
                    if str(v.type) == "address":
                        read_address_variables.append(v)
                # checking that len(read_address_variables) == 2 eliminates similarity checks to address(0) 
                if len(read_address_variables) == len(n.variables_read) and len(read_address_variables) == 2:
                    # one variable must be in n.state_variables_read
                    # the other variable must be v.name == msg.sender
                    if read_address_variables[0].name == "msg.sender" and read_address_variables[1] in n.state_variables_read:
                        protected_functions.append(f)
                    elif read_address_variables[1].name == "msg.sender" and read_address_variables[0] in n.state_variables_read:
                        protected_functions.append(f)
                # MISSING check if address variables in require/assert are compared for similarity
    return protected_functions

# functions can be protected by require statement that indirectly (via function calls) compares one state variables and the msg.sender var that are both addresses
def get_indirectRequire_protected_functions(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        variablesCalled = []
        for n in f.nodes:
            if "require" in str(n.expression) or "assert" in str(n.expression):
                # we access indeirect variable calls with _internal_calls of a node
                for ic in n._internal_calls:
                    if isinstance(ic, FunctionContract):
                        for v in ic._vars_read:
                            variablesCalled.append(v)
                # checking that len(variablesCalled) == 2 eliminates similarity checks to address(0) 
                # this is limilited to the case where both binary expression elements are functions -> open TODO
                if len(variablesCalled) == 2:
                    # one variable must be in n.state_variables_read
                    # the other variable must be v.name == msg.sender
                    if variablesCalled[0].name == "msg.sender" and isinstance(variablesCalled[1], StateVariable):
                        protected_functions.append(f)
                    elif variablesCalled[1].name == "msg.sender" and isinstance(variablesCalled[0], StateVariable):
                        protected_functions.append(f)
    return protected_functions
                    
# functions can be protected by if statement that directly compares two state variables that are both addresses
def get_directIf_protected_functions(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        for n in f.nodes:
            if str(n.type) == "IF" and "==" in str(n.expression):
                read_address_variables = []
                for v in n.variables_read:
                    # check if variables read in if statement are Ethereum addresses
                    if str(v.type) == "address":
                        read_address_variables.append(v)
                if len(read_address_variables) == len(n.variables_read) and len(read_address_variables) == 2:
                    # one variable must be in n.state_variables_read
                    # the other variable must be v.name == msg.sender
                    if read_address_variables[0].name == "msg.sender" and read_address_variables[1] in n.state_variables_read:
                        protected_functions.append(f)
                    elif read_address_variables[1].name == "msg.sender" and read_address_variables[0] in n.state_variables_read:
                        protected_functions.append(f)
    return protected_functions

# functions can be protected by if statement that indirectly (via function calls) compares one state variables and the msg.sender var that are both addresses
def get_indirectIf_protected_functions(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        variablesCalled = []
        for n in f.nodes:
            if str(n.type) == "IF" and "==" in str(n.expression):
                # we access indeirect variable calls with _internal_calls of a node
                for ic in n._internal_calls:
                    if isinstance(ic, FunctionContract):
                        for v in ic._vars_read:
                            variablesCalled.append(v)
                # checking that len(variablesCalled) == 2 eliminates similarity checks to address(0) 
                # this is limilited to the case where both binary expression elements are functions -> open TODO
                if len(variablesCalled) == 2:
                    # one variable must be in n.state_variables_read
                    # the other variable must be v.name == msg.sender
                    if variablesCalled[0].name == "msg.sender" and isinstance(variablesCalled[1], StateVariable):
                        protected_functions.append(f)
                    elif variablesCalled[1].name == "msg.sender" and isinstance(variablesCalled[0], StateVariable):
                        protected_functions.append(f)
    return protected_functions

def get_protected_functions_with_role_based(contract:Contract) -> List[Function] :
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions: 
        for n in f.nodes:
            requireHasRole = False
            stateVar = False
            msgSender = False
            if "require" in str(n.expression) or "assert" in str(n.expression):
                if len(n._internal_calls) == 2:
                    if n._internal_calls[0].name == "hasRole" and "require" in n._internal_calls[1].name:
                        requireHasRole = True 
                    elif n._internal_calls[1].name == "hasRole" and "require" in n._internal_calls[0].name:
                        requireHasRole = True 
                if len(n.variables_read) == 2:
                    if n.variables_read[0].name == "msg.sender" and n.variables_read[1] in n.state_variables_read:
                        stateVar = True 
                        msgSender = True
                    elif n.variables_read[1].name == "msg.sender" and n.variables_read[0] in n.state_variables_read:
                        stateVar = True 
                        msgSender = True
            if requireHasRole and stateVar and msgSender:
                protected_functions.append(f)
    return protected_functions

def get_protected_functions(contract:Contract) -> List[Function]:
    onlyOwnerFunctions = get_onlyOwner_protected_functions(contract)
    directRequireFunctions = get_directRequire_protected_functions(contract)
    directIfFunctions = get_directIf_protected_functions(contract)
    indirectRequireFunctions = get_indirectRequire_protected_functions(contract)
    indirectIfFunctions = get_indirectIf_protected_functions(contract)

    protectedFunctions = onlyOwnerFunctions + directRequireFunctions + directIfFunctions + indirectRequireFunctions + indirectIfFunctions
    return protectedFunctions

def functions_modifying_balance(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    balance_writing_functions = []
    for f in all_functions:
        for n in f.nodes:
            for v in n.state_variables_written:
                if "mapping(address => uint256)" == str(v.type) and ("=" in str(n.expression) or "+=" in str(n.expression) or "-=" in str(n.expression)) and f not in balance_writing_functions:
                    balance_writing_functions.append(f)
    return balance_writing_functions
                     
##### if we analyze the onlyOwner.sol contract
# onlyOwner: transferOwnership, transferOwnershipTwo, testFunctionWithModifier
# directRequire: testFunctionWithRequireDirect
# directIfFunctions: testFunctionWithIfDirect
# indirectRequire: _checkOwner, testFunctionIndirectRequire
        
   
#test_protected_functions(contract) 

protectedFunctions = get_protected_functions(contract)
balanceModifyingFunctions = functions_modifying_balance(contract)
protectedBalanceModifyingFunctions = set(protectedFunctions).intersection(balanceModifyingFunctions)
for f in protectedBalanceModifyingFunctions:
    print(f.name)


# TODOs
# 1) role based access control patterns identififaction
# 2) what about if/require statements that use one function call and one direct variable (mix between indirect and direct) -> we don't catch this edge case
# 3) cleanup code

# limitation: we are working with best practices
# we can only detect access control modifiers that use the open zeppelin convention
# eg. we are checking for the owner role using the onlyOwner() modifier and we are seaching for that string
# eg. we are checking for role based access control using hasRole() function and we are seaching for that string