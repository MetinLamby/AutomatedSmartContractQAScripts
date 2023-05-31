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

"""
functions_with_centralization_modifier():
Input: Slither Contract object
Output: List of functions that include modifier with require and msg.sender address comparison

We iterate over all functions that include a modifier. We check whether the dected modifiers of a functions includes
a require expression that compares two variables. One of the variables is msg.sender. The other variable must be a storage variable of type address.
The order of the varioables within the condition can be arbitrary.
"""
def functions_with_centralization_modifier(contract:Contract) -> List[Function]:
    contractFunctions = contract.functions
    functionsWithModifier = []
    for f in contractFunctions: # iterate over contract functions
        if f.modifiers:
            for m in f.modifiers: # iterate over function modifiers if available
                for n in m.nodes: # iterate over modifier nodes
                    if ("require" in str(n.expression)) and len(n.variables_read) != 0:
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
                                functionsWithModifier.append(f)
                            elif read_address_variables[1].name == "msg.sender" and read_address_variables[0] in n.state_variables_read:
                                functionsWithModifier.append(f)
    return functionsWithModifier

"""
functions_with_centralization_require():
Input: Slither Contract object
Output: List of functions that include require expression and msg.sender address comparison

We iterate over all functions that include a require expression that compares two variables.
One of the variables is msg.sender. The other variable must be a storage variable of type address.
The order of the varioables within the condition can be arbitrary.
"""
def functions_with_centralization_require(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    protected_functions = []
    for f in all_functions:
        for n in f.nodes:
            if "require" in str(n.expression) and len(n.variables_read) != 0:
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

"""
functions_with_centralization_if():
Input: Slither Contract object
Output: List of functions that include if expression and msg.sender address comparison condition

We iterate over all functions that include an if condition that compares two variables.
One of the variables is msg.sender. The other variable must be a storage variable of type address.
The order of the varioables within the condition can be arbitrary.
"""
def functions_with_centralization_if(contract:Contract) -> List[Function]:
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

"""
get_protected_functions():
Input: Slither Contract object
Output: List of functions that include all access control patterns included in litertaure review

Join all functions that include at least one pattern
"""
def get_protected_functions(contract:Contract) -> List[Function]:
    centralizedModifierFunctions = functions_with_centralization_modifier(contract)
    centralizedRequireFunctions = functions_with_centralization_require(contract)
    centralizedIfFunctions = functions_with_centralization_if(contract)

    protectedFunctions = centralizedModifierFunctions + centralizedRequireFunctions + centralizedIfFunctions
    return protectedFunctions

"""
functions_modifying_balance():
Input: Slither Contract object
Output: List of functions that include logioc that modifies the balance. Either using Safemath library functions or normal arithmetic operations
"""
def functions_modifying_balance(contract:Contract) -> List[Function]:
    all_functions = contract.functions
    balance_writing_functions = []
    for f in all_functions:
        for n in f.nodes:
            for v in n.state_variables_written:
                if "mapping(address => uint256)" == str(v.type) and (str(n.expression) in ["=", "+", "-", "/", "*", "%", "+=", "-=", ".add(", ".sub(", ".mul(", ".div(", ".mod("]) and f not in balance_writing_functions:
                    balance_writing_functions.append(f)
    return balance_writing_functions

protectedFunctions = get_protected_functions(contract)
balanceModifyingFunctions = functions_modifying_balance(contract)
protectedBalanceModifyingFunctions = set(protectedFunctions).intersection(balanceModifyingFunctions)
for f in protectedBalanceModifyingFunctions:
    print(f.name)
