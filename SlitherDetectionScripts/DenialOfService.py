import sys
from slither.slither import Slither
from typing import List
from slither.core.declarations import Function, Contract, FunctionContract
from slither.core.expressions import BinaryOperationType
from slither.core.variables.state_variable import StateVariable
from slither.core.expressions.conditional_expression import ConditionalExpression
from slither.slithir.operations.condition import Condition


if len(sys.argv) != 2:
    print("python variable_in_condition.py variable_in_condition.sol")
    sys.exit(-1)

# Init slither
slither = Slither(sys.argv[1])

# Get the contract
contract = slither.contracts[0]

all_functions = contract.functions

"""
Vulnerability name: Denial of service

Vulnerability description: contracts that contain functions with conditionals that include an external call
"""

def detect_dos_conditional_call(allFunctions: List[Function]) -> List[Function]:
    vulnerableFunctions = []
    vulnerableLinesInFunction = []
    for f in allFunctions:
        for so in f.slithir_operations:
            if isinstance(so, Condition): # leverage SLithIR represenatation to check if expression is a conditional
                # get the building blocks of the operation and check if a call function is included
                if so._node._external_calls_as_expressions:
                    if f not in vulnerableFunctions:
                        vulnerableFunctions.append(f)
                        newFunction = True
                        vulnerableLines = []
                    else:
                        newFunction = False
                    for call in so._node._external_calls_as_expressions: # a function cn include multiple condistionals with external calls
                        vulnerableLines.append(str(call.source_mapping).split('#')[-1]) # add the line number of the source code to a list
                        if newFunction:
                            vulnerableLinesInFunction.append(vulnerableLines)

    return vulnerableFunctions, vulnerableLinesInFunction

vulnerableFunctions, vulnerableLinesInFunction = detect_dos_conditional_call(all_functions)
if vulnerableFunctions:
    print("We detected the ``Denial of Service (DoS)'' vulnerability in the " + contract.name + " contract.")
    print("The vulnerable functions are: ")
    for vf in vulnerableFunctions:
        print("- " + vf.name)
else:
    print("There is no function that has a conditional that includes an external call")