import sys
from slither.slither import Slither
from typing import List
from slither.core.declarations import Function, Contract, FunctionContract
from slither.core.expressions import BinaryOperationType
from slither.core.variables.state_variable import StateVariable
from slither.core.expressions.expression import Expression

if len(sys.argv) != 2:
    print("python variable_in_condition.py variable_in_condition.sol")
    sys.exit(-1)

# Init slither
slither = Slither(sys.argv[1])

# Get the contract
contract = slither.contracts[0]

"""
Vulnerability name: Generating Randomness

Vulnerability description: smart contracts using pseudorandom number generated from block data

Vulnerabile patterns:

1) blockhash()
2) block.number
3) block.timestamp
4) block.coinbase
5) block.difficulty

Slither detection script pseudocode:
"""

def detect_pseudoranom_number_generators_from_blockdata(all_functions:List[Function]) -> List[Function]:
    vulnerablePatterns = ["blockhash(", "block.number", "block.timestamp", "block.coinbase", "block.difficulty"]
    vulnerableFunctions = []
    vulnerableNodes = []
    for f in all_functions:
        for n in f.nodes:
            if isinstance(n.expression, Expression):
                for p in vulnerablePatterns:
                    if p in str(n.expression) and f not in vulnerableFunctions and f.can_send_eth():
                        vulnerableFunctions.append(f)
                        vulnerableNodes.append(n)
    return vulnerableFunctions, vulnerableNodes


all_functions = contract.functions
vulnerable_Functions, vulnerable_Nodes = detect_pseudoranom_number_generators_from_blockdata(all_functions)
if vulnerable_Functions:
    print("We detected the ``Block information dependency'' vulnerability in " + contract.name + " contract.")
    print("The vulnerable functions are: ")
    for vf in vulnerable_Functions:
        print(vf.name)
else:
    print("There is no function that can send eth that includes block data")

