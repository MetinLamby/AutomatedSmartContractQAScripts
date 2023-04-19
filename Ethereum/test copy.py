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

all_functions = contract.functions

def payable_functions(contract: Contract) -> List[Function]:
    all_functions = contract.functions
    payableFunctions = []
    for f in all_functions:
        if f.payable:
            payableFunctions.append(f)
    return payableFunctions

def functions_modifying_balance(contract: Contract) -> List[Function]:
    all_functions = contract.functions
    balance_writing_functions = []
    for f in all_functions:
        for n in f.nodes:
            for v in n.state_variables_written:
                if "mapping(address => uint256)" == str(v.type) and ("=" in str(n.expression) or "+=" in str(n.expression)) and f not in balance_writing_functions:
                    balance_writing_functions.append(f)
    return balance_writing_functions

def includes_deposit_functions(contract: Contract) -> bool:
    payableFunctions = payable_functions(contract)
    balanceIncreaseFunctions = functions_modifying_balance(contract)
    deposit_functions = set(payableFunctions).intersection(balanceIncreaseFunctions)
    if deposit_functions:
        return True
    else:
        return False 
    
def includes_withdraw_functions(contract: Contract) -> bool:
    all_functions = contract.functions
    withdraw_functions = []
    for f in all_functions:
        for n in f.nodes:
            # transfer() and send() functions are only available to payable addresses. 
            # I do not need to check whether the receiver of the send/receive function is a payable
            # because if they are not payable, there is a compilation error
            if ".transfer(" in str(n.expression) or ".send(" in str(n.expression):
                withdraw_functions.append(f)
    if withdraw_functions:
        return True
    else:
        return False 
    
def includes_freezing_asset_vulnerability(contract: Contract) -> bool:
    if includes_deposit_functions(contract) and not includes_withdraw_functions(contract):
        return True
    else: 
        return False
    
print(includes_freezing_asset_vulnerability(contract))