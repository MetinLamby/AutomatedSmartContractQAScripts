import sys
from typing import List
from slither.slither import Slither
from slither.core.declarations import Function
from slither.slithir.operations.condition import Condition


if len(sys.argv) != 2:
    print("python variable_in_condition.py variable_in_condition.sol")
    sys.exit(-1)

"""
Vulnerability name: Denial of service

Vulnerability description: contracts that contain functions with conditionals that include an external call
"""


def detect_dos_conditional_call(allFunctions: List[Function]) -> List[Function]:
    vulnerableFunctions = []
    for f in allFunctions:
        for so in f.slithir_operations:
            if isinstance(
                so, Condition
            ):  # leverage SLithIR represenatation to check if expression is a conditional
                # get the building blocks of the operation and check if a call function is included
                if so.node.external_calls_as_expressions:
                    if f not in vulnerableFunctions:
                        vulnerableFunctions.append(f)
                        vulnerableLines = []
                    for (
                        call
                    ) in (
                        so.node.external_calls_as_expressions
                    ):  # a function cn include multiple condistionals with external calls
                        vulnerableLines.append(
                            # str(call.source_mapping).split("#")[-1]
                            str(call.source_mapping).rsplit("#", maxsplit=1)[-1]
                        )  # add the line numbr of the source code to a list

    return vulnerableFunctions


def main():
    # Init slither
    slither = Slither(sys.argv[1])

    # Get the contract
    contract = slither.contracts[0]

    all_functions = contract.functions

    vulnerableFunctions = detect_dos_conditional_call(all_functions)
    if vulnerableFunctions:
        print(
            "We detected the ``Denial of Service (DoS)'' vulnerability in the "
            + contract.name
            + " contract."
        )
        print("The vulnerable functions are: ")
        for vf in vulnerableFunctions:
            print("- " + vf.name)
    else:
        print("There is no function that has a conditional that includes an external call")


if __name__ == "__main__":
    main()
