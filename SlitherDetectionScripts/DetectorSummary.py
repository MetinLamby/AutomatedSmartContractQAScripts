import sys
from BlockInformationDependency import detect_pseudoranom_number_generators_from_blockdata
from CentralizationRisk import detect_protected_balance_modifying_functions
from DenialOfService import detect_dos_conditional_call
from slither.slither import Slither


def main():
    # Init slither
    slither = Slither(sys.argv[1])

    # Get the contract
    contract = slither.contracts[0]

    all_functions = contract.functions

    # Block Information Dependency Check
    vulnerable_Functions_Block_Information = detect_pseudoranom_number_generators_from_blockdata(
        all_functions
    )
    block_Information_Vul_Exists = bool(vulnerable_Functions_Block_Information)

    # Centralization Risk Check
    vulnerable_Functions_Centralization_Risk = detect_protected_balance_modifying_functions(
        contract
    )
    centralization_Risk_Vul_Exists = bool(vulnerable_Functions_Centralization_Risk)

    # Denial of Service
    vulnerable_Functions_Denial_of_Service = detect_dos_conditional_call(all_functions)
    denial_of_Service_Vul_Exists = bool(vulnerable_Functions_Denial_of_Service)

    # generate the output table
    columns = ["Centralization Risk", "Block Information Dependency", "Denial of Service"]
    values = [
        centralization_Risk_Vul_Exists,
        block_Information_Vul_Exists,
        denial_of_Service_Vul_Exists,
    ]
    max_width = max(len(col) for col in columns) + 2
    header_row = "Vulnerability".ljust(max_width) + "".join(col.ljust(max_width) for col in columns)
    print(header_row)
    separator_row = "-" * (max_width * (len(columns) + 1))
    print(separator_row)
    for val in [True, False]:
        data_row = f"{str(val):<{max_width}}" + "".join(
            ["✓".ljust(max_width) if v == val else "✗".ljust(max_width) for v in values]
        )
        print(data_row)


if __name__ == "__main__":
    main()
