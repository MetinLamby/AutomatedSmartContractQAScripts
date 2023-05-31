"""Detector for finding execution paths missing DeleteApplication check."""

from typing import List, TYPE_CHECKING

from tealer.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DetectorType,
)
from tealer.teal.basic_blocks import BasicBlock
from tealer.detectors.utils import (
    detect_missing_tx_field_validations,
    detector_terminal_description,
)
from tealer.utils.teal_enums import TealerTransactionType

if TYPE_CHECKING:
    from tealer.utils.output import SupportedOutput
    from tealer.teal.context.block_transaction_context import BlockTransactionContext


class DenialOfServiceDetector(AbstractDetector):  # pylint: disable=too-few-public-methods
    """Detector to find execution paths missing DeleteApplication check.

    Stateful smart contracts(application) can be deleted in algorand. If the
    application transaction of type DeleteApplication is approved by the application,
    then the application will be deleted. Contracts can check the application
    transaction type using OnCompletion field.

    This detector tries to find execution paths that approve the application
    transaction("return 1") and doesn't check the OnCompletion field against
    DeleteApplication value. Execution paths that only execute if the application
    transaction is not DeleteApplication are excluded.
    """

    NAME = "denialOfService"
    DESCRIPTION = "Applications with dos"
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "Applications with dos"
    WIKI_DESCRIPTION = (
        "Applications with dos"
    )
    WIKI_EXPLOIT_SCENARIO = "Applications with dos"

    WIKI_RECOMMENDATION = "use pull pattern, not push"

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        ###### use the print() statements if you want to output things ######

        print("############################ My output #################################")

        def identify_inner_transaction() -> List[BasicBlock]:
            bbs = tealProgram.bbs
            innerTransactionAssetTransfers = []
            for bb in bbs:
                bbInnerTransactions = []
                currentInstructions = bb.instructions
                # if there is an access control pattern and there is only one next block, the pattern is implemented with assert
                index = 0
                while index < len(currentInstructions):
                    if "itxn_begin" == str(currentInstructions[index]):
                        innerTrans = []
                        indexInnerTrans = index
                        # create an array that includes all stack operations for an inner transactions
                        while "itxn_submit" != str(currentInstructions[indexInnerTrans]):
                            innerTrans.append(currentInstructions[indexInnerTrans])
                            indexInnerTrans += 1
                        innerTrans.append(currentInstructions[indexInnerTrans])
                        bbInnerTransactions.append(innerTrans)
                    index += 1
                # bbInnerTransactions represents all inner transactions contained in basic blocks that contain an access control mechanism within the same basicblock
                for innerTrans in bbInnerTransactions: # innerTrans is an array that contains all operations for an inner transaction
                    # check if inner transaction is an asset transfer
                    innerTransactionIndex = 0
                    while innerTransactionIndex < len(innerTrans): # iterate through the instructions of the inner transaction
                        if "itxn_field TypeEnum" == str(innerTrans[innerTransactionIndex]) and "int axfer" == str(innerTrans[innerTransactionIndex - 1]):
                            #bbInnerTransactions = bbInnerTransactions - innerTrans
                            if bbInnerTransactions not in innerTransactionAssetTransfers:
                                innerTransactionAssetTransfers.append(bbInnerTransactions)
                        innerTransactionIndex += 1
            return innerTransactionAssetTransfers

        def flatten(lst:List):
            flattened_lst = []
            for item in lst:
                if isinstance(item, list):
                    flattened_lst.extend(flatten(item))
                else:
                    flattened_lst.append(item)
            return flattened_lst

        def identify_inner_transaction_receivers(innerTransactionArray:List):
            receiversAll = []
            index = 0
            while index < len(innerTransactionArray):
                if "itxn_field AssetReceiver" == str(innerTransactionArray[index]):
                    if "app_global_get" == str(innerTransactionArray[index-1]):
                        receiversAll.append(innerTransactionArray[index-2])
                    else:
                        receiversAll.append(innerTransactionArray[index-1])
                index += 1
            return receiversAll

        def unique_receivers(receivers:List):
            uniqueReceivers = []
            for r in receivers:
                if str(r) not in uniqueReceivers:
                    uniqueReceivers.append(str(r))
            return uniqueReceivers

        def find_receiver_validated(uniqueReceivers:List):
            allInstructions = tealProgram.instructions
            validatedReceivers = []
            for ur in uniqueReceivers:
                index = 0
                while index < len(allInstructions):
                    if ur == str(allInstructions[index]):
                        if "byte" in ur and "app_global_get" == str(allInstructions[index+1]) and "global CurrentApplicationID" == str(allInstructions[index+2]) and "app_opted_in" == str(allInstructions[index+3]):
                            validatedReceivers.append(ur)
                        elif "global CurrentApplicationID" == str(allInstructions[index+1]) and "app_opted_in" == str(allInstructions[index+2]):
                            validatedReceivers.append(ur)
                    index += 1
            return validatedReceivers


        innertrans = identify_inner_transaction()
        flattened_lst = flatten(innertrans)
        receivers = identify_inner_transaction_receivers(flattened_lst)

        uniqueReceivers =  unique_receivers(receivers)
        validatedReceiversForOptIn = find_receiver_validated(uniqueReceivers)

        uniqueReceivers.sort()
        validatedReceiversForOptIn.sort()

        if uniqueReceivers != validatedReceiversForOptIn:
            print(f"even though we found inner transactions of ASA to receivers {uniqueReceivers}, only the receiver in expression(s) {validatedReceiversForOptIn} is/are validated")
        else:
            print("all addresses are validated")


        # limitation: we do not check if the validation is a restrictor for the inner transaction to happen

        ###### Leave the below code for correct output ########

        print("############################ Default output ############################")

        def checks_field(block_ctx: "BlockTransactionContext") -> bool:
            # return False if Txn Type can be DeleteApplication.
            # return True if Txn Type cannot be DeleteApplication.
            return False

        paths_without_check: List[List[BasicBlock]] = detect_missing_tx_field_validations(
            self.teal.bbs[0], checks_field
        )

        description = detector_terminal_description(self)

        filename = "includes_centralization_risk"

        return self.generate_result(paths_without_check, description, filename)
