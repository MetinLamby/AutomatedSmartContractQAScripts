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


class FreezingAssets(AbstractDetector):  # pylint: disable=too-few-public-methods
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

    NAME = "freezingAssets"
    DESCRIPTION = "Applications with freezing asset vulnerability. When TEAL smart contract contains a deposit functionality but no withdraw functionality."
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "FreezingAssets"
    WIKI_DESCRIPTION = (
        "Applications with freezing asset vulnerability. When TEAL smart contract contains a deposit functionality but no withdraw functionality."
    )
    WIKI_EXPLOIT_SCENARIO = "One deposits funds and wants to withdraw those but it is not possible"

    WIKI_RECOMMENDATION = "Do not rely on withdraw functionality from external contracts"

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        ###### use the print() statements if you want to output things ######

        print("############################ My output #################################")

        def detect_txn_amount() -> List[BasicBlock]:
            bbs = tealProgram.bbs
            bbContainingDeposit = []
            for bb in bbs:
                for ins in bb.instructions:
                    if "txn Amount" == str(ins):
                        bbContainingDeposit.append(bb)
            return bbContainingDeposit

        def detect_deposit(bbs:List[BasicBlock]) -> List[BasicBlock]:
            depositBbs = []
            if bbs:
                for bb in bbs:
                    currentInstructions = bb.instructions
                    index = 0
                    while index < len(currentInstructions):
                        if "txn Amount" == str(currentInstructions[index]):
                            if "app_global_put" == str(currentInstructions[index + 1]) or "app_local_put" == str(currentInstructions[index + 1]):
                                """
                                -> direct storage
                                txn Amount
                                app_global_put
                                """
                                # print("txn amount is stored directly")
                                depositBbs.append(bb)
                            else:
                                """
                                -> arithmetic operation pre storage
                                byte "balance"
                                app_global_get
                                txn Amount
                                +
                                app_global_put
                                """
                                if detect_arithmetic_operation(currentInstructions[index + 1]) and "app_global_put" == str(currentInstructions[index + 2]) or "app_local_put" == str(currentInstructions[index + 2]):
                                    # index+1 is arithemtic operation and index+2 is storgae write if first element on stack is either constand or storage read
                                    # print("txn amount is used as a second element of an arithemtic operatioon and then stored")
                                    depositBbs.append(bb)
                                elif (detect_arithmetic_operation(currentInstructions[index + 2]) and "app_global_put" == str(currentInstructions[index + 3]) or "app_local_put" == str(currentInstructions[index + 3])) or (detect_arithmetic_operation(currentInstructions[index + 3]) and "app_global_put" == str(currentInstructions[index + 4]) or "app_local_put" == str(currentInstructions[index + 4])):
                                    # if txn is used as teh first element of an arithemic calculation and the stored
                                    # print("txn amount is used as the first element of an arithemtic operatioon and then stored")
                                    depositBbs.append(bb)
                                #else:
                                    #print("txn Amount is not stored in the storage of the smart contract")
                        index += 1
            #else:
                # There is no freezing asset vulnerability the user cannot depoit any funds to the smart contract
            return depositBbs

        def detect_arithmetic_operation(instruction) -> bool:
            if str(instruction) in ["+", "-", "/", "*", "%"]: # arithmetic operation opcodes from: https://developer.algorand.org/docs/get-details/dapps/avm/teal/opcodes/#mulw
                return True
            else:
                return False

        def detect_asset_transfer_bbs() -> List[BasicBlock]:
            bbs = tealProgram.bbs
            bbContainingWithdraw = []
            for bb in bbs:
                bbInnerTransactions = []
                if len(bb.next) == 1:
                    currentInstructions = bb.instructions
                    # if there is an access control pattern and there is only one next block, the pattern is implemented with assert
                    index = 0
                    while index < len(currentInstructions):
                        """
                        itxn_begin
                        int axfer            -> if itxn_field == axfer we have an asset tranfer function (https://developer.algorand.org/docs/get-details/dapps/avm/teal/specification/?from_query=typeenum#operations)
                        itxn_field TypeEnum
                        byte "pool_address"
                        app_global_get
                        itxn_field AssetReceiver
                        load 0
                        itxn_field AssetAmount
                        byte "stable_token"
                        app_global_get
                        itxn_field XferAsset
                        global CurrentApplicationAddress
                        itxn_field Sender
                        itxn_submit
                        """
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
                                if bb not in bbContainingWithdraw:
                                    bbContainingWithdraw.append(bb)
                            innerTransactionIndex += 1
            return bbContainingWithdraw

        def detect_freezing_asset():
            txnAmountBbs = detect_txn_amount()
            depositFunctionBBs = detect_deposit(txnAmountBbs)
            withdrawFunctions = detect_asset_transfer_bbs()
            print("depositFunctionBBs: " + str(depositFunctionBBs))
            print("withdrawFunctions: " + str(withdrawFunctions))
            if depositFunctionBBs and not withdrawFunctions:
                print("detected freezing asset vulnerability because user can deposit funds but not withdraw")
            else:
                print("no freezing asset vulnerability detected")

        detect_freezing_asset()


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
