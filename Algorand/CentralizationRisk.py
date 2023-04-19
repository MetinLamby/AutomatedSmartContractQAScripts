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


class MetinTester(AbstractDetector):  # pylint: disable=too-few-public-methods
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

    NAME = "centralizationRisk"
    DESCRIPTION = "Applications with centralization risk"
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "Centralization Risk"
    WIKI_DESCRIPTION = (
        "Smart contract that includes restriucted functions that have balance modifying behaviour"
    )
    WIKI_EXPLOIT_SCENARIO = "test"

    WIKI_RECOMMENDATION = "test"

    def detect(self) -> "SupportedOutput":
        
        tealProgram = self.teal
        
        ###### use the print() statements if you want to output things ######
        
        print("############################ My output #################################")
        
        def bb_with_address_similarity_condition() -> List[BasicBlock]:
            instructions = tealProgram.instructions
            addressComparisonBlocks = []
            addressComparisonIndex = []
            """
            byte "Creator"
            app_global_get
            txn Sender
            ==
            """
            # or 
            """
            txn Sender
            byte "Creator"
            app_global_get
            ==
            """
            index = 0
            #print(instructions)
            while index < len(instructions):
                if "txn Sender" == str(instructions[index]) and "==" == str(instructions[index + 1]) and "app_global_get" == str(instructions[index - 1]) and "byte " in str(instructions[index - 2]):
                    addressComparisonBlocks.append(instructions[index].bb)
                    addressComparisonIndex.append(instructions[index + 1].line)
                elif "txn Sender" == str(instructions[index]) and "byte " in str(instructions[index + 1]) and "app_global_get" == str(instructions[index + 2]) and "==" == str(instructions[index + 3]):
                    addressComparisonBlocks.append(instructions[index].bb)
                    addressComparisonIndex.append(instructions[index + 3].line)
                index += 1
            return addressComparisonBlocks, addressComparisonIndex
        
        def bb_analysis(bbs:List[BasicBlock], accessControlLines:List):
            bbAccessControlLines = accessControlLines
            bbIndex = 0
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
                    innerTransAssetTrans = []
                    for innerTrans in bbInnerTransactions: # innerTrans is an array that contains all operations for an inner transaction
                        # check if inner transaction is an asset transfer
                        innerTransactionIndex = 0
                        while innerTransactionIndex < len(innerTrans): # iterate through the instructions of the inner transaction
                            if "itxn_field TypeEnum" == str(innerTrans[innerTransactionIndex]) and "int axfer" == str(innerTrans[innerTransactionIndex - 1]):
                                innerTransAssetTrans.append(innerTrans[0].line)
                            innerTransactionIndex += 1
                    # make sure that access control pattern is in front of asset tranfer functions
                    controledAssetTranfers = []
                    for at in innerTransAssetTrans:
                        if bbAccessControlLines[bbIndex] < at:
                            controledAssetTranfers.append(at)
                    # print centralization risks in blocks that do not branch
                    print("Block: " + str(bb.idx) + " has a centralization risk because we found an access control pattern on line " + str(bbAccessControlLines[bbIndex]) + " which restricts access to asset trasfer functions on lines " + str(controledAssetTranfers))
                    
                    
                    
                    
                    
                    
                    
                    
                    
                    
                elif len(bb.next) == 2:
                    # bnz -> branch to TARGET if value A is not zero
                    # bz -> branch to TARGET if value A is zero
                    if "bz " in str(bb.exit_instr):
                        for bbn in bb.next:
                            if str(bbn.entry_instr)[-1] != ":":
                                # look for innertansaction with TypeEnum == axfer in bbn.instructions
                                currentInstructions = bbn.instructions
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
                                innerTransAssetTrans = []
                                for innerTrans in bbInnerTransactions: # innerTrans is an array that contains all operations for an inner transaction
                                    # check if inner transaction is an asset transfer
                                    innerTransactionIndex = 0
                                    while innerTransactionIndex < len(innerTrans): # iterate through the instructions of the inner transaction
                                        if "itxn_field TypeEnum" == str(innerTrans[innerTransactionIndex]) and "int axfer" == str(innerTrans[innerTransactionIndex - 1]):
                                            innerTransAssetTrans.append(innerTrans[0].line)
                                        innerTransactionIndex += 1
                                # in a branching pattern we do not need to check for order of patterns because branch is always later
                                if innerTransAssetTrans:
                                    # print centralization risks in blocks that do not branch
                                    print("Blocks " + str(bb.idx) + " and " + str(bbn.idx) + " have a centralization risk because we found an access control pattern on line " + str(bbAccessControlLines[bbIndex]) + " which restricts access to asset trasfer functions on lines " + str(innerTransAssetTrans))      
                    elif "bnz " in str(bb.exit_instr):
                        for bbn in bb.next:
                            if str(bbn.entry_instr)[-1] == ":":
                                # look for innertansaction with TypeEnum == axfer in bbn.instructions
                                currentInstructions = bbn.instructions
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
                                innerTransAssetTrans = []
                                for innerTrans in bbInnerTransactions: # innerTrans is an array that contains all operations for an inner transaction
                                    # check if inner transaction is an asset transfer
                                    innerTransactionIndex = 0
                                    while innerTransactionIndex < len(innerTrans): # iterate through the instructions of the inner transaction
                                        if "itxn_field TypeEnum" == str(innerTrans[innerTransactionIndex]) and "int axfer" == str(innerTrans[innerTransactionIndex - 1]):
                                            innerTransAssetTrans.append(innerTrans[0].line)
                                        innerTransactionIndex += 1
                                # in a branching pattern we do not need to check for order of patterns because branch is always later
                                if innerTransAssetTrans:
                                    # print centralization risks in blocks that do not branch
                                    print("Blocks " + str(bb.idx) + " and " + str(bbn.idx) + " have a centralization risk because we found an access control pattern on line " + str(bbAccessControlLines[bbIndex]) + " which restricts access to asset trasfer functions on lines " + str(innerTransAssetTrans))
                bbIndex += 1            
        bbs, indexs = bb_with_address_similarity_condition()
        bb_analysis(bbs, indexs)
        
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
