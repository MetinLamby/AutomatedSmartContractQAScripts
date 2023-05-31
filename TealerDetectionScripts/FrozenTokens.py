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


class FreezingAssetsUpdated(AbstractDetector):  # pylint: disable=too-few-public-methods
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

    NAME = "freezingAssetsUpdated"
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

        # there should be a validation for transaction revceiver, sender, type and amount
        def detect_bbs_with_transaction_evaluation(bbs:List[BasicBlock]):
            transactionEvaluatingBbs = []
            for bb in bbs:
                currentInstructions = bb.instructions
                index = 0
                while index < len(currentInstructions):
                    if "gtxn" in str(currentInstructions[index]) and currentInstructions[index].bb not in transactionEvaluatingBbs:
                        transactionEvaluatingBbs.append(currentInstructions[index].bb)
                    index += 1
            return transactionEvaluatingBbs

        def detect_validation_attributes_per_bb(bbs:List[BasicBlock]):
            bbTransactions = []
            for bb in bbs:
                transactionAttributes = []
                currentInstructions = bb.instructions
                index = 0
                while index < len(currentInstructions):
                    if "==" == str(currentInstructions[index]):
                        if "gtxn" in str(currentInstructions[index - 2]):
                            transactionAttributeExpression = currentInstructions[index - 2]
                            transactionAttributes.append(str(transactionAttributeExpression).split()[2])
                        elif "gtxn" in str(currentInstructions[index - 1]):
                            transactionAttributeExpression = currentInstructions[index - 1]
                            transactionAttributes.append(str(transactionAttributeExpression).split()[2])
                    index += 1
                bbTransactions.append(transactionAttributes)
            return bbTransactions

        bbs = detect_bbs_with_transaction_evaluation(tealProgram.bbs)
        transactionChecks = detect_validation_attributes_per_bb(bbs)
        index = 0
        while index < len(transactionChecks):
            transactionChecks[index].sort()
            if ['Amount', 'Receiver', 'Sender', 'TypeEnum'] == transactionChecks[index]:
                print("Basic block with id " + str(bbs[index].idx) + " evaluates a transaction based on Amount, Receiver, Sender and Type attributes")
            else:
                print("Basic block with id " + str(bbs[index].idx) + " evaluates a transaction but the validity is not assured")
            index += 1



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
