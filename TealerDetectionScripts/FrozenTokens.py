"""Detector for finding execution paths missing DeleteApplication check."""

from typing import List, TYPE_CHECKING

from tealer.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DetectorType,
)
from tealer.teal.basic_blocks import BasicBlock

if TYPE_CHECKING:
    from tealer.utils.output import SupportedOutput
    from tealer.teal.context.block_transaction_context import BlockTransactionContext


class FrozenAssets(AbstractDetector):  # pylint: disable=too-few-public-methods
    NAME = "frozenAssets"
    DESCRIPTION = "Applications with freezing asset vulnerability. When TEAL smart contract contains a deposit functionality but no withdraw functionality."
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "FreezingAssets"
    WIKI_DESCRIPTION = (
        "Applications with freezing asset vulnerability. When TEAL transactions are not validated"
    )
    WIKI_EXPLOIT_SCENARIO = "When TEAL transactions are not validated"

    WIKI_RECOMMENDATION = "When TEAL transactions are not validated"

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        # there should be a validation for transaction revceiver, sender, type and amount
        def detect_bbs_with_transaction_evaluation(bbs: List[BasicBlock]):
            transactionEvaluatingBbs = []
            for bb in bbs:
                currentInstructions = bb.instructions
                index = 0
                while index < len(currentInstructions):
                    if (
                        "gtxn" in str(currentInstructions[index])
                        and currentInstructions[index].bb not in transactionEvaluatingBbs
                    ):
                        transactionEvaluatingBbs.append(currentInstructions[index].bb)
                    index += 1
            return transactionEvaluatingBbs

        def detect_validation_attributes_per_bb(bbs: List[BasicBlock]):
            bbTransactions = []
            for bb in bbs:
                transactionAttributes = []
                currentInstructions = bb.instructions
                index = 0
                while index < len(currentInstructions):
                    if "==" == str(currentInstructions[index]):
                        if "gtxn" in str(currentInstructions[index - 2]):
                            transactionAttributeExpression = currentInstructions[index - 2]
                            transactionAttributes.append(
                                str(transactionAttributeExpression).split()[2]
                            )
                        elif "gtxn" in str(currentInstructions[index - 1]):
                            transactionAttributeExpression = currentInstructions[index - 1]
                            transactionAttributes.append(
                                str(transactionAttributeExpression).split()[2]
                            )
                    index += 1
                bbTransactions.append(transactionAttributes)
            return bbTransactions

        bbs = detect_bbs_with_transaction_evaluation(tealProgram.bbs)
        transactionChecks = detect_validation_attributes_per_bb(bbs)
        index = 0
        while index < len(transactionChecks):
            transactionChecks[index].sort()
            if ["Amount", "Receiver", "Sender", "TypeEnum"] == transactionChecks[index]:
                print(
                    "Basic block with id "
                    + str(bbs[index].idx)
                    + " evaluates a transaction based on Amount, Receiver, Sender and Type attributes"
                )
            else:
                print(
                    "Basic block with id "
                    + str(bbs[index].idx)
                    + " evaluates a transaction but the validity is not assured"
                )
            index += 1
