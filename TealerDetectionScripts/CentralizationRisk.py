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


class CentralizationRisk(AbstractDetector):  # pylint: disable=too-few-public-methods
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
    WIKI_EXPLOIT_SCENARIO = (
        "There is restricted access to an internal transaction that is an asset transfer"
    )

    WIKI_RECOMMENDATION = "Be aware of private key compromised because they could lead to privacy issues in smart contracts where the owners key is compromised"

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        def bb_with_address_similarity_condition():
            basicBlocks = tealProgram.bbs
            addressComparisonBlocks = []
            addressComparisonLines = []
            addressComparisonIndex = []
            currentInstrcutions = []
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
            for bb in basicBlocks:
                currentInstrcutions = bb.instructions
                index = 0
                while index < len(currentInstrcutions):
                    if (
                        "txn Sender" == str(currentInstrcutions[index])
                        and "==" == str(currentInstrcutions[index + 1])
                        and "app_global_get" == str(currentInstrcutions[index - 1])
                        and "byte " in str(currentInstrcutions[index - 2])
                    ):
                        addressComparisonBlocks.append(bb)
                        addressComparisonLines.append(currentInstrcutions[index + 1].line)
                        addressComparisonIndex.append(index + 1)
                    elif (
                        "txn Sender" == str(currentInstrcutions[index])
                        and "byte " in str(currentInstrcutions[index + 1])
                        and "app_global_get" == str(currentInstrcutions[index + 2])
                        and "==" == str(currentInstrcutions[index + 3])
                    ):
                        addressComparisonBlocks.append(bb)
                        addressComparisonLines.append(currentInstrcutions[index + 3].line)
                        addressComparisonIndex.append(index + 3)
                    index += 1
            return addressComparisonBlocks, addressComparisonLines, addressComparisonIndex

        # order of expressions
        # address comparison
        # assert or branch
        # logal storage write

        def bb_with_assert_or_branch(
            bbs: List[BasicBlock], accessControlLines: List, accessControlIndices: List
        ):
            vulnerableBB = []
            vulnerableBBLocalPutLines = []
            if len(bbs) == len(accessControlLines) == len(accessControlIndices):
                currentInstrcutions = []
                bbIndex = 0
                while bbIndex < len(bbs):
                    currentInstrcutions = bbs[bbIndex].instructions[
                        accessControlIndices[bbIndex] + 1 :
                    ]  # we analyze all instrcutions of a basic block after the final expression required for address comparison
                    currentInstrcutionIndex = 0
                    if (
                        len(bbs[bbIndex].next) == 1 or len(bbs[bbIndex].next) == 0
                    ):  # having one or zero next bbs indicates no branch
                        # if "assert" == str(currentInstrcutions[currentInstrcutionIndex]):
                        while currentInstrcutionIndex < len(currentInstrcutions):
                            if "assert" == str(currentInstrcutions[currentInstrcutionIndex]):
                                currentInstrcutions = currentInstrcutions[
                                    currentInstrcutionIndex + 1 :
                                ]
                                break
                            currentInstrcutionIndex += 1
                        for i in currentInstrcutions:
                            if "app_local_put" == str(i):
                                vulnerableBB.append(bbs[bbIndex])
                                vulnerableBBLocalPutLines.append(i.line)
                    elif len(bbs[bbIndex].next) == 2:  # having two next bbs indicates a branch
                        # bnz -> branch to TARGET if value A is not zero
                        # bz -> branch to TARGET if value A is zero
                        if "bz " in str(bbs[bbIndex].exit_instr):
                            for bbn in bbs[bbIndex].next:
                                if str(bbn.entry_instr)[-1] != ":":
                                    currentInstructions = bbn.instructions
                                    for i in currentInstructions:
                                        if "app_local_put" == str(i):
                                            vulnerableBB.append(bbn)
                                            vulnerableBBLocalPutLines.append(i.line)
                        elif "bnz " in str(bbs[bbIndex].exit_instr):
                            for bbn in bbs[bbIndex].next:
                                if str(bbn.entry_instr)[-1] == ":":
                                    currentInstructions = bbn.instructions
                                    for i in currentInstructions:
                                        if "app_local_put" == str(i):
                                            vulnerableBB.append(bbn)
                                            vulnerableBBLocalPutLines.append(i.line)
                    bbIndex += 1
            return vulnerableBB, vulnerableBBLocalPutLines

        bbs, lines, indices = bb_with_address_similarity_condition()
        vulnerableBBs, vulnerableBBLocalPutLinesList = bb_with_assert_or_branch(bbs, lines, indices)
        index = 0
        while index < len(vulnerableBBs):
            print(
                "we detected a centralization risk in basic block with id "
                + str(vulnerableBBs[index].idx)
                + " because the basic block contains an address comparison with a branch or assert opcode that restricts access to a app_local_put instrcution on line "
                + str(vulnerableBBLocalPutLinesList[index])
            )
            index += 1
