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


class GeneratingRandomness(AbstractDetector):  # pylint: disable=too-few-public-methods
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

    NAME = "generatingRandomness"
    DESCRIPTION = "Applications that use block seed."
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "GeneratingRandomness"
    WIKI_DESCRIPTION = (
        "Applications that use block seed."
    )
    WIKI_EXPLOIT_SCENARIO = "do not use block seed"

    WIKI_RECOMMENDATION = "Do not generate randomness with block seed."

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        ###### use the print() statements if you want to output things ######

        print("############################ My output #################################")

        def detect_source_code_lines_with_blockSeed() -> List:
            bbs = tealProgram.bbs
            instructionsContainingBlockSeed = []
            for bb in bbs:
                for ins in bb.instructions:
                    if "block BlkSeed" == str(ins):
                        instructionsContainingBlockSeed.append(ins)
            return instructionsContainingBlockSeed


        vulnerableInstrcutions = detect_source_code_lines_with_blockSeed()
        print("We detected the ``Generating Randomness'' vulnerability in the submitted TEAL contract.")
        print("The vulnerable instructions are: ")
        for vins in vulnerableInstrcutions:
            print(str(vins) + " on line " + str(vins._line_num) + " of the provided program")


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
