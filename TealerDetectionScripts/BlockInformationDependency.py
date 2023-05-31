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


class BlockInformationDepenecy(AbstractDetector):  # pylint: disable=too-few-public-methods
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

    NAME = "blockInformationDependency"
    DESCRIPTION = "Applications that use block seed in the same execution path as balance modification"
    TYPE = DetectorType.STATEFULL

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI_URL = "https://github.com/crytic/tealer/wiki/Detector-Documentation#deletable-application"
    WIKI_TITLE = "blockInformationDependency"
    WIKI_DESCRIPTION = (
        "Applications that use block seed."
    )
    WIKI_EXPLOIT_SCENARIO = "do not use block seed"

    WIKI_RECOMMENDATION = "do not use block seed"

    def detect(self) -> "SupportedOutput":

        tealProgram = self.teal

        ###### use the print() statements if you want to output things ######

        print("############################ My output #################################")

        def detect_bbs_with_blockSeed() -> List:
            bbs = tealProgram.bbs
            bbsContainingBlockSeed = []
            for bb in bbs:
                for ins in bb.instructions:
                    if "block BlkSeed" == str(ins) and bb not in bbsContainingBlockSeed:
                        bbsContainingBlockSeed.append(ins.bb)
            return bbsContainingBlockSeed

        def detect_bbs_with_local_put_ins() -> List:
            bbs = tealProgram.bbs
            bbsLocalPut = []
            for bb in bbs:
                for ins in bb.instructions:
                    if "app_local_put" == str(ins) and bb not in bbsLocalPut:
                        bbsLocalPut.append(ins.bb)
            return bbsLocalPut


        # https://favtutor.com/blogs/breadth-first-search-python
        def find_execution_path(start_BB, end_BB):
            found_paths = []
            visited = set()
            queue = [(start_BB, [])] # bbs that still need to be explored. The queue is initialized with the starting node and an empty path
            while queue: # continues as long as there are nodes in the queue to be explored
                node, path = queue.pop(0) # removes the first node from the queue using the pop(0) method and assigns it to the variables node and path
                if node in end_BB:
                    #return path + [node] # returns the current path plus the current node
                    found_paths.append(path + [node])
                visited.add(node)
                for child in node.next:
                    if child not in visited:
                        queue.append((child, path + [node])) # adds the child node to the queue with a path that includes the current path plus the current node
            return found_paths

        bbsWithBlockData = detect_bbs_with_blockSeed()
        bbsWithLocalStorage = detect_bbs_with_local_put_ins()

        # illustrate code with CFG example of injectedRandomness.teal contract
        if bbsWithBlockData and bbsWithLocalStorage:
            for start_BB in bbsWithBlockData:
                paths = find_execution_path(start_BB, bbsWithLocalStorage)
                if paths:
                    for path in paths:
                        print(f"Basic block {start_BB.idx} includes block data usage while basic block {path[-1].idx} includes a local write. Both nodes lie in the same execution path therefore include a block information dependency")
                        print(path)
        elif bbsWithBlockData and not bbsWithLocalStorage:
            print("The contract uses block data but does not have a local write. Therefore, there is no block information dependency vulnerability identified")
        elif bbsWithLocalStorage and not bbsWithBlockData:
            print("The contract has a local write but does not use block data. Therefore, there is no block information dependency vulnerability identified")
        else:
            print("The contract has no local write and does not use block data. Therefore, there is no block information dependency vulnerability identified")


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
