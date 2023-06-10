# Automated Quality Assurance using Static Analysis For Ethereum and Algorand Smart Contracts

This project describes the automatic detection of Ethereum and Algorand smart contract vulnerabilities using static analysis. We limit the vulnerability scope by focusing on those issues that occur in both Transaction Execution Approval Language (TEAL) and Solidity applications. The static analysis frameworks Tealer and Slither are extended to identify the existence of frozen tokens, generating randomness, denial of service, and centralization risk vulnerabilities.

This project is part of a Bachelor’s Thesis in Information Systems for the School of Computation, Information and Technology — Informatics at the Technische Universität München (TUM)
## Setup and Execution

Setup the folder structure
```bash
mkdir SmartContractQACode
cd SmartContractQACode
mkdir TealerDir SlitherDir SmartContractQAThesisFiles
```

Clone the detection scripts and the test smart contracts
```bash
cd SmartContractQAThesisFiles
git clone git@github.com:MetinLamby/AutomatedSmartContractQAScripts.git
cd ..
```

### Ethereum Smart Contract QA
Clone the Slither framework
```bash
cd SlitherDir
virtualenv --python=/usr/bin/python3 venv # create a virtual environment
git clone git@github.com:crytic/slither.git
source venv/bin/activate # activate a virtual environment
cd slither
python3 setup.py install
pip3 install solc-select cbor2 wcwidth
solc-select install 0.8.20
solc-select use 0.8.20
deactivate # deactivate a virtual environment
```

Move the Slither detection scripts into the framework
```bash
cd ../..  
mv SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/SlitherDetectionScripts/ SlitherDir/slither/examples/scripts/
cd SlitherDir
source venv/bin/activate # activate a virtual environment
cd slither
```

Execute the available detectors by exchanging ```<DETECTOR>``` with one of the below detection scripts:
- CentralizationRisk.py
- BlockInformationDependency.py
- DenialOfService.py
- DetectorSummary.py
```bash
python examples/scripts/SlitherDetectionScripts/<DETECTOR> ../../SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TestSmartContracts/Solidity/experimentContract.sol
deactivate # deactivate a virtual environment
cd ../../
```

### Algorand Smart Contract QA
Clone the Tealer framework
```bash
cd TealerDir
git clone git@github.com:crytic/tealer.git
cd tealer
pip install -e ".[dev]"
cd ../..
```

Move the Tealer detection scripts into the framework
```bash
mv SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TealerDetectionScripts TealerDir/tealer/tealer/detectors/
cd TealerDir/tealer 
# register detectors in all_detectors.py file
echo "from tealer.detectors.TealerDetectionScripts.CentralizationRisk import CentralizationRisk
from tealer.detectors.TealerDetectionScripts.BlockInformationDependency import BlockInformationDependency
from tealer.detectors.TealerDetectionScripts.DenialOfService import DenialOfService
from tealer.detectors.TealerDetectionScripts.FrozenTokens import FrozenAssets" >> tealer/detectors/all_detectors.py
```

❗ comment out line number 555 ```handle_output(args, results_detectors, _results_printers, error)``` in file ```tealer/tealer/__main__.py```

Execute the available detectors by exchanging ```<DETECTOR>``` with one of the below detectors:
- frozenAssets
- denialOfService
- centralizationRisk
- blockInformationDependency
```bash
tealer ../../SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TestSmartContracts/TEAL/experimentContract.teal --detect <DETECTOR>
```

## Demo
- [TEAL Smart Contract Static Analysis Demo](https://youtu.be/NnaqdfUmyDA)
- [Solidity Smart Contract Static Analysis Demo](https://youtu.be/HJvL00_5r3s)

## Related

The related static analysis frameworks are
[Tealer](https://github.com/crytic/tealer) and 
[Slither](https://github.com/crytic/slither)

