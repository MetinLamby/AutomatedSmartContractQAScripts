# Quality Assurance using Static Analysis For Ethereum and Algorand Smart Contracts

This project describes the automatic detection of Ethereum and Algorand smart contract vulnerabilities using static analysis. We limit the vulnerability scope by focusing on those issues that occur in both Transaction Execution Approval Language (TEAL) and Solidity applications. The static analysis frameworks Tealer and Slither are extended to identify the existence of frozen tokens, generating randomness, denial of service, and centralization-related risks vulnerabilities.

This project is part of a Bachelor’s Thesis in Information Systems for the School of Computation, Information and Technology — Informatics at the Technische Universität München (TUM)
## Setup and Execution

Setup Folder Structure
```bash
mkdir SmartContractQACode<<-Iteration1>>
cd SmartContractQACode<<-Iteration1>>
mkdir TealerDir
mkdir SlitherDir
mkdir SmartContractQAThesisFiles
```

Clone Detection Scripts and Test Smart Contracts
```bash
cd SmartContractQAThesisFiles
git clone git@github.com:MetinLamby/AutomatedSmartContractQAScripts.git
cd ..
```

### Ethereum Smart Contract QA
Clone the Slither Framework
```bash
cd SlitherDir
virtualenv --python=/usr/bin/python3 venv
git clone git@github.com:crytic/slither.git
source venv/bin/activate
cd slither
python3 setup.py install
pip3 install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

Move Slither Detection Scripts into Frameworks and Execute
```bash
mv SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/SlitherDetectionScripts/ SlitherDir/slither/examples/scripts/
cd SlitherDir
source venv/bin/activate
cd slither
# choose the vulnerability you want to detect
# DETECTORs are CentralizationRisk.py, BlockInformationDependency.py and DenialOfService.py
python examples/scripts/SlitherDetectionScripts/<<DETECTOR>> ../../SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TestSmartContracts/Solidity/experimentContract.sol
cd ../../
```

### Algorand Smart Contract QA
Clone Tealer Framework and Test
```bash
cd TealerDir
virtualenv --python=/usr/bin/python3 venv
git clone git@github.com:crytic/tealer.git
# for some reason the detector scripts only work without virtual environment
# virtualenv --python=/usr/bin/python3 venv
# source venv/bin/activate
cd tealer
pip install -e ".[dev]"
cd ../..
```

Move Tealer Detection Scripts into Frameworks and Execute

```bash
mv SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TealerDetectionScripts TealerDir/tealer/tealer/detectors/
# register detectors in all_detectors.py file
echo "from tealer.detectors.TealerDetectionScripts.CentralizationRisk import CentralizationRiskDetector
from tealer.detectors.TealerDetectionScripts.BlockInformationDependency import BlockInformationDepenecy
from tealer.detectors.TealerDetectionScripts.DenialOfService import DenialOfServiceDetector
from tealer.detectors.TealerDetectionScripts.FrozenTokens import FreezingAssetsUpdated" >> tealer/detectors/all_detectors.py
# choose the vulnerability you want to detect
# DETECTORs are freezingAssetsUpdated, denialOfService, centralizationRisk and blockInformationDependency
tealer ../../SmartContractQAThesisFiles/AutomatedSmartContractQAScripts/TestSmartContracts/TEAL/test.teal --detect <<DETECTOR>>
```
## Demo
- [TEAL Smart Contract Static Analysis Demo](https://youtu.be/AnB4bfgr-ps)
- [Solidity Smart Contract Static Analysis Demo](https://youtu.be/AnB4bfgr-ps)

## Related

The related static analysis frameworks are
[Tealer](https://github.com/crytic/tealer) and 
[Slither](https://github.com/crytic/slither)

