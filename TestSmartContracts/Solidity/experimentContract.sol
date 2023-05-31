// Source: https://github.com/crytic/not-so-smart-contracts/blob/master/bad_randomness/theRun_source_code/theRun.sol
// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract ExternalContract {
    uint public number;
    function getBlockData() public view returns(uint blockNumber) {
        return block.number;
    }
}

contract Experiment {

    mapping(address => uint256) public balances;
    address payable owner;
    address payable externalAccount;
    ExternalContract public externalCon;

    constructor() {
        owner = payable(msg.sender);
        balances[owner] = 1 ether;
        balances[externalAccount] = 1 ether;
    }

    // +++++++++++++++ helper modifers +++++++++++++++
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    // +++++++++++++++ helper functions +++++++++++++++
    function getOwnerBalance() public view returns(uint256 ownerBalance) {
        return balances[owner];
    }

    function getExternalAccountBalance() public view returns(uint256 externalAccountBalance) {
        return balances[externalAccount];
    }

    function getOwner() public view returns(address ownerVariable) {
        return owner;
    }

    function modifyMsgValue() public payable returns(uint value) {
        return  3 + msg.value;
    }


    // +++++++++++++++ vulnerability injections +++++++++++++++
    // 1) freezing assets vulnerability is not included because already covered by Slither

    // 2)
    // centralization risks vulnerability
    // vulnerability: when a contract includes fund modifying logic where the access to that logic is restricted to privileged users with access control patterns
    // add the onlyOwner modifier to add the centralization risk vulnerability
    function centralizationRisk() public payable onlyOwner {
        require(msg.value > 0 ether);
        balances[externalAccount] = balances[externalAccount] + msg.value;
    }

    // 3)
    // block information dependency vulnerability
    // vulnerability: if block data was utilized within the same function as function that can send ether (withdraw or deposit)
    function blockInformationDependency(uint amount) public payable {
        require(msg.value == amount);
        require(msg.value > 0 ether);
        // uncomment the below line to add the block information dependency vulnerability
        amount = amount + block.number;
        balances[owner] = balances[owner] + amount;
    }

    // 4)
    // denial of service vulnerability
    // vulnerability: if conditional includes an external call
    function denialOfService() public payable returns(bool constantSimilarBool) {
        //uint constantNumber = 3;
        //uint constantNumberTwo = 3;
        // uncomment the conditional with external call to add the vulnerability
        // uncomment the conditional without external call to remove the vulnerability (use constants but also comment out constant variables)
        // if (constantNumber == constantNumberTwo) {
        if (payable(owner).send(msg.value)) {
            return true;
        } else {
            return false;
        }
    }


}

