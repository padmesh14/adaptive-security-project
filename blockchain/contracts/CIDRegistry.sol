
 // SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CIDRegistry {
    address public owner;

    struct CIDRecord {
        string cid;
        uint256 timestamp;
        address submittedBy;
    }

    mapping(bytes32 => CIDRecord) private records;

    event CIDStored(
        bytes32 indexed recordId,
        string cid,
        address indexed submittedBy,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function storeCID(bytes32 recordId, string calldata cid) external {
        require(msg.sender == owner, "Only registry owner can write");
        require(bytes(cid).length > 0, "CID cannot be empty");
        require(records[recordId].timestamp == 0, "CID record is immutable");

        records[recordId] = CIDRecord({
            cid: cid,
            timestamp: block.timestamp,
            submittedBy: msg.sender
        });

        emit CIDStored(recordId, cid, msg.sender, block.timestamp);
    }

    function getCID(bytes32 recordId)
        external
        view
        returns (string memory cid, uint256 timestamp, address submittedBy)
    {
        CIDRecord memory record = records[recordId];
        return (record.cid, record.timestamp, record.submittedBy);
    }
}
