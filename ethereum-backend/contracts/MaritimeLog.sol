pragma solidity ^0.8.0;

contract MaritimeLog {
    // Roles
    bytes32 public constant ROLE_OPERATOR = keccak256("OPERATOR");
    bytes32 public constant ROLE_OEM = keccak256("OEM");
    bytes32 public constant ROLE_SERVICE = keccak256("SERVICE");

    // Role -> (Wallet address -> bool)
    mapping(bytes32 => mapping(address => bool)) public roles;


    // Data Structures
    struct Part {
        string partName;
        address manufacturer;
        string serialNumber;
        uint256 manufactureDate;
        uint256 warrantyExpiryDate;
        string certificateHash;
        bool exists;
    }

    struct ServiceEvent {
        address serviceProvider;
        uint256 eventTimestamp;
        string serviceType;
        string protocolHash;
    }

    // Data storage
    mapping(bytes32 => Part) public parts;

    // Service events history
    mapping(bytes32 => ServiceEvent[]) public partHistory;


    //Events
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event PartRegistered(
        bytes32 indexed partId,
        string partName,
        address manufacturer,
        string serialNumber
    );
    event ServiceEventLogged(
        bytes32 indexed partId,
        address serviceProvider,
        string serviceType,
        uint256 eventTimestamp
    );
    event WarrantyExtented(
        bytes32 indexed partId,
        uint256 newExpiryDate,
        address extendedBy
    );


    // Managment Functions
    // Constructor
    constructor() {
        roles[ROLE_OPERATOR][msg.sender] = true;
        emit RoleGranted(ROLE_OPERATOR, msg.sender);
    }

    modifier onlyRole(bytes32 _role) {
        require(roles[_role][msg.sender], "Access denied: no permission for this operation.");
        _;
    }

    modifier validRole(bytes32 _role) {
        require(
            _role == ROLE_OPERATOR ||
            _role == ROLE_SERVICE ||
            _role == ROLE_OEM,
            "Invalid role."
        );
        _;
    }

    function grantRole(bytes32 _role, address _account) public onlyRole(ROLE_OPERATOR) validRole(_role) {
        roles[_role][_account] = true;
        emit RoleGranted(_role, _account);
    }

    function revokeRole(bytes32 _role, address _account) public onlyRole(ROLE_OPERATOR) {
        roles[_role][_account] = false;
        emit RoleRevoked(_role, _account);
    }

    // Transaction Functions
    function registerPart(
        string memory _partName,
        string memory _serialNumber,
        uint256 _warrantySeconds,
        string memory _certificateHash
    ) public onlyRole(ROLE_OEM) returns (bytes32) {
        // part ID is hash of manufacturer address + serial number
        bytes32 newPartId = keccak256(abi.encodePacked(msg.sender, _serialNumber));
        require(!parts[newPartId].exists, "Part with this serial number already registered by this OEM.");

        parts[newPartId] = Part({
            partName: _partName,
            manufacturer: msg.sender,
            serialNumber: _serialNumber,
            manufactureDate: block.timestamp,
            warrantyExpiryDate: block.timestamp + _warrantySeconds,
            certificateHash: _certificateHash,
            exists: true
        });

        emit PartRegistered(newPartId, _partName, msg.sender, _serialNumber);
        return newPartId;
    }

    function logServiceEvent(
        bytes32 _partId,
        string memory _serviceType,
        string memory _protocolHash
    ) public {
        bool isService = roles[ROLE_SERVICE][msg.sender];
        bool isOperator = roles[ROLE_OPERATOR][msg.sender];
        require(isService || isOperator, "Access denied: no permission to log service event.");
        require(parts[_partId].exists, "Part does not exist.");

        partHistory[_partId].push(ServiceEvent({
            serviceProvider: msg.sender,
            eventTimestamp: block.timestamp,
            serviceType: _serviceType,
            protocolHash: _protocolHash
        }));

        emit ServiceEventLogged(_partId, msg.sender, _serviceType, block.timestamp);
    }

    function extendWarranty(bytes32 _partId, uint256 _additionalSeconds) public onlyRole(ROLE_OEM) {
        require(parts[_partId].exists, "Part not registered.");
        require(parts[_partId].manufacturer == msg.sender, "Only the OEM who manufactured the part can extend its warranty.");

        parts[_partId].warrantyExpiryDate += _additionalSeconds;

        emit WarrantyExtented(_partId, parts[_partId].warrantyExpiryDate, msg.sender);
    }

    function getPartId(address _manufacturer, string memory _serialNumber) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_manufacturer, _serialNumber));
    }

    function checkWarrantyStatus(bytes32 _partId) public view returns (bool isValid, uint256 timeLeft) {
        require(parts[_partId].exists, "Part not registered.");
        if (block.timestamp < parts[_partId].warrantyExpiryDate) {
            return (true, parts[_partId].warrantyExpiryDate - block.timestamp);
        } else {
            return (false, 0);
        }
    }

    function getPartHistory(bytes32 _partId) public view returns (ServiceEvent[] memory) {
        require(parts[_partId].exists, "Part not registered.");
        return partHistory[_partId];
    }

}