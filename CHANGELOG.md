# Changelog

## 2.0.0
### Changed
- Moved many standalone functions to util.py
- Using params (containing genesis hash and suggested fee) for transactions; deprecating individual genesis hash and fee inputs
- Renamed params.py to node_params.py to avoid confusion with transaction "params" input
- In KeyregTxn, selkey and votekey are now in base64 instead of base32
- Renamed address_from_private_key() to public_key_from_private_key()
- Renamed retrieve_from_file() to read_from_file()
- When sending a transaction, transaction ID is returned in a dictionary
- Removed redundant args/attributes in docstrings

### Fixed
- decoding plain transactions in read_from_file()

### Added
- contract templates:
    - DynamicFee
    - PeriodicPayment
    - LimitOrder
- type suggestions for functions

## 1.1.1
### Added
- Added asset decimals field.

## 1.1.0
### Added
- Added support for Algorand Standardized Assets (ASA)
- Added support for Algorand Smart Contracts (ASC) 
    - Added support for Hashed Time Lock Contract (HTLC) 
    - Added support for Split contract
- Added support for Group Transactions
- Added support for leases

## 1.0.5
### Added
- custom headers and example

## 1.0.4
### Changed
- more flexibility in transactions_by_address()
- documentation changes

## 1.0.3
### Added
- signing and verifying signatures for arbitrary bytes

## 1.0.2
### Added
- option for flat fee when creating transactions
- functions for converting from microalgos to algos and from algos to microalgos

## 1.0.1
### Added
- algod.send_transaction(): sends SignedTransaction

### Changed
- algod.send_raw_transaction(): sends base64 encoded transaction
- Multisig.get_account_from_sig() is now Multisig.get_multisig_account

## 1.0.0
### Added
- SDK released