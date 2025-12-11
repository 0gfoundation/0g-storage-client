// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// EpochRange is an auto generated low-level Go binding around an user-defined struct.
type EpochRange struct {
	Start *big.Int
	End   *big.Int
}

// EpochRangeWithContextDigest is an auto generated low-level Go binding around an user-defined struct.
type EpochRangeWithContextDigest struct {
	Start  *big.Int
	End    *big.Int
	Digest [32]byte
}

// MineContext is an auto generated low-level Go binding around an user-defined struct.
type MineContext struct {
	Epoch       *big.Int
	MineStart   *big.Int
	FlowRoot    [32]byte
	FlowLength  *big.Int
	BlockDigest [32]byte
	Digest      [32]byte
}

// Submission is an auto generated low-level Go binding around an user-defined struct.
type Submission struct {
	Data      SubmissionData
	Submitter common.Address
}

// SubmissionData is an auto generated low-level Go binding around an user-defined struct.
type SubmissionData struct {
	Length *big.Int
	Tags   []byte
	Nodes  []SubmissionNode
}

// SubmissionNode is an auto generated low-level Go binding around an user-defined struct.
type SubmissionNode struct {
	Root   [32]byte
	Height *big.Int
}

// FlowMetaData contains all meta data concerning the Flow contract.
var FlowMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"deployDelay_\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"AccessControlBadConfirmation\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"bytes32\",\"name\":\"neededRole\",\"type\":\"bytes32\"}],\"name\":\"AccessControlUnauthorizedAccount\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"EnforcedPause\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ExpectedPause\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidInitialization\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidSubmission\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"price\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"paid\",\"type\":\"uint256\"}],\"name\":\"NotEnoughFee\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotInitializing\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint64\",\"name\":\"version\",\"type\":\"uint64\"}],\"name\":\"Initialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"startMerkleRoot\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"submissionIndex\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"flowLength\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"context\",\"type\":\"bytes32\"}],\"name\":\"NewEpoch\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Paused\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"previousAdminRole\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"newAdminRole\",\"type\":\"bytes32\"}],\"name\":\"RoleAdminChanged\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleGranted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"}],\"name\":\"RoleRevoked\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"internalType\":\"bytes32\",\"name\":\"identity\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"submissionIndex\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"startPos\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"length\",\"type\":\"uint256\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"length\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"tags\",\"type\":\"bytes\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"height\",\"type\":\"uint256\"}],\"internalType\":\"structSubmissionNode[]\",\"name\":\"nodes\",\"type\":\"tuple[]\"}],\"indexed\":false,\"internalType\":\"structSubmissionData\",\"name\":\"submission\",\"type\":\"tuple\"}],\"name\":\"Submit\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"Unpaused\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"DEFAULT_ADMIN_ROLE\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"PAUSER_ROLE\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"length\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"tags\",\"type\":\"bytes\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"height\",\"type\":\"uint256\"}],\"internalType\":\"structSubmissionNode[]\",\"name\":\"nodes\",\"type\":\"tuple[]\"}],\"internalType\":\"structSubmissionData\",\"name\":\"data\",\"type\":\"tuple\"},{\"internalType\":\"address\",\"name\":\"submitter\",\"type\":\"address\"}],\"internalType\":\"structSubmission[]\",\"name\":\"submissions\",\"type\":\"tuple[]\"}],\"name\":\"batchSubmit\",\"outputs\":[{\"internalType\":\"uint256[]\",\"name\":\"indexes\",\"type\":\"uint256[]\"},{\"internalType\":\"bytes32[]\",\"name\":\"digests\",\"type\":\"bytes32[]\"},{\"internalType\":\"uint256[]\",\"name\":\"startIndexes\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256[]\",\"name\":\"lengths\",\"type\":\"uint256[]\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"blocksPerEpoch\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"computeFlowRoot\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"deployDelay\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"epoch\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"epochStartPosition\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"firstBlock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getContext\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"epoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"mineStart\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"flowRoot\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"flowLength\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"blockDigest\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"}],\"internalType\":\"structMineContext\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"}],\"name\":\"getEpochRange\",\"outputs\":[{\"components\":[{\"internalType\":\"uint128\",\"name\":\"start\",\"type\":\"uint128\"},{\"internalType\":\"uint128\",\"name\":\"end\",\"type\":\"uint128\"}],\"internalType\":\"structEpochRange\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getEpochRangeHistory\",\"outputs\":[{\"components\":[{\"internalType\":\"uint128\",\"name\":\"start\",\"type\":\"uint128\"},{\"internalType\":\"uint128\",\"name\":\"end\",\"type\":\"uint128\"},{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"}],\"internalType\":\"structEpochRangeWithContextDigest\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"txSeq\",\"type\":\"uint256\"}],\"name\":\"getFlowRootByTxSeq\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"}],\"name\":\"getRoleAdmin\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"}],\"name\":\"getRoleMember\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"}],\"name\":\"getRoleMemberCount\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"grantRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"hasRole\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"market_\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"blocksPerEpoch_\",\"type\":\"uint256\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"makeContext\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"cnt\",\"type\":\"uint256\"}],\"name\":\"makeContextFixedTimes\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"makeContextWithResult\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"epoch\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"mineStart\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"flowRoot\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"flowLength\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"blockDigest\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"}],\"internalType\":\"structMineContext\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"market\",\"outputs\":[{\"internalType\":\"addresspayable\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"numSubmissions\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint128\",\"name\":\"targetPosition\",\"type\":\"uint128\"}],\"name\":\"queryContextAtPosition\",\"outputs\":[{\"components\":[{\"internalType\":\"uint128\",\"name\":\"start\",\"type\":\"uint128\"},{\"internalType\":\"uint128\",\"name\":\"end\",\"type\":\"uint128\"},{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"}],\"internalType\":\"structEpochRangeWithContextDigest\",\"name\":\"range\",\"type\":\"tuple\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"callerConfirmation\",\"type\":\"address\"}],\"name\":\"renounceRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"role\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"}],\"name\":\"revokeRole\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"rootHistory\",\"outputs\":[{\"internalType\":\"contractIDigestHistory\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"blocksPerEpoch_\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"firstBlock_\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"rootHistory_\",\"type\":\"address\"}],\"name\":\"setParams\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"submissionIndex\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"length\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"tags\",\"type\":\"bytes\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"height\",\"type\":\"uint256\"}],\"internalType\":\"structSubmissionNode[]\",\"name\":\"nodes\",\"type\":\"tuple[]\"}],\"internalType\":\"structSubmissionData\",\"name\":\"data\",\"type\":\"tuple\"},{\"internalType\":\"address\",\"name\":\"submitter\",\"type\":\"address\"}],\"internalType\":\"structSubmission\",\"name\":\"submission\",\"type\":\"tuple\"}],\"name\":\"submit\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"digest\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"startIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"length\",\"type\":\"uint256\"}],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes4\",\"name\":\"interfaceId\",\"type\":\"bytes4\"}],\"name\":\"supportsInterface\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"tree\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"currentLength\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"unstagedHeight\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
}

// FlowABI is the input ABI used to generate the binding from.
// Deprecated: Use FlowMetaData.ABI instead.
var FlowABI = FlowMetaData.ABI

// Flow is an auto generated Go binding around an Ethereum contract.
type Flow struct {
	FlowCaller     // Read-only binding to the contract
	FlowTransactor // Write-only binding to the contract
	FlowFilterer   // Log filterer for contract events
}

// FlowCaller is an auto generated read-only Go binding around an Ethereum contract.
type FlowCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FlowTransactor is an auto generated write-only Go binding around an Ethereum contract.
type FlowTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FlowFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type FlowFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// FlowSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type FlowSession struct {
	Contract     *Flow             // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// FlowCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type FlowCallerSession struct {
	Contract *FlowCaller   // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// FlowTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type FlowTransactorSession struct {
	Contract     *FlowTransactor   // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// FlowRaw is an auto generated low-level Go binding around an Ethereum contract.
type FlowRaw struct {
	Contract *Flow // Generic contract binding to access the raw methods on
}

// FlowCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type FlowCallerRaw struct {
	Contract *FlowCaller // Generic read-only contract binding to access the raw methods on
}

// FlowTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type FlowTransactorRaw struct {
	Contract *FlowTransactor // Generic write-only contract binding to access the raw methods on
}

// NewFlow creates a new instance of Flow, bound to a specific deployed contract.
func NewFlow(address common.Address, backend bind.ContractBackend) (*Flow, error) {
	contract, err := bindFlow(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Flow{FlowCaller: FlowCaller{contract: contract}, FlowTransactor: FlowTransactor{contract: contract}, FlowFilterer: FlowFilterer{contract: contract}}, nil
}

// NewFlowCaller creates a new read-only instance of Flow, bound to a specific deployed contract.
func NewFlowCaller(address common.Address, caller bind.ContractCaller) (*FlowCaller, error) {
	contract, err := bindFlow(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &FlowCaller{contract: contract}, nil
}

// NewFlowTransactor creates a new write-only instance of Flow, bound to a specific deployed contract.
func NewFlowTransactor(address common.Address, transactor bind.ContractTransactor) (*FlowTransactor, error) {
	contract, err := bindFlow(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &FlowTransactor{contract: contract}, nil
}

// NewFlowFilterer creates a new log filterer instance of Flow, bound to a specific deployed contract.
func NewFlowFilterer(address common.Address, filterer bind.ContractFilterer) (*FlowFilterer, error) {
	contract, err := bindFlow(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &FlowFilterer{contract: contract}, nil
}

// bindFlow binds a generic wrapper to an already deployed contract.
func bindFlow(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := FlowMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Flow *FlowRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Flow.Contract.FlowCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Flow *FlowRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.Contract.FlowTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Flow *FlowRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Flow.Contract.FlowTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Flow *FlowCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Flow.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Flow *FlowTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Flow *FlowTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Flow.Contract.contract.Transact(opts, method, params...)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Flow *FlowCaller) DEFAULTADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "DEFAULT_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Flow *FlowSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _Flow.Contract.DEFAULTADMINROLE(&_Flow.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_Flow *FlowCallerSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _Flow.Contract.DEFAULTADMINROLE(&_Flow.CallOpts)
}

// PAUSERROLE is a free data retrieval call binding the contract method 0xe63ab1e9.
//
// Solidity: function PAUSER_ROLE() view returns(bytes32)
func (_Flow *FlowCaller) PAUSERROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "PAUSER_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// PAUSERROLE is a free data retrieval call binding the contract method 0xe63ab1e9.
//
// Solidity: function PAUSER_ROLE() view returns(bytes32)
func (_Flow *FlowSession) PAUSERROLE() ([32]byte, error) {
	return _Flow.Contract.PAUSERROLE(&_Flow.CallOpts)
}

// PAUSERROLE is a free data retrieval call binding the contract method 0xe63ab1e9.
//
// Solidity: function PAUSER_ROLE() view returns(bytes32)
func (_Flow *FlowCallerSession) PAUSERROLE() ([32]byte, error) {
	return _Flow.Contract.PAUSERROLE(&_Flow.CallOpts)
}

// BlocksPerEpoch is a free data retrieval call binding the contract method 0xf0682054.
//
// Solidity: function blocksPerEpoch() view returns(uint256)
func (_Flow *FlowCaller) BlocksPerEpoch(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "blocksPerEpoch")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BlocksPerEpoch is a free data retrieval call binding the contract method 0xf0682054.
//
// Solidity: function blocksPerEpoch() view returns(uint256)
func (_Flow *FlowSession) BlocksPerEpoch() (*big.Int, error) {
	return _Flow.Contract.BlocksPerEpoch(&_Flow.CallOpts)
}

// BlocksPerEpoch is a free data retrieval call binding the contract method 0xf0682054.
//
// Solidity: function blocksPerEpoch() view returns(uint256)
func (_Flow *FlowCallerSession) BlocksPerEpoch() (*big.Int, error) {
	return _Flow.Contract.BlocksPerEpoch(&_Flow.CallOpts)
}

// DeployDelay is a free data retrieval call binding the contract method 0x9bbbfdbb.
//
// Solidity: function deployDelay() view returns(uint256)
func (_Flow *FlowCaller) DeployDelay(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "deployDelay")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// DeployDelay is a free data retrieval call binding the contract method 0x9bbbfdbb.
//
// Solidity: function deployDelay() view returns(uint256)
func (_Flow *FlowSession) DeployDelay() (*big.Int, error) {
	return _Flow.Contract.DeployDelay(&_Flow.CallOpts)
}

// DeployDelay is a free data retrieval call binding the contract method 0x9bbbfdbb.
//
// Solidity: function deployDelay() view returns(uint256)
func (_Flow *FlowCallerSession) DeployDelay() (*big.Int, error) {
	return _Flow.Contract.DeployDelay(&_Flow.CallOpts)
}

// Epoch is a free data retrieval call binding the contract method 0x900cf0cf.
//
// Solidity: function epoch() view returns(uint256)
func (_Flow *FlowCaller) Epoch(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "epoch")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Epoch is a free data retrieval call binding the contract method 0x900cf0cf.
//
// Solidity: function epoch() view returns(uint256)
func (_Flow *FlowSession) Epoch() (*big.Int, error) {
	return _Flow.Contract.Epoch(&_Flow.CallOpts)
}

// Epoch is a free data retrieval call binding the contract method 0x900cf0cf.
//
// Solidity: function epoch() view returns(uint256)
func (_Flow *FlowCallerSession) Epoch() (*big.Int, error) {
	return _Flow.Contract.Epoch(&_Flow.CallOpts)
}

// EpochStartPosition is a free data retrieval call binding the contract method 0x93e405a0.
//
// Solidity: function epochStartPosition() view returns(uint256)
func (_Flow *FlowCaller) EpochStartPosition(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "epochStartPosition")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// EpochStartPosition is a free data retrieval call binding the contract method 0x93e405a0.
//
// Solidity: function epochStartPosition() view returns(uint256)
func (_Flow *FlowSession) EpochStartPosition() (*big.Int, error) {
	return _Flow.Contract.EpochStartPosition(&_Flow.CallOpts)
}

// EpochStartPosition is a free data retrieval call binding the contract method 0x93e405a0.
//
// Solidity: function epochStartPosition() view returns(uint256)
func (_Flow *FlowCallerSession) EpochStartPosition() (*big.Int, error) {
	return _Flow.Contract.EpochStartPosition(&_Flow.CallOpts)
}

// FirstBlock is a free data retrieval call binding the contract method 0x231b0268.
//
// Solidity: function firstBlock() view returns(uint256)
func (_Flow *FlowCaller) FirstBlock(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "firstBlock")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// FirstBlock is a free data retrieval call binding the contract method 0x231b0268.
//
// Solidity: function firstBlock() view returns(uint256)
func (_Flow *FlowSession) FirstBlock() (*big.Int, error) {
	return _Flow.Contract.FirstBlock(&_Flow.CallOpts)
}

// FirstBlock is a free data retrieval call binding the contract method 0x231b0268.
//
// Solidity: function firstBlock() view returns(uint256)
func (_Flow *FlowCallerSession) FirstBlock() (*big.Int, error) {
	return _Flow.Contract.FirstBlock(&_Flow.CallOpts)
}

// GetContext is a free data retrieval call binding the contract method 0x127f0f07.
//
// Solidity: function getContext() view returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowCaller) GetContext(opts *bind.CallOpts) (MineContext, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getContext")

	if err != nil {
		return *new(MineContext), err
	}

	out0 := *abi.ConvertType(out[0], new(MineContext)).(*MineContext)

	return out0, err

}

// GetContext is a free data retrieval call binding the contract method 0x127f0f07.
//
// Solidity: function getContext() view returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowSession) GetContext() (MineContext, error) {
	return _Flow.Contract.GetContext(&_Flow.CallOpts)
}

// GetContext is a free data retrieval call binding the contract method 0x127f0f07.
//
// Solidity: function getContext() view returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowCallerSession) GetContext() (MineContext, error) {
	return _Flow.Contract.GetContext(&_Flow.CallOpts)
}

// GetEpochRange is a free data retrieval call binding the contract method 0x7d590708.
//
// Solidity: function getEpochRange(bytes32 digest) view returns((uint128,uint128))
func (_Flow *FlowCaller) GetEpochRange(opts *bind.CallOpts, digest [32]byte) (EpochRange, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getEpochRange", digest)

	if err != nil {
		return *new(EpochRange), err
	}

	out0 := *abi.ConvertType(out[0], new(EpochRange)).(*EpochRange)

	return out0, err

}

// GetEpochRange is a free data retrieval call binding the contract method 0x7d590708.
//
// Solidity: function getEpochRange(bytes32 digest) view returns((uint128,uint128))
func (_Flow *FlowSession) GetEpochRange(digest [32]byte) (EpochRange, error) {
	return _Flow.Contract.GetEpochRange(&_Flow.CallOpts, digest)
}

// GetEpochRange is a free data retrieval call binding the contract method 0x7d590708.
//
// Solidity: function getEpochRange(bytes32 digest) view returns((uint128,uint128))
func (_Flow *FlowCallerSession) GetEpochRange(digest [32]byte) (EpochRange, error) {
	return _Flow.Contract.GetEpochRange(&_Flow.CallOpts, digest)
}

// GetEpochRangeHistory is a free data retrieval call binding the contract method 0x4282b532.
//
// Solidity: function getEpochRangeHistory(uint256 index) view returns((uint128,uint128,bytes32))
func (_Flow *FlowCaller) GetEpochRangeHistory(opts *bind.CallOpts, index *big.Int) (EpochRangeWithContextDigest, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getEpochRangeHistory", index)

	if err != nil {
		return *new(EpochRangeWithContextDigest), err
	}

	out0 := *abi.ConvertType(out[0], new(EpochRangeWithContextDigest)).(*EpochRangeWithContextDigest)

	return out0, err

}

// GetEpochRangeHistory is a free data retrieval call binding the contract method 0x4282b532.
//
// Solidity: function getEpochRangeHistory(uint256 index) view returns((uint128,uint128,bytes32))
func (_Flow *FlowSession) GetEpochRangeHistory(index *big.Int) (EpochRangeWithContextDigest, error) {
	return _Flow.Contract.GetEpochRangeHistory(&_Flow.CallOpts, index)
}

// GetEpochRangeHistory is a free data retrieval call binding the contract method 0x4282b532.
//
// Solidity: function getEpochRangeHistory(uint256 index) view returns((uint128,uint128,bytes32))
func (_Flow *FlowCallerSession) GetEpochRangeHistory(index *big.Int) (EpochRangeWithContextDigest, error) {
	return _Flow.Contract.GetEpochRangeHistory(&_Flow.CallOpts, index)
}

// GetFlowRootByTxSeq is a free data retrieval call binding the contract method 0x6d7ad0fc.
//
// Solidity: function getFlowRootByTxSeq(uint256 txSeq) view returns(bytes32)
func (_Flow *FlowCaller) GetFlowRootByTxSeq(opts *bind.CallOpts, txSeq *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getFlowRootByTxSeq", txSeq)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetFlowRootByTxSeq is a free data retrieval call binding the contract method 0x6d7ad0fc.
//
// Solidity: function getFlowRootByTxSeq(uint256 txSeq) view returns(bytes32)
func (_Flow *FlowSession) GetFlowRootByTxSeq(txSeq *big.Int) ([32]byte, error) {
	return _Flow.Contract.GetFlowRootByTxSeq(&_Flow.CallOpts, txSeq)
}

// GetFlowRootByTxSeq is a free data retrieval call binding the contract method 0x6d7ad0fc.
//
// Solidity: function getFlowRootByTxSeq(uint256 txSeq) view returns(bytes32)
func (_Flow *FlowCallerSession) GetFlowRootByTxSeq(txSeq *big.Int) ([32]byte, error) {
	return _Flow.Contract.GetFlowRootByTxSeq(&_Flow.CallOpts, txSeq)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Flow *FlowCaller) GetRoleAdmin(opts *bind.CallOpts, role [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getRoleAdmin", role)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Flow *FlowSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _Flow.Contract.GetRoleAdmin(&_Flow.CallOpts, role)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_Flow *FlowCallerSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _Flow.Contract.GetRoleAdmin(&_Flow.CallOpts, role)
}

// GetRoleMember is a free data retrieval call binding the contract method 0x9010d07c.
//
// Solidity: function getRoleMember(bytes32 role, uint256 index) view returns(address)
func (_Flow *FlowCaller) GetRoleMember(opts *bind.CallOpts, role [32]byte, index *big.Int) (common.Address, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getRoleMember", role, index)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetRoleMember is a free data retrieval call binding the contract method 0x9010d07c.
//
// Solidity: function getRoleMember(bytes32 role, uint256 index) view returns(address)
func (_Flow *FlowSession) GetRoleMember(role [32]byte, index *big.Int) (common.Address, error) {
	return _Flow.Contract.GetRoleMember(&_Flow.CallOpts, role, index)
}

// GetRoleMember is a free data retrieval call binding the contract method 0x9010d07c.
//
// Solidity: function getRoleMember(bytes32 role, uint256 index) view returns(address)
func (_Flow *FlowCallerSession) GetRoleMember(role [32]byte, index *big.Int) (common.Address, error) {
	return _Flow.Contract.GetRoleMember(&_Flow.CallOpts, role, index)
}

// GetRoleMemberCount is a free data retrieval call binding the contract method 0xca15c873.
//
// Solidity: function getRoleMemberCount(bytes32 role) view returns(uint256)
func (_Flow *FlowCaller) GetRoleMemberCount(opts *bind.CallOpts, role [32]byte) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "getRoleMemberCount", role)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRoleMemberCount is a free data retrieval call binding the contract method 0xca15c873.
//
// Solidity: function getRoleMemberCount(bytes32 role) view returns(uint256)
func (_Flow *FlowSession) GetRoleMemberCount(role [32]byte) (*big.Int, error) {
	return _Flow.Contract.GetRoleMemberCount(&_Flow.CallOpts, role)
}

// GetRoleMemberCount is a free data retrieval call binding the contract method 0xca15c873.
//
// Solidity: function getRoleMemberCount(bytes32 role) view returns(uint256)
func (_Flow *FlowCallerSession) GetRoleMemberCount(role [32]byte) (*big.Int, error) {
	return _Flow.Contract.GetRoleMemberCount(&_Flow.CallOpts, role)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Flow *FlowCaller) HasRole(opts *bind.CallOpts, role [32]byte, account common.Address) (bool, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "hasRole", role, account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Flow *FlowSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _Flow.Contract.HasRole(&_Flow.CallOpts, role, account)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_Flow *FlowCallerSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _Flow.Contract.HasRole(&_Flow.CallOpts, role, account)
}

// Market is a free data retrieval call binding the contract method 0x80f55605.
//
// Solidity: function market() view returns(address)
func (_Flow *FlowCaller) Market(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "market")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Market is a free data retrieval call binding the contract method 0x80f55605.
//
// Solidity: function market() view returns(address)
func (_Flow *FlowSession) Market() (common.Address, error) {
	return _Flow.Contract.Market(&_Flow.CallOpts)
}

// Market is a free data retrieval call binding the contract method 0x80f55605.
//
// Solidity: function market() view returns(address)
func (_Flow *FlowCallerSession) Market() (common.Address, error) {
	return _Flow.Contract.Market(&_Flow.CallOpts)
}

// NumSubmissions is a free data retrieval call binding the contract method 0x77e19824.
//
// Solidity: function numSubmissions() view returns(uint256)
func (_Flow *FlowCaller) NumSubmissions(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "numSubmissions")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NumSubmissions is a free data retrieval call binding the contract method 0x77e19824.
//
// Solidity: function numSubmissions() view returns(uint256)
func (_Flow *FlowSession) NumSubmissions() (*big.Int, error) {
	return _Flow.Contract.NumSubmissions(&_Flow.CallOpts)
}

// NumSubmissions is a free data retrieval call binding the contract method 0x77e19824.
//
// Solidity: function numSubmissions() view returns(uint256)
func (_Flow *FlowCallerSession) NumSubmissions() (*big.Int, error) {
	return _Flow.Contract.NumSubmissions(&_Flow.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Flow *FlowCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Flow *FlowSession) Paused() (bool, error) {
	return _Flow.Contract.Paused(&_Flow.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_Flow *FlowCallerSession) Paused() (bool, error) {
	return _Flow.Contract.Paused(&_Flow.CallOpts)
}

// RootHistory is a free data retrieval call binding the contract method 0xc7dd5221.
//
// Solidity: function rootHistory() view returns(address)
func (_Flow *FlowCaller) RootHistory(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "rootHistory")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RootHistory is a free data retrieval call binding the contract method 0xc7dd5221.
//
// Solidity: function rootHistory() view returns(address)
func (_Flow *FlowSession) RootHistory() (common.Address, error) {
	return _Flow.Contract.RootHistory(&_Flow.CallOpts)
}

// RootHistory is a free data retrieval call binding the contract method 0xc7dd5221.
//
// Solidity: function rootHistory() view returns(address)
func (_Flow *FlowCallerSession) RootHistory() (common.Address, error) {
	return _Flow.Contract.RootHistory(&_Flow.CallOpts)
}

// SubmissionIndex is a free data retrieval call binding the contract method 0xb8a409ac.
//
// Solidity: function submissionIndex() view returns(uint256)
func (_Flow *FlowCaller) SubmissionIndex(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "submissionIndex")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// SubmissionIndex is a free data retrieval call binding the contract method 0xb8a409ac.
//
// Solidity: function submissionIndex() view returns(uint256)
func (_Flow *FlowSession) SubmissionIndex() (*big.Int, error) {
	return _Flow.Contract.SubmissionIndex(&_Flow.CallOpts)
}

// SubmissionIndex is a free data retrieval call binding the contract method 0xb8a409ac.
//
// Solidity: function submissionIndex() view returns(uint256)
func (_Flow *FlowCallerSession) SubmissionIndex() (*big.Int, error) {
	return _Flow.Contract.SubmissionIndex(&_Flow.CallOpts)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Flow *FlowCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Flow *FlowSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _Flow.Contract.SupportsInterface(&_Flow.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_Flow *FlowCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _Flow.Contract.SupportsInterface(&_Flow.CallOpts, interfaceId)
}

// Tree is a free data retrieval call binding the contract method 0xfd54b228.
//
// Solidity: function tree() view returns(uint256 currentLength, uint256 unstagedHeight)
func (_Flow *FlowCaller) Tree(opts *bind.CallOpts) (struct {
	CurrentLength  *big.Int
	UnstagedHeight *big.Int
}, error) {
	var out []interface{}
	err := _Flow.contract.Call(opts, &out, "tree")

	outstruct := new(struct {
		CurrentLength  *big.Int
		UnstagedHeight *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.CurrentLength = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.UnstagedHeight = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Tree is a free data retrieval call binding the contract method 0xfd54b228.
//
// Solidity: function tree() view returns(uint256 currentLength, uint256 unstagedHeight)
func (_Flow *FlowSession) Tree() (struct {
	CurrentLength  *big.Int
	UnstagedHeight *big.Int
}, error) {
	return _Flow.Contract.Tree(&_Flow.CallOpts)
}

// Tree is a free data retrieval call binding the contract method 0xfd54b228.
//
// Solidity: function tree() view returns(uint256 currentLength, uint256 unstagedHeight)
func (_Flow *FlowCallerSession) Tree() (struct {
	CurrentLength  *big.Int
	UnstagedHeight *big.Int
}, error) {
	return _Flow.Contract.Tree(&_Flow.CallOpts)
}

// BatchSubmit is a paid mutator transaction binding the contract method 0x49aa3395.
//
// Solidity: function batchSubmit(((uint256,bytes,(bytes32,uint256)[]),address)[] submissions) payable returns(uint256[] indexes, bytes32[] digests, uint256[] startIndexes, uint256[] lengths)
func (_Flow *FlowTransactor) BatchSubmit(opts *bind.TransactOpts, submissions []Submission) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "batchSubmit", submissions)
}

// BatchSubmit is a paid mutator transaction binding the contract method 0x49aa3395.
//
// Solidity: function batchSubmit(((uint256,bytes,(bytes32,uint256)[]),address)[] submissions) payable returns(uint256[] indexes, bytes32[] digests, uint256[] startIndexes, uint256[] lengths)
func (_Flow *FlowSession) BatchSubmit(submissions []Submission) (*types.Transaction, error) {
	return _Flow.Contract.BatchSubmit(&_Flow.TransactOpts, submissions)
}

// BatchSubmit is a paid mutator transaction binding the contract method 0x49aa3395.
//
// Solidity: function batchSubmit(((uint256,bytes,(bytes32,uint256)[]),address)[] submissions) payable returns(uint256[] indexes, bytes32[] digests, uint256[] startIndexes, uint256[] lengths)
func (_Flow *FlowTransactorSession) BatchSubmit(submissions []Submission) (*types.Transaction, error) {
	return _Flow.Contract.BatchSubmit(&_Flow.TransactOpts, submissions)
}

// ComputeFlowRoot is a paid mutator transaction binding the contract method 0x1deb0fca.
//
// Solidity: function computeFlowRoot() returns(bytes32)
func (_Flow *FlowTransactor) ComputeFlowRoot(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "computeFlowRoot")
}

// ComputeFlowRoot is a paid mutator transaction binding the contract method 0x1deb0fca.
//
// Solidity: function computeFlowRoot() returns(bytes32)
func (_Flow *FlowSession) ComputeFlowRoot() (*types.Transaction, error) {
	return _Flow.Contract.ComputeFlowRoot(&_Flow.TransactOpts)
}

// ComputeFlowRoot is a paid mutator transaction binding the contract method 0x1deb0fca.
//
// Solidity: function computeFlowRoot() returns(bytes32)
func (_Flow *FlowTransactorSession) ComputeFlowRoot() (*types.Transaction, error) {
	return _Flow.Contract.ComputeFlowRoot(&_Flow.TransactOpts)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Flow *FlowTransactor) GrantRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "grantRole", role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Flow *FlowSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.Contract.GrantRole(&_Flow.TransactOpts, role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_Flow *FlowTransactorSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.Contract.GrantRole(&_Flow.TransactOpts, role, account)
}

// Initialize is a paid mutator transaction binding the contract method 0xcd6dc687.
//
// Solidity: function initialize(address market_, uint256 blocksPerEpoch_) returns()
func (_Flow *FlowTransactor) Initialize(opts *bind.TransactOpts, market_ common.Address, blocksPerEpoch_ *big.Int) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "initialize", market_, blocksPerEpoch_)
}

// Initialize is a paid mutator transaction binding the contract method 0xcd6dc687.
//
// Solidity: function initialize(address market_, uint256 blocksPerEpoch_) returns()
func (_Flow *FlowSession) Initialize(market_ common.Address, blocksPerEpoch_ *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.Initialize(&_Flow.TransactOpts, market_, blocksPerEpoch_)
}

// Initialize is a paid mutator transaction binding the contract method 0xcd6dc687.
//
// Solidity: function initialize(address market_, uint256 blocksPerEpoch_) returns()
func (_Flow *FlowTransactorSession) Initialize(market_ common.Address, blocksPerEpoch_ *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.Initialize(&_Flow.TransactOpts, market_, blocksPerEpoch_)
}

// MakeContext is a paid mutator transaction binding the contract method 0x38d45e10.
//
// Solidity: function makeContext() returns()
func (_Flow *FlowTransactor) MakeContext(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "makeContext")
}

// MakeContext is a paid mutator transaction binding the contract method 0x38d45e10.
//
// Solidity: function makeContext() returns()
func (_Flow *FlowSession) MakeContext() (*types.Transaction, error) {
	return _Flow.Contract.MakeContext(&_Flow.TransactOpts)
}

// MakeContext is a paid mutator transaction binding the contract method 0x38d45e10.
//
// Solidity: function makeContext() returns()
func (_Flow *FlowTransactorSession) MakeContext() (*types.Transaction, error) {
	return _Flow.Contract.MakeContext(&_Flow.TransactOpts)
}

// MakeContextFixedTimes is a paid mutator transaction binding the contract method 0x18a641ef.
//
// Solidity: function makeContextFixedTimes(uint256 cnt) returns()
func (_Flow *FlowTransactor) MakeContextFixedTimes(opts *bind.TransactOpts, cnt *big.Int) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "makeContextFixedTimes", cnt)
}

// MakeContextFixedTimes is a paid mutator transaction binding the contract method 0x18a641ef.
//
// Solidity: function makeContextFixedTimes(uint256 cnt) returns()
func (_Flow *FlowSession) MakeContextFixedTimes(cnt *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.MakeContextFixedTimes(&_Flow.TransactOpts, cnt)
}

// MakeContextFixedTimes is a paid mutator transaction binding the contract method 0x18a641ef.
//
// Solidity: function makeContextFixedTimes(uint256 cnt) returns()
func (_Flow *FlowTransactorSession) MakeContextFixedTimes(cnt *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.MakeContextFixedTimes(&_Flow.TransactOpts, cnt)
}

// MakeContextWithResult is a paid mutator transaction binding the contract method 0xb464b53e.
//
// Solidity: function makeContextWithResult() returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowTransactor) MakeContextWithResult(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "makeContextWithResult")
}

// MakeContextWithResult is a paid mutator transaction binding the contract method 0xb464b53e.
//
// Solidity: function makeContextWithResult() returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowSession) MakeContextWithResult() (*types.Transaction, error) {
	return _Flow.Contract.MakeContextWithResult(&_Flow.TransactOpts)
}

// MakeContextWithResult is a paid mutator transaction binding the contract method 0xb464b53e.
//
// Solidity: function makeContextWithResult() returns((uint256,uint256,bytes32,uint256,bytes32,bytes32))
func (_Flow *FlowTransactorSession) MakeContextWithResult() (*types.Transaction, error) {
	return _Flow.Contract.MakeContextWithResult(&_Flow.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Flow *FlowTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Flow *FlowSession) Pause() (*types.Transaction, error) {
	return _Flow.Contract.Pause(&_Flow.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_Flow *FlowTransactorSession) Pause() (*types.Transaction, error) {
	return _Flow.Contract.Pause(&_Flow.TransactOpts)
}

// QueryContextAtPosition is a paid mutator transaction binding the contract method 0x31bae174.
//
// Solidity: function queryContextAtPosition(uint128 targetPosition) returns((uint128,uint128,bytes32) range)
func (_Flow *FlowTransactor) QueryContextAtPosition(opts *bind.TransactOpts, targetPosition *big.Int) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "queryContextAtPosition", targetPosition)
}

// QueryContextAtPosition is a paid mutator transaction binding the contract method 0x31bae174.
//
// Solidity: function queryContextAtPosition(uint128 targetPosition) returns((uint128,uint128,bytes32) range)
func (_Flow *FlowSession) QueryContextAtPosition(targetPosition *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.QueryContextAtPosition(&_Flow.TransactOpts, targetPosition)
}

// QueryContextAtPosition is a paid mutator transaction binding the contract method 0x31bae174.
//
// Solidity: function queryContextAtPosition(uint128 targetPosition) returns((uint128,uint128,bytes32) range)
func (_Flow *FlowTransactorSession) QueryContextAtPosition(targetPosition *big.Int) (*types.Transaction, error) {
	return _Flow.Contract.QueryContextAtPosition(&_Flow.TransactOpts, targetPosition)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Flow *FlowTransactor) RenounceRole(opts *bind.TransactOpts, role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "renounceRole", role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Flow *FlowSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Flow.Contract.RenounceRole(&_Flow.TransactOpts, role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_Flow *FlowTransactorSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _Flow.Contract.RenounceRole(&_Flow.TransactOpts, role, callerConfirmation)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Flow *FlowTransactor) RevokeRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "revokeRole", role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Flow *FlowSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.Contract.RevokeRole(&_Flow.TransactOpts, role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_Flow *FlowTransactorSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _Flow.Contract.RevokeRole(&_Flow.TransactOpts, role, account)
}

// SetParams is a paid mutator transaction binding the contract method 0xebdec6d3.
//
// Solidity: function setParams(uint256 blocksPerEpoch_, uint256 firstBlock_, address rootHistory_) returns()
func (_Flow *FlowTransactor) SetParams(opts *bind.TransactOpts, blocksPerEpoch_ *big.Int, firstBlock_ *big.Int, rootHistory_ common.Address) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "setParams", blocksPerEpoch_, firstBlock_, rootHistory_)
}

// SetParams is a paid mutator transaction binding the contract method 0xebdec6d3.
//
// Solidity: function setParams(uint256 blocksPerEpoch_, uint256 firstBlock_, address rootHistory_) returns()
func (_Flow *FlowSession) SetParams(blocksPerEpoch_ *big.Int, firstBlock_ *big.Int, rootHistory_ common.Address) (*types.Transaction, error) {
	return _Flow.Contract.SetParams(&_Flow.TransactOpts, blocksPerEpoch_, firstBlock_, rootHistory_)
}

// SetParams is a paid mutator transaction binding the contract method 0xebdec6d3.
//
// Solidity: function setParams(uint256 blocksPerEpoch_, uint256 firstBlock_, address rootHistory_) returns()
func (_Flow *FlowTransactorSession) SetParams(blocksPerEpoch_ *big.Int, firstBlock_ *big.Int, rootHistory_ common.Address) (*types.Transaction, error) {
	return _Flow.Contract.SetParams(&_Flow.TransactOpts, blocksPerEpoch_, firstBlock_, rootHistory_)
}

// Submit is a paid mutator transaction binding the contract method 0xbc8c11f8.
//
// Solidity: function submit(((uint256,bytes,(bytes32,uint256)[]),address) submission) payable returns(uint256 index, bytes32 digest, uint256 startIndex, uint256 length)
func (_Flow *FlowTransactor) Submit(opts *bind.TransactOpts, submission Submission) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "submit", submission)
}

// Submit is a paid mutator transaction binding the contract method 0xbc8c11f8.
//
// Solidity: function submit(((uint256,bytes,(bytes32,uint256)[]),address) submission) payable returns(uint256 index, bytes32 digest, uint256 startIndex, uint256 length)
func (_Flow *FlowSession) Submit(submission Submission) (*types.Transaction, error) {
	return _Flow.Contract.Submit(&_Flow.TransactOpts, submission)
}

// Submit is a paid mutator transaction binding the contract method 0xbc8c11f8.
//
// Solidity: function submit(((uint256,bytes,(bytes32,uint256)[]),address) submission) payable returns(uint256 index, bytes32 digest, uint256 startIndex, uint256 length)
func (_Flow *FlowTransactorSession) Submit(submission Submission) (*types.Transaction, error) {
	return _Flow.Contract.Submit(&_Flow.TransactOpts, submission)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Flow *FlowTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Flow.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Flow *FlowSession) Unpause() (*types.Transaction, error) {
	return _Flow.Contract.Unpause(&_Flow.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_Flow *FlowTransactorSession) Unpause() (*types.Transaction, error) {
	return _Flow.Contract.Unpause(&_Flow.TransactOpts)
}

// FlowInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the Flow contract.
type FlowInitializedIterator struct {
	Event *FlowInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowInitialized represents a Initialized event raised by the Flow contract.
type FlowInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Flow *FlowFilterer) FilterInitialized(opts *bind.FilterOpts) (*FlowInitializedIterator, error) {

	logs, sub, err := _Flow.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &FlowInitializedIterator{contract: _Flow.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Flow *FlowFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *FlowInitialized) (event.Subscription, error) {

	logs, sub, err := _Flow.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowInitialized)
				if err := _Flow.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_Flow *FlowFilterer) ParseInitialized(log types.Log) (*FlowInitialized, error) {
	event := new(FlowInitialized)
	if err := _Flow.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowNewEpochIterator is returned from FilterNewEpoch and is used to iterate over the raw logs and unpacked data for NewEpoch events raised by the Flow contract.
type FlowNewEpochIterator struct {
	Event *FlowNewEpoch // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowNewEpochIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowNewEpoch)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowNewEpoch)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowNewEpochIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowNewEpochIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowNewEpoch represents a NewEpoch event raised by the Flow contract.
type FlowNewEpoch struct {
	Sender          common.Address
	Index           *big.Int
	StartMerkleRoot [32]byte
	SubmissionIndex *big.Int
	FlowLength      *big.Int
	Context         [32]byte
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterNewEpoch is a free log retrieval operation binding the contract event 0xbc8a3fd82465d43f1709e44ed882f7e1af0147274196ef1ec009f5d52ff4e993.
//
// Solidity: event NewEpoch(address indexed sender, uint256 indexed index, bytes32 startMerkleRoot, uint256 submissionIndex, uint256 flowLength, bytes32 context)
func (_Flow *FlowFilterer) FilterNewEpoch(opts *bind.FilterOpts, sender []common.Address, index []*big.Int) (*FlowNewEpochIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var indexRule []interface{}
	for _, indexItem := range index {
		indexRule = append(indexRule, indexItem)
	}

	logs, sub, err := _Flow.contract.FilterLogs(opts, "NewEpoch", senderRule, indexRule)
	if err != nil {
		return nil, err
	}
	return &FlowNewEpochIterator{contract: _Flow.contract, event: "NewEpoch", logs: logs, sub: sub}, nil
}

// WatchNewEpoch is a free log subscription operation binding the contract event 0xbc8a3fd82465d43f1709e44ed882f7e1af0147274196ef1ec009f5d52ff4e993.
//
// Solidity: event NewEpoch(address indexed sender, uint256 indexed index, bytes32 startMerkleRoot, uint256 submissionIndex, uint256 flowLength, bytes32 context)
func (_Flow *FlowFilterer) WatchNewEpoch(opts *bind.WatchOpts, sink chan<- *FlowNewEpoch, sender []common.Address, index []*big.Int) (event.Subscription, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var indexRule []interface{}
	for _, indexItem := range index {
		indexRule = append(indexRule, indexItem)
	}

	logs, sub, err := _Flow.contract.WatchLogs(opts, "NewEpoch", senderRule, indexRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowNewEpoch)
				if err := _Flow.contract.UnpackLog(event, "NewEpoch", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseNewEpoch is a log parse operation binding the contract event 0xbc8a3fd82465d43f1709e44ed882f7e1af0147274196ef1ec009f5d52ff4e993.
//
// Solidity: event NewEpoch(address indexed sender, uint256 indexed index, bytes32 startMerkleRoot, uint256 submissionIndex, uint256 flowLength, bytes32 context)
func (_Flow *FlowFilterer) ParseNewEpoch(log types.Log) (*FlowNewEpoch, error) {
	event := new(FlowNewEpoch)
	if err := _Flow.contract.UnpackLog(event, "NewEpoch", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the Flow contract.
type FlowPausedIterator struct {
	Event *FlowPaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowPaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowPaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowPaused represents a Paused event raised by the Flow contract.
type FlowPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Flow *FlowFilterer) FilterPaused(opts *bind.FilterOpts) (*FlowPausedIterator, error) {

	logs, sub, err := _Flow.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &FlowPausedIterator{contract: _Flow.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Flow *FlowFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *FlowPaused) (event.Subscription, error) {

	logs, sub, err := _Flow.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowPaused)
				if err := _Flow.contract.UnpackLog(event, "Paused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_Flow *FlowFilterer) ParsePaused(log types.Log) (*FlowPaused, error) {
	event := new(FlowPaused)
	if err := _Flow.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowRoleAdminChangedIterator is returned from FilterRoleAdminChanged and is used to iterate over the raw logs and unpacked data for RoleAdminChanged events raised by the Flow contract.
type FlowRoleAdminChangedIterator struct {
	Event *FlowRoleAdminChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowRoleAdminChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowRoleAdminChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowRoleAdminChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowRoleAdminChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowRoleAdminChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowRoleAdminChanged represents a RoleAdminChanged event raised by the Flow contract.
type FlowRoleAdminChanged struct {
	Role              [32]byte
	PreviousAdminRole [32]byte
	NewAdminRole      [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterRoleAdminChanged is a free log retrieval operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Flow *FlowFilterer) FilterRoleAdminChanged(opts *bind.FilterOpts, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (*FlowRoleAdminChangedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _Flow.contract.FilterLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return &FlowRoleAdminChangedIterator{contract: _Flow.contract, event: "RoleAdminChanged", logs: logs, sub: sub}, nil
}

// WatchRoleAdminChanged is a free log subscription operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Flow *FlowFilterer) WatchRoleAdminChanged(opts *bind.WatchOpts, sink chan<- *FlowRoleAdminChanged, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _Flow.contract.WatchLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowRoleAdminChanged)
				if err := _Flow.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleAdminChanged is a log parse operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_Flow *FlowFilterer) ParseRoleAdminChanged(log types.Log) (*FlowRoleAdminChanged, error) {
	event := new(FlowRoleAdminChanged)
	if err := _Flow.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowRoleGrantedIterator is returned from FilterRoleGranted and is used to iterate over the raw logs and unpacked data for RoleGranted events raised by the Flow contract.
type FlowRoleGrantedIterator struct {
	Event *FlowRoleGranted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowRoleGrantedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowRoleGranted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowRoleGranted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowRoleGrantedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowRoleGrantedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowRoleGranted represents a RoleGranted event raised by the Flow contract.
type FlowRoleGranted struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleGranted is a free log retrieval operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) FilterRoleGranted(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*FlowRoleGrantedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Flow.contract.FilterLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &FlowRoleGrantedIterator{contract: _Flow.contract, event: "RoleGranted", logs: logs, sub: sub}, nil
}

// WatchRoleGranted is a free log subscription operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) WatchRoleGranted(opts *bind.WatchOpts, sink chan<- *FlowRoleGranted, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Flow.contract.WatchLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowRoleGranted)
				if err := _Flow.contract.UnpackLog(event, "RoleGranted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleGranted is a log parse operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) ParseRoleGranted(log types.Log) (*FlowRoleGranted, error) {
	event := new(FlowRoleGranted)
	if err := _Flow.contract.UnpackLog(event, "RoleGranted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowRoleRevokedIterator is returned from FilterRoleRevoked and is used to iterate over the raw logs and unpacked data for RoleRevoked events raised by the Flow contract.
type FlowRoleRevokedIterator struct {
	Event *FlowRoleRevoked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowRoleRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowRoleRevoked)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowRoleRevoked)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowRoleRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowRoleRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowRoleRevoked represents a RoleRevoked event raised by the Flow contract.
type FlowRoleRevoked struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleRevoked is a free log retrieval operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) FilterRoleRevoked(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*FlowRoleRevokedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Flow.contract.FilterLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &FlowRoleRevokedIterator{contract: _Flow.contract, event: "RoleRevoked", logs: logs, sub: sub}, nil
}

// WatchRoleRevoked is a free log subscription operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) WatchRoleRevoked(opts *bind.WatchOpts, sink chan<- *FlowRoleRevoked, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _Flow.contract.WatchLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowRoleRevoked)
				if err := _Flow.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleRevoked is a log parse operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_Flow *FlowFilterer) ParseRoleRevoked(log types.Log) (*FlowRoleRevoked, error) {
	event := new(FlowRoleRevoked)
	if err := _Flow.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowSubmitIterator is returned from FilterSubmit and is used to iterate over the raw logs and unpacked data for Submit events raised by the Flow contract.
type FlowSubmitIterator struct {
	Event *FlowSubmit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowSubmitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowSubmit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowSubmit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowSubmitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowSubmitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowSubmit represents a Submit event raised by the Flow contract.
type FlowSubmit struct {
	Sender          common.Address
	Identity        [32]byte
	SubmissionIndex *big.Int
	StartPos        *big.Int
	Length          *big.Int
	Submission      SubmissionData
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterSubmit is a free log retrieval operation binding the contract event 0x167ce04d2aa1981994d3a31695da0d785373335b1078cec239a1a3a2c7675555.
//
// Solidity: event Submit(address indexed sender, bytes32 indexed identity, uint256 submissionIndex, uint256 startPos, uint256 length, (uint256,bytes,(bytes32,uint256)[]) submission)
func (_Flow *FlowFilterer) FilterSubmit(opts *bind.FilterOpts, sender []common.Address, identity [][32]byte) (*FlowSubmitIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var identityRule []interface{}
	for _, identityItem := range identity {
		identityRule = append(identityRule, identityItem)
	}

	logs, sub, err := _Flow.contract.FilterLogs(opts, "Submit", senderRule, identityRule)
	if err != nil {
		return nil, err
	}
	return &FlowSubmitIterator{contract: _Flow.contract, event: "Submit", logs: logs, sub: sub}, nil
}

// WatchSubmit is a free log subscription operation binding the contract event 0x167ce04d2aa1981994d3a31695da0d785373335b1078cec239a1a3a2c7675555.
//
// Solidity: event Submit(address indexed sender, bytes32 indexed identity, uint256 submissionIndex, uint256 startPos, uint256 length, (uint256,bytes,(bytes32,uint256)[]) submission)
func (_Flow *FlowFilterer) WatchSubmit(opts *bind.WatchOpts, sink chan<- *FlowSubmit, sender []common.Address, identity [][32]byte) (event.Subscription, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}
	var identityRule []interface{}
	for _, identityItem := range identity {
		identityRule = append(identityRule, identityItem)
	}

	logs, sub, err := _Flow.contract.WatchLogs(opts, "Submit", senderRule, identityRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowSubmit)
				if err := _Flow.contract.UnpackLog(event, "Submit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSubmit is a log parse operation binding the contract event 0x167ce04d2aa1981994d3a31695da0d785373335b1078cec239a1a3a2c7675555.
//
// Solidity: event Submit(address indexed sender, bytes32 indexed identity, uint256 submissionIndex, uint256 startPos, uint256 length, (uint256,bytes,(bytes32,uint256)[]) submission)
func (_Flow *FlowFilterer) ParseSubmit(log types.Log) (*FlowSubmit, error) {
	event := new(FlowSubmit)
	if err := _Flow.contract.UnpackLog(event, "Submit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// FlowUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the Flow contract.
type FlowUnpausedIterator struct {
	Event *FlowUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *FlowUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(FlowUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(FlowUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *FlowUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *FlowUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// FlowUnpaused represents a Unpaused event raised by the Flow contract.
type FlowUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Flow *FlowFilterer) FilterUnpaused(opts *bind.FilterOpts) (*FlowUnpausedIterator, error) {

	logs, sub, err := _Flow.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &FlowUnpausedIterator{contract: _Flow.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Flow *FlowFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *FlowUnpaused) (event.Subscription, error) {

	logs, sub, err := _Flow.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(FlowUnpaused)
				if err := _Flow.contract.UnpackLog(event, "Unpaused", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_Flow *FlowFilterer) ParseUnpaused(log types.Log) (*FlowUnpaused, error) {
	event := new(FlowUnpaused)
	if err := _Flow.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
