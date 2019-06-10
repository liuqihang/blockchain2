// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// interface restrictions
var _ StateDB = (*CommitStateDB)(nil)

type Revision struct {
	ID           int
	JournalIndex int
}

var (
	// emptyState is the known hash of an empty state trie entry.
	emptyState = crypto.Keccak256Hash(nil)

	// emptyCode is the known hash of the empty EVM bytecode.
	emptyCode = crypto.Keccak256Hash(nil)
)

type (
	StateDB interface {
		CreateAccount(common.Address)

		SubBalance(common.Address, *big.Int)
		AddBalance(common.Address, *big.Int)
		GetBalance(common.Address) *big.Int
		SetBalance(addr common.Address, amount *big.Int)

		GetNonce(common.Address) uint64
		SetNonce(common.Address, uint64)

		GetCodeHash(common.Address) common.Hash
		GetCode(common.Address) []byte
		SetCode(common.Address, []byte)
		GetCodeSize(common.Address) int

		AddRefund(uint64)
		SubRefund(uint64)
		GetRefund() uint64

		GetCommittedState(common.Address, common.Hash) common.Hash
		GetState(common.Address, common.Hash) common.Hash
		SetState(common.Address, common.Hash, common.Hash)

		Suicide(common.Address) bool
		HasSuicided(common.Address) bool

		Database() Database

		// Exist reports whether the given account exists in state.
		// Notably this should also return true for suicided accounts.
		Exist(common.Address) bool

		// Empty returns whether the given account is empty. Empty
		// is defined according to EIP161 (balance = nonce = code = 0).
		Empty(common.Address) bool

		RevertToSnapshot(int)
		Snapshot() int

		AddLog(*types.Log)
		GetLogs(hash common.Hash) []*types.Log

		Preimages() map[common.Hash][]byte
		AddPreimage(common.Hash, []byte)

		ForEachStorage(common.Address, func(common.Hash, common.Hash) bool)

		Copy() StateDB
		GetOrNewStateObject(addr common.Address) StateObject

		IntermediateRoot(deleteEmptyObjects bool) common.Hash
		Prepare(thash, bhash common.Hash, ti int)

		Commit(deleteEmptyObjects bool) (root common.Hash, err error)
		Finalize(deleteEmptyObjects bool)

		Error() error
		RawDump() Dump
		Reset(root common.Hash) error
		StorageTrie(addr common.Address) Trie
	}

	// StateDBs within the ethereum protocol are used to store anything
	// within the merkle trie. StateDBs take care of caching and storing
	// nested states. It's the general query interface to retrieve:
	// * Contracts
	// * Accounts
	CommitStateDB struct {
		db   Database
		trie Trie

		// This map holds 'live' objects, which will get modified while processing a state transition.
		stateObjects      map[common.Address]*stateObject
		stateObjectsDirty map[common.Address]struct{}

		// DB error.
		// State objects are used by the consensus core and VM which are
		// unable to deal with database-level errors. Any error that occurs
		// during a database read is memoized here and will eventually be returned
		// by StateDB.Commit.
		dbErr error

		// The refund counter, also used by state transitioning.
		refund uint64

		thash, bhash common.Hash
		txIndex      int
		logs         map[common.Hash][]*types.Log
		logSize      uint

		preimages map[common.Hash][]byte

		// Journal of state modifications. This is the backbone of
		// Snapshot and RevertToSnapshot.
		journal        *journal
		validRevisions []Revision
		nextRevisionId int

		lock sync.Mutex
	}
)

// Create a new state from a given trie.
func New(root common.Hash, db Database) (*CommitStateDB, error) {
	tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	return &CommitStateDB{
		db:                db,
		trie:              tr,
		stateObjects:      make(map[common.Address]*stateObject),
		stateObjectsDirty: make(map[common.Address]struct{}),
		logs:              make(map[common.Hash][]*types.Log),
		preimages:         make(map[common.Hash][]byte),
		journal:           newJournal(),
	}, nil
}

// setError remembers the first non-nil error it is called with.
func (csdb *CommitStateDB) setError(err error) {
	if csdb.dbErr == nil {
		csdb.dbErr = err
	}
}

func (csdb *CommitStateDB) Error() error {
	return csdb.dbErr
}

// Reset clears out all ephemeral state objects from the state db, but keeps
// the underlying state trie to avoid reloading data for the next operations.
func (csdb *CommitStateDB) Reset(root common.Hash) error {
	tr, err := csdb.db.OpenTrie(root)
	if err != nil {
		return err
	}
	csdb.trie = tr
	csdb.stateObjects = make(map[common.Address]*stateObject)
	csdb.stateObjectsDirty = make(map[common.Address]struct{})
	csdb.thash = common.Hash{}
	csdb.bhash = common.Hash{}
	csdb.txIndex = 0
	csdb.logs = make(map[common.Hash][]*types.Log)
	csdb.logSize = 0
	csdb.preimages = make(map[common.Hash][]byte)
	csdb.clearJournalAndRefund()
	return nil
}

func (csdb *CommitStateDB) AddLog(log *types.Log) {
	csdb.journal.append(addLogChange{txhash: csdb.thash})

	log.TxHash = csdb.thash
	log.BlockHash = csdb.bhash
	log.TxIndex = uint(csdb.txIndex)
	log.Index = csdb.logSize
	csdb.logs[csdb.thash] = append(csdb.logs[csdb.thash], log)
	csdb.logSize++
}

func (csdb *CommitStateDB) GetLogs(hash common.Hash) []*types.Log {
	return csdb.logs[hash]
}

func (csdb *CommitStateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range csdb.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (csdb *CommitStateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := csdb.preimages[hash]; !ok {
		csdb.journal.append(addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		csdb.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (csdb *CommitStateDB) Preimages() map[common.Hash][]byte {
	return csdb.preimages
}

// AddRefund adds gas to the refund counter
func (csdb *CommitStateDB) AddRefund(gas uint64) {
	csdb.journal.append(refundChange{prev: csdb.refund})
	csdb.refund += gas
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
func (csdb *CommitStateDB) SubRefund(gas uint64) {
	csdb.journal.append(refundChange{prev: csdb.refund})
	if gas > csdb.refund {
		panic("Refund counter below zero")
	}
	csdb.refund -= gas
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (csdb *CommitStateDB) Exist(addr common.Address) bool {
	return csdb.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (csdb *CommitStateDB) Empty(addr common.Address) bool {
	so := csdb.getStateObject(addr)
	return so == nil || so.empty()
}

// Retrieve the balance from the given address or 0 if object not found
func (csdb *CommitStateDB) GetBalance(addr common.Address) *big.Int {
	stateObject := csdb.getStateObject(addr)

	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (csdb *CommitStateDB) GetNonce(addr common.Address) uint64 {
	stateObject := csdb.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

func (csdb *CommitStateDB) GetCode(addr common.Address) []byte {
	stateObject := csdb.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(csdb.db)
	}
	return nil
}

func (csdb *CommitStateDB) GetCodeSize(addr common.Address) int {
	stateObject := csdb.getStateObject(addr)
	if stateObject == nil {
		return 0
	}
	if stateObject.code != nil {
		return len(stateObject.code)
	}
	size, err := csdb.db.ContractCodeSize(stateObject.addrHash, common.BytesToHash(stateObject.CodeHash()))
	if err != nil {
		csdb.setError(err)
	}
	return size
}

func (csdb *CommitStateDB) GetCodeHash(addr common.Address) common.Hash {
	stateObject := csdb.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

// GetState retrieves a value from the given account's storage trie.
func (csdb *CommitStateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := csdb.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(csdb.db, hash)
	}
	return common.Hash{}
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (csdb *CommitStateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := csdb.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(csdb.db, hash)
	}
	return common.Hash{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (csdb *CommitStateDB) Database() Database {
	return csdb.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (csdb *CommitStateDB) StorageTrie(addr common.Address) Trie {
	stateObject := csdb.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(csdb)
	return cpy.updateTrie(csdb.db)
}

func (csdb *CommitStateDB) HasSuicided(addr common.Address) bool {
	stateObject := csdb.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (csdb *CommitStateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (csdb *CommitStateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (csdb *CommitStateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

func (csdb *CommitStateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (csdb *CommitStateDB) SetCode(addr common.Address, code []byte) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (csdb *CommitStateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := csdb.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(csdb.db, key, value)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (csdb *CommitStateDB) Suicide(addr common.Address) bool {
	stateObject := csdb.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	csdb.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (csdb *CommitStateDB) updateStateObject(stateObject *stateObject) {
	addr := stateObject.Address()
	data, err := rlp.EncodeToBytes(stateObject)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	csdb.setError(csdb.trie.TryUpdate(addr[:], data))
}

// deleteStateObject removes the given object from the state trie.
func (csdb *CommitStateDB) deleteStateObject(stateObject *stateObject) {
	stateObject.deleted = true
	addr := stateObject.Address()
	csdb.setError(csdb.trie.TryDelete(addr[:]))
}

// Retrieve a state object given by the address. Returns nil if not found.
func (csdb *CommitStateDB) getStateObject(addr common.Address) (stateObject *stateObject) {
	// Prefer 'live' objects.
	if obj := csdb.stateObjects[addr]; obj != nil {
		if obj.deleted {
			return nil
		}
		return obj
	}

	// Load the object from the database.
	enc, err := csdb.trie.TryGet(addr[:])
	if len(enc) == 0 {
		csdb.setError(err)
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		log.Error("Failed to decode state object", "addr", addr, "err", err)
		return nil
	}
	// Insert into the live set.
	obj := newObject(csdb, addr, data)
	csdb.setStateObject(obj)
	return obj
}

func (csdb *CommitStateDB) setStateObject(object *stateObject) {
	csdb.stateObjects[object.Address()] = object
}

// Retrieve a state object or create a new state object if nil.
func (csdb *CommitStateDB) GetOrNewStateObject(addr common.Address) StateObject {
	stateObject := csdb.getStateObject(addr)
	if stateObject == nil || stateObject.deleted {
		stateObject, _ = csdb.createObject(addr)
	}

	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (csdb *CommitStateDB) createObject(addr common.Address) (newobj, prev *stateObject) {
	prev = csdb.getStateObject(addr)
	newobj = newObject(csdb, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		csdb.journal.append(createObjectChange{account: &addr})
	} else {
		csdb.journal.append(resetObjectChange{prev: prev})
	}
	csdb.setStateObject(newobj)
	return newobj, prev
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (csdb *CommitStateDB) CreateAccount(addr common.Address) {
	new, prev := csdb.createObject(addr)
	if prev != nil {
		new.setBalance(prev.data.Balance)
	}
}

func (csdb *CommitStateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) {
	so := csdb.getStateObject(addr)
	if so == nil {
		return
	}
	it := trie.NewIterator(so.getTrie(csdb.db).NodeIterator(nil))
	for it.Next() {
		key := common.BytesToHash(csdb.trie.GetKey(it.Key))
		if value, dirty := so.dirtyStorage[key]; dirty {
			cb(key, value)
			continue
		}
		cb(key, common.BytesToHash(it.Value))
	}
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (csdb *CommitStateDB) Copy() StateDB {
	csdb.lock.Lock()
	defer csdb.lock.Unlock()

	// Copy all the basic fields, initialize the memory ones
	state := &CommitStateDB{
		db:                csdb.db,
		trie:              csdb.db.CopyTrie(csdb.trie),
		stateObjects:      make(map[common.Address]*stateObject, len(csdb.journal.dirties)),
		stateObjectsDirty: make(map[common.Address]struct{}, len(csdb.journal.dirties)),
		refund:            csdb.refund,
		logs:              make(map[common.Hash][]*types.Log, len(csdb.logs)),
		logSize:           csdb.logSize,
		preimages:         make(map[common.Hash][]byte),
		journal:           newJournal(),
	}
	// Copy the dirty states, logs, and preimages
	for addr := range csdb.journal.dirties {
		// As documented [here](https://github.com/ethereum/go-ethereum/pull/16485#issuecomment-380438527),
		// and in the Finalise-method, there is a case where an object is in the journal but not
		// in the stateObjects: OOG after touch on ripeMD prior to Byzantium. Thus, we need to check for
		// nil
		if object, exist := csdb.stateObjects[addr]; exist {
			state.stateObjects[addr] = object.deepCopy(state)
			state.stateObjectsDirty[addr] = struct{}{}
		}
	}
	// Above, we don't copy the actual journal. This means that if the copy is copied, the
	// loop above will be a no-op, since the copy's journal is empty.
	// Thus, here we iterate over stateObjects, to enable copies of copies
	for addr := range csdb.stateObjectsDirty {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = csdb.stateObjects[addr].deepCopy(state)
			state.stateObjectsDirty[addr] = struct{}{}
		}
	}
	for hash, logs := range csdb.logs {
		cpy := make([]*types.Log, len(logs))
		for i, l := range logs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		state.logs[hash] = cpy
	}
	for hash, preimage := range csdb.preimages {
		state.preimages[hash] = preimage
	}
	return state
}

// Snapshot returns an identifier for the current revision of the state.
func (csdb *CommitStateDB) Snapshot() int {
	id := csdb.nextRevisionId
	csdb.nextRevisionId++
	csdb.validRevisions = append(csdb.validRevisions, Revision{id, csdb.journal.length()})
	return id
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (csdb *CommitStateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(csdb.validRevisions), func(i int) bool {
		return csdb.validRevisions[i].ID >= revid
	})

	if idx == len(csdb.validRevisions) || csdb.validRevisions[idx].ID != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}

	snapshot := csdb.validRevisions[idx].JournalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	csdb.journal.revert(csdb, snapshot)
	csdb.validRevisions = csdb.validRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
func (csdb *CommitStateDB) GetRefund() uint64 {
	return csdb.refund
}

// Finalize finalizes the state by removing the csdb destructed objects
// and clears the journal as well as the refunds.
func (csdb *CommitStateDB) Finalize(deleteEmptyObjects bool) {
	for addr := range csdb.journal.dirties {
		stateObject, exist := csdb.stateObjects[addr]
		if !exist {
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			continue
		}

		if stateObject.suicided || (deleteEmptyObjects && stateObject.empty()) {
			csdb.deleteStateObject(stateObject)
		} else {
			stateObject.updateRoot(csdb.db)
			csdb.updateStateObject(stateObject)
		}
		csdb.stateObjectsDirty[addr] = struct{}{}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	csdb.clearJournalAndRefund()
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (csdb *CommitStateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	csdb.Finalize(deleteEmptyObjects)
	return csdb.trie.Hash()
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (csdb *CommitStateDB) Prepare(thash, bhash common.Hash, ti int) {
	csdb.thash = thash
	csdb.bhash = bhash
	csdb.txIndex = ti
}

func (csdb *CommitStateDB) clearJournalAndRefund() {
	csdb.journal = newJournal()
	csdb.validRevisions = csdb.validRevisions[:0]
	csdb.refund = 0
}

// Commit writes the state to the underlying in-memory trie database.
func (csdb *CommitStateDB) Commit(deleteEmptyObjects bool) (root common.Hash, err error) {
	defer csdb.clearJournalAndRefund()

	for addr := range csdb.journal.dirties {
		csdb.stateObjectsDirty[addr] = struct{}{}
	}
	// Commit objects to the trie.
	for addr, stateObject := range csdb.stateObjects {
		_, isDirty := csdb.stateObjectsDirty[addr]
		switch {
		case stateObject.suicided || (isDirty && deleteEmptyObjects && stateObject.empty()):
			// If the object has been removed, don't bother syncing it
			// and just mark it for deletion in the trie.
			csdb.deleteStateObject(stateObject)
		case isDirty:
			// Write any contract code associated with the state object
			if stateObject.code != nil && stateObject.dirtyCode {
				csdb.db.TrieDB().InsertBlob(common.BytesToHash(stateObject.CodeHash()), stateObject.code)
				stateObject.dirtyCode = false
			}
			// Write any storage changes in the state object to its storage trie.
			if err := stateObject.CommitTrie(csdb.db); err != nil {
				return common.Hash{}, err
			}
			// Update the object in the main account trie.
			csdb.updateStateObject(stateObject)
		}
		delete(csdb.stateObjectsDirty, addr)
	}
	// Write trie changes.
	root, err = csdb.trie.Commit(func(leaf []byte, parent common.Hash) error {
		var account Account
		if err := rlp.DecodeBytes(leaf, &account); err != nil {
			return nil
		}
		if account.Root != emptyState {
			csdb.db.TrieDB().Reference(account.Root, parent)
		}
		code := common.BytesToHash(account.CodeHash)
		if code != emptyCode {
			csdb.db.TrieDB().Reference(code, parent)
		}
		return nil
	})
	log.Debug("Trie cache stats after commit", "misses", trie.CacheMisses(), "unloads", trie.CacheUnloads())
	return root, err
}
