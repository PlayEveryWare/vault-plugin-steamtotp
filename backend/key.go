package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

const keyStoragePrefix = "key/"

// keyEntry is the stored representation of a Steam shared secret.
type keyEntry struct {
	// Key is the normalized, padded, upper-case base32 shared secret.
	Key string `json:"key"`
	// AccountName is an optional label identifying the Steam account.
	AccountName string `json:"account_name"`
}

func keyStoragePath(name string) string {
	return keyStoragePrefix + name
}

// getKey reads a key entry from storage. It returns nil, nil when absent.
func getKey(ctx context.Context, s logical.Storage, name string) (*keyEntry, error) {
	entry, err := s.Get(ctx, keyStoragePath(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var k keyEntry
	if err := entry.DecodeJSON(&k); err != nil {
		return nil, err
	}
	return &k, nil
}

// write persists the key entry to storage under the given name.
func (k *keyEntry) write(ctx context.Context, s logical.Storage, name string) error {
	entry, err := logical.StorageEntryJSON(keyStoragePath(name), k)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
