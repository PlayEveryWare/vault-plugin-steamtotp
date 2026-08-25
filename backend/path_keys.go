package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathKeysHelpSyn  = `Manage Steam Guard shared secrets.`
	pathKeysHelpDesc = `
This path stores Steam Guard shared secrets under a name. Writing accepts the
base32 shared secret, optionally prefixed with "steam://" (the format used by
Bitwarden). Reading returns only metadata; the secret
itself is never returned. Codes are generated from code/<name>.
`
)

func pathKeys(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefix,
				OperationSuffix: "keys",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.keyList,
					Summary:  "List the names of stored Steam Guard keys.",
				},
			},

			HelpSynopsis:    pathKeysHelpSyn,
			HelpDescription: pathKeysHelpDesc,
		},
		{
			Pattern: "keys/" + framework.GenericNameWithAtRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefix,
				OperationSuffix: "key",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key.",
				},
				"key": {
					Type:        framework.TypeString,
					Required:    true,
					Description: `Steam Guard shared secret in base32. An optional "steam://" prefix, whitespace, dashes, and missing "=" padding are accepted.`,
				},
				"account_name": {
					Type:        framework.TypeString,
					Description: "Optional label identifying the Steam account this key belongs to.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.keyWrite,
					Summary:  "Store a Steam Guard shared secret.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.keyWrite,
					Summary:  "Overwrite a Steam Guard shared secret.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.keyRead,
					Summary:  "Read metadata about a stored key. The secret is never returned.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.keyDelete,
					Summary:  "Delete a stored key.",
				},
			},

			ExistenceCheck: b.keyExistenceCheck,

			HelpSynopsis:    pathKeysHelpSyn,
			HelpDescription: pathKeysHelpDesc,
		},
	}
}

func (b *backend) keyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	k, err := getKey(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return k != nil, nil
}

func (b *backend) keyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, keyStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) keyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	rawKey, ok := data.GetOk("key")
	if !ok || rawKey.(string) == "" {
		return logical.ErrorResponse("the key value is required"), nil
	}

	normalized, err := normalizeKey(rawKey.(string))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid key: %s", err)), nil
	}

	k := &keyEntry{
		Key:         normalized,
		AccountName: data.Get("account_name").(string),
	}
	if err := k.write(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) keyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	k, err := getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"account_name": k.AccountName,
		},
	}, nil
}

func (b *backend) keyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, keyStoragePath(name)); err != nil {
		return nil, err
	}
	return nil, nil
}
