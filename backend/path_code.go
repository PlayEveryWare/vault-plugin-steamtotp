package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathCodeHelpSyn  = `Generate the current Steam Guard code for a key.`
	pathCodeHelpDesc = `
This path generates the 5-character Steam Guard code for the named key using
the Vault server's clock. Along with the current code it returns the number of
seconds the code remains valid (expires_in), the unix time at which it expires
(valid_until), and the code for the following period (next_code) so callers
near a window boundary can choose which to use.
`
)

func pathCode(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "code/" + framework.GenericNameWithAtRegex("name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefix,
				OperationSuffix: "code",
			},

			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.codeRead,
					Summary:  "Generate the current and next Steam Guard codes.",
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "generate",
					},
				},
			},

			HelpSynopsis:    pathCodeHelpSyn,
			HelpDescription: pathCodeHelpDesc,
		},
	}
}

func (b *backend) codeRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	k, err := getKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown key: %s", name)), nil
	}

	secret, err := decodeKey(k.Key)
	if err != nil {
		return nil, fmt.Errorf("stored key for %q is corrupt: %w", name, err)
	}

	now := b.now()
	counter := steamCounter(now)
	validUntil := int64(counter+1) * steamPeriod

	return &logical.Response{
		Data: map[string]interface{}{
			"code":        steamCodeForCounter(secret, counter),
			"next_code":   steamCodeForCounter(secret, counter+1),
			"expires_in":  validUntil - now.Unix(),
			"valid_until": validUntil,
			"period":      steamPeriod,
		},
	}, nil
}
