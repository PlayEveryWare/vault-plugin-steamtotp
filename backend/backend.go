package backend

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	backendHelp = `
The Steam TOTP backend stores Steam Guard shared secrets and generates the
5-character Steam Guard codes derived from them. Secrets are written to
keys/<name> and are never returned; codes are read from code/<name>.
`

	operationPrefix = "steamtotp"
)

var (
	projectVersion string
)

type backend struct {
	*framework.Backend

	// now returns the current time. Tests override it to pin the TOTP window.
	now func() time.Time
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	if conf == nil {
		return nil, errors.New("backend configuration is nil")
	}

	b := new(backend)
	b.now = time.Now

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{keyStoragePrefix},
		},
		Paths: framework.PathAppend(
			pathKeys(b),
			pathCode(b),
		),
		Secrets:        []*framework.Secret{},
		RunningVersion: projectVersion,
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	b.Logger().Info("plugin backend successfully initialized")
	return b, nil
}
