package transit

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathLatestKeyHelpSyn  = ""
	pathLatestKeyHelpDesc = ""
)

func (b *backend) pathRefreshKeyCache() *framework.Path {

	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/refresh-cache",
		Fields: map[string]*framework.FieldSchema{
			"name": {

				Type:        framework.TypeString,
				Description: "Name of the key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.refreshPolicyCache,
		},

		HelpSynopsis:    pathLatestKeyHelpSyn,
		HelpDescription: pathLatestKeyHelpDesc,
	}
}

func (b *backend) refreshPolicyCache(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	_, err := b.pathPolicyRead(ctx, req, d)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, keysutil.ExplicitCacheRefreshCtxKey, true)
	return b.pathPolicyRead(ctx, req, d)
}
