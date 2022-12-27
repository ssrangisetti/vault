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
				Description: "Name of the key to be refreshed",
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
	name := d.Get("name").(string)
	policyReq := keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    name,
	}

	p, _, err := b.GetPolicy(ctx, policyReq, b.GetRandomReader())
	if p == nil {
		return logical.ErrorResponse("policy with id : " + policyReq.Name + " not found"), logical.ErrInvalidRequest
	}
	if err != nil {
		return logical.ErrorResponse("error while getting policy with id : " + policyReq.Name), logical.ErrInvalidRequest
	}

	ctx = keysutil.CacheRefreshContext(ctx, true)
	_, _, err = b.GetPolicy(ctx, policyReq, b.GetRandomReader())

	return nil, err
}
