package helpers

import (
	"context"
	"net/http"
	"slices"

	"github.com/saschazar21/go-oidc-provider/utils"
)

type authenticationPolicyKey struct{}

type authenticationPolicy struct {
	methods []utils.AMR
}

// WithAuthenticationPolicy requires trusted evidence of every configured method.
// An explicitly empty policy fails closed; an absent policy retains legacy behavior.
// The caller's slice is copied so later changes cannot weaken an in-flight request.
func WithAuthenticationPolicy(r *http.Request, methods []utils.AMR) *http.Request {
	policy := authenticationPolicy{methods: slices.Clone(methods)}
	return r.WithContext(context.WithValue(r.Context(), authenticationPolicyKey{}, policy))
}

// AuthenticationMethodsSatisfied checks evidence, never inferring methods from
// account state, client claims, or the currently configured login flow.
func AuthenticationMethodsSatisfied(ctx context.Context, methods *[]utils.AMR) bool {
	policy, configured := ctx.Value(authenticationPolicyKey{}).(authenticationPolicy)
	if !configured {
		return true
	}
	if len(policy.methods) == 0 || methods == nil {
		return false
	}
	for _, required := range policy.methods {
		if required == "" || !slices.Contains(*methods, required) {
			return false
		}
	}
	return true
}

// Keep the helper's explicit context (and cancellation) while honoring policy
// attached to the HTTP request, even when callers pass a separate DB context.
func authenticationPolicyContext(ctx context.Context, r *http.Request) context.Context {
	if policy, ok := r.Context().Value(authenticationPolicyKey{}).(authenticationPolicy); ok {
		return context.WithValue(ctx, authenticationPolicyKey{}, policy)
	}
	return ctx
}

func copyAuthenticationMethods(methods *[]utils.AMR) *[]utils.AMR {
	if methods == nil {
		return nil
	}
	copy := slices.Clone(*methods)
	return &copy
}
