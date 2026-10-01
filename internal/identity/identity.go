// Package identity carries the authenticated caller of an HTTP request from
// the authentication middleware to the handlers that record who acted (for
// example the acknowledged_by and resolved_by of an alert).
package identity

import (
	"context"
	"strconv"
)

type callerKey struct{}

// WithCaller returns a context carrying caller, the authenticated identity
// that made the request.
func WithCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

// Caller returns the caller stored by WithCaller.
func Caller(ctx context.Context) (string, bool) {
	caller, ok := ctx.Value(callerKey{}).(string)
	return caller, ok && caller != ""
}

// APIKeyCaller names the API key at index i (from 0) of auth.api_keys:
// "api-key-1" for the first. (SIEM_API_KEY is appended to the list.) The
// name says which configured key made a request without revealing anything
// about the key itself.
func APIKeyCaller(i int) string {
	return "api-key-" + strconv.Itoa(i+1)
}
