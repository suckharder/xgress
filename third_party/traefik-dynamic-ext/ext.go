// Package ext is a vendored copy of Traefik's internal
// github.com/traefik/traefik/dynamic/ext module.
//
// Traefik's go.mod replaces that module path with a local directory inside its
// own repository, so when we import github.com/traefik/traefik/v3/pkg/config/dynamic
// as a library the replace does not propagate to us. We mirror the (trivial)
// package here and add an equivalent `replace` directive in our root go.mod.
//
// Source: https://github.com/traefik/traefik/blob/v3.7.5/pkg/config/dynamic/ext/ext.go
package ext

// HTTP is a dynamic.HTTP extension.
type HTTP struct{}

// Router is a dynamic.Router extension.
type Router struct{}
