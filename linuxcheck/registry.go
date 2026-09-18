// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"

	"github.com/visvasity/hostcheck/report"
)

// boundCollector is a type-erased collector bound to the Report section field it
// populates. Erasing the payload type here lets a single registry hold
// collectors for heterogeneous section types while each collector's own code
// stays fully typed.
type boundCollector struct {
	key      string
	commands []Command
	// collect runs the collector and stores the resulting section in out.
	collect func(ctx context.Context, env *Env, out *report.Report)
	// setStatus stores a data-less section carrying the given status in out,
	// without running the collector (used for disabled/not-applicable modules).
	setStatus func(out *report.Report, s report.Status)
}

// bind associates a typed collector with the Report field it populates. sel
// returns a pointer to that field, keeping the placement type-safe.
func bind[T any](c Collector[T], sel func(*report.Report) *report.Section[T]) boundCollector {
	return boundCollector{
		key:      c.Key(),
		commands: c.Commands(),
		collect: func(ctx context.Context, env *Env, out *report.Report) {
			*sel(out) = c.Collect(ctx, env)
		},
		setStatus: func(out *report.Report, s report.Status) {
			*sel(out) = report.Section[T]{Status: s}
		},
	}
}

// Registry is an ordered set of collectors, each bound to its Report section
// field and keyed by module key. It is the agent's capability set: the modules
// it knows how to collect. Different agent builds may register different sets.
type Registry struct {
	order []boundCollector
	byKey map[string]int
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byKey: make(map[string]int)}
}

// Register adds a typed collector to the registry, bound to the Report field
// returned by sel. It panics if the collector's key is unknown to the catalog or
// already registered — both are programmer errors caught at startup.
func Register[T any](r *Registry, c Collector[T], sel func(*report.Report) *report.Section[T]) {
	key := c.Key()
	if _, ok := report.Lookup(key); !ok {
		panic("linuxcheck: collector key not in catalog: " + key)
	}
	if _, dup := r.byKey[key]; dup {
		panic("linuxcheck: duplicate collector key: " + key)
	}
	r.byKey[key] = len(r.order)
	r.order = append(r.order, bind(c, sel))
}

// Keys returns the registered module keys in registration order.
func (r *Registry) Keys() []string {
	keys := make([]string, len(r.order))
	for i, b := range r.order {
		keys[i] = b.key
	}
	return keys
}

// Has reports whether a collector is registered for the given module key.
func (r *Registry) Has(key string) bool {
	_, ok := r.byKey[key]
	return ok
}

// get returns the bound collector for a key.
func (r *Registry) get(key string) (boundCollector, bool) {
	i, ok := r.byKey[key]
	if !ok {
		return boundCollector{}, false
	}
	return r.order[i], true
}

// Commands returns the commands declared by the collector for key, and whether
// such a collector is registered. This backs the transparency/--explain view.
func (r *Registry) Commands(key string) ([]Command, bool) {
	i, ok := r.byKey[key]
	if !ok {
		return nil, false
	}
	return r.order[i].commands, true
}
