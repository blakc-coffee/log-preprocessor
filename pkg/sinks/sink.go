// Package sinks contains the common contracts and lifecycle errors used by
// ULPF export sinks.
package sinks

import (
	"errors"

	"github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// Sink aliases the frozen cross-workstream sink contract.
type Sink = types.Sink

var (
	// ErrClosed is returned after a sink or dispatcher has been closed.
	ErrClosed = errors.New("sink: closed")
	// ErrSpoolFull indicates that durable buffering reached its configured cap.
	ErrSpoolFull = errors.New("sink: spool full")
)
