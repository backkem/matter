package webrtctransport

import "errors"

// Package errors.
var (
	// ErrInvalidTLV is returned when TLV decoding fails.
	ErrInvalidTLV = errors.New("webrtc-transport: invalid TLV")

	// ErrSessionNotFound is returned when a session ID doesn't exist.
	ErrSessionNotFound = errors.New("webrtc-transport: session not found")

	// ErrSessionExists is returned when trying to create a duplicate session.
	ErrSessionExists = errors.New("webrtc-transport: session already exists")

	// ErrUnauthorized is returned when the caller doesn't match the session's peer.
	ErrUnauthorized = errors.New("webrtc-transport: unauthorized")

	// ErrInvalidStreamUsage is returned for unsupported stream usage values.
	ErrInvalidStreamUsage = errors.New("webrtc-transport: invalid stream usage")

	// ErrResourceExhausted is returned when no more sessions can be created.
	ErrResourceExhausted = errors.New("webrtc-transport: resource exhausted")

	// ErrNoDelegate is returned when no delegate is configured.
	ErrNoDelegate = errors.New("webrtc-transport: no delegate configured")
)
