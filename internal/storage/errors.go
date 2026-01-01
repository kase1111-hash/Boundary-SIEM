// Package storage provides ClickHouse storage for SIEM events.
package storage

import (
	"errors"
	"fmt"
)

// Storage error types for categorizing storage failures.
var (
	// ErrConnectionFailed indicates a failure to connect to the database.
	ErrConnectionFailed = errors.New("storage: connection failed")

	// ErrQueryFailed indicates a query execution failure.
	ErrQueryFailed = errors.New("storage: query failed")

	// ErrBatchInsertFailed indicates a batch insert failure.
	ErrBatchInsertFailed = errors.New("storage: batch insert failed")

	// ErrNotFound indicates the requested record was not found.
	ErrNotFound = errors.New("storage: not found")

	// ErrTimeout indicates an operation timeout.
	ErrTimeout = errors.New("storage: operation timeout")

	// ErrInvalidData indicates invalid data was provided.
	ErrInvalidData = errors.New("storage: invalid data")

	// ErrDatabaseClosed indicates the database connection is closed.
	ErrDatabaseClosed = errors.New("storage: database connection closed")
)

// StorageError wraps storage errors with additional context.
type StorageError struct {
	Op      string // Operation that failed (e.g., "Insert", "Query", "Connect")
	Table   string // Table involved, if applicable
	Err     error  // Underlying error
	Retries int    // Number of retries attempted, if applicable
}

// Error returns the error message.
func (e *StorageError) Error() string {
	if e.Table != "" {
		return fmt.Sprintf("storage.%s(%s): %v", e.Op, e.Table, e.Err)
	}
	return fmt.Sprintf("storage.%s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError creates a new StorageError.
func NewStorageError(op, table string, err error) *StorageError {
	return &StorageError{
		Op:    op,
		Table: table,
		Err:   err,
	}
}

// NewStorageErrorWithRetries creates a StorageError that includes retry count.
func NewStorageErrorWithRetries(op, table string, err error, retries int) *StorageError {
	return &StorageError{
		Op:      op,
		Table:   table,
		Err:     err,
		Retries: retries,
	}
}

// IsConnectionError checks if the error is a connection error.
func IsConnectionError(err error) bool {
	return errors.Is(err, ErrConnectionFailed)
}

// IsQueryError checks if the error is a query error.
func IsQueryError(err error) bool {
	return errors.Is(err, ErrQueryFailed)
}

// IsNotFound checks if the error is a not found error.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsTimeout checks if the error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsRetryable checks if the error is retryable (connection or timeout).
func IsRetryable(err error) bool {
	return IsConnectionError(err) || IsTimeout(err)
}

// WrapConnectionError wraps an error as a connection error.
func WrapConnectionError(op string, err error) error {
	return &StorageError{
		Op:  op,
		Err: fmt.Errorf("%w: %v", ErrConnectionFailed, err),
	}
}

// WrapQueryError wraps an error as a query error.
func WrapQueryError(op, table string, err error) error {
	return &StorageError{
		Op:    op,
		Table: table,
		Err:   fmt.Errorf("%w: %v", ErrQueryFailed, err),
	}
}

// WrapNotFoundError wraps an error as a not found error.
func WrapNotFoundError(op, table, id string) error {
	return &StorageError{
		Op:    op,
		Table: table,
		Err:   fmt.Errorf("%w: id=%s", ErrNotFound, id),
	}
}
