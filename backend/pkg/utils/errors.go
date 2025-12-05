package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// APIError represents a structured API error response
type APIError struct {
	Error       string       `json:"error"`
	Message     string       `json:"message,omitempty"`
	Code        string       `json:"code,omitempty"`
	Status      int          `json:"status,omitempty"`
	Details     interface{}  `json:"details,omitempty"`
	FieldErrors []FieldError `json:"field_errors,omitempty"`
}

// FieldError represents validation errors for specific fields
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// ErrorResponse represents the complete error response structure
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   APIError    `json:"error"`
	Request RequestInfo `json:"request,omitempty"`
}

// RequestInfo contains information about the request that caused the error
type RequestInfo struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Params  string `json:"params,omitempty"`
	Headers string `json:"headers,omitempty"`
}

// Common error codes
const (
	ErrorCodeInvalidRequest   = "invalid_request"
	ErrorCodeValidationFailed = "validation_failed"
	ErrorCodeUnauthorized     = "unauthorized"
	ErrorCodeForbidden        = "forbidden"
	ErrorCodeNotFound         = "not_found"
	ErrorCodeConflict         = "conflict"
	ErrorCodeRateLimited      = "rate_limited"
	ErrorCodeInternalError    = "internal_error"
	ErrorCodeInvalidJSON      = "invalid_json"
	ErrorCodeMissingField     = "missing_field"
	ErrorCodeInvalidField     = "invalid_field"
)

// Common error messages
var (
	ErrorInvalidJSON = APIError{
		Error:   "Invalid JSON payload",
		Message: "The request body contains invalid JSON",
		Code:    ErrorCodeInvalidJSON,
		Status:  http.StatusBadRequest,
	}

	ErrorMissingRequiredField = APIError{
		Error:   "Missing required field",
		Message: "One or more required fields are missing",
		Code:    ErrorCodeMissingField,
		Status:  http.StatusBadRequest,
	}

	ErrorInvalidFieldValue = APIError{
		Error:   "Invalid field value",
		Message: "One or more fields contain invalid values",
		Code:    ErrorCodeInvalidField,
		Status:  http.StatusBadRequest,
	}

	ErrorUnauthorized = APIError{
		Error:   "Unauthorized",
		Message: "Authentication is required for this endpoint",
		Code:    ErrorCodeUnauthorized,
		Status:  http.StatusUnauthorized,
	}

	ErrorForbidden = APIError{
		Error:   "Forbidden",
		Message: "You don't have permission to access this resource",
		Code:    ErrorCodeForbidden,
		Status:  http.StatusForbidden,
	}

	ErrorNotFound = APIError{
		Error:   "Resource not found",
		Message: "The requested resource was not found",
		Code:    ErrorCodeNotFound,
		Status:  http.StatusNotFound,
	}

	ErrorRateLimited = APIError{
		Error:   "Rate limit exceeded",
		Message: "Too many requests, please try again later",
		Code:    ErrorCodeRateLimited,
		Status:  http.StatusTooManyRequests,
	}

	ErrorInternalServer = APIError{
		Error:   "Internal server error",
		Message: "An unexpected error occurred on the server",
		Code:    ErrorCodeInternalError,
		Status:  http.StatusInternalServerError,
	}
)

// NewAPIError creates a new API error with detailed information
func NewAPIError(message string, code string, status int) APIError {
	return APIError{
		Error:   "api_error",
		Message: message,
		Code:    code,
		Status:  status,
	}
}

// NewValidationError creates a validation error with field-specific details
func NewValidationError(message string, fieldErrors []FieldError) APIError {
	return APIError{
		Error:       "validation_error",
		Message:     message,
		Code:        ErrorCodeValidationFailed,
		Status:      http.StatusBadRequest,
		FieldErrors: fieldErrors,
	}
}

// NewFieldError creates a field-specific validation error
func NewFieldError(field, message, code string) FieldError {
	return FieldError{
		Field:   field,
		Message: message,
		Code:    code,
	}
}

// NewErrorResponse creates a complete error response with request context
func NewErrorResponse(apiError APIError, r *http.Request) ErrorResponse {
	var params, headers string

	// Extract request parameters if available
	if r != nil {
		if r.URL != nil {
			params = r.URL.Query().Encode()
			if params == "" {
				params = "none"
			}
		}

		// Extract relevant headers (excluding sensitive ones)
		safeHeaders := make(http.Header)
		for key := range r.Header {
			if key == "Authorization" || key == "Cookie" || key == "X-Api-Key" {
				safeHeaders.Set(key, "[REDACTED]")
			} else {
				safeHeaders.Set(key, r.Header.Get(key))
			}
		}

		if len(safeHeaders) > 0 {
			headersBytes, _ := json.Marshal(safeHeaders)
			headers = string(headersBytes)
		} else {
			headers = "none"
		}
	}

	requestInfo := RequestInfo{
		Method:  r.Method,
		Path:    r.URL.Path,
		Params:  params,
		Headers: headers,
	}

	return ErrorResponse{
		Success: false,
		Error:   apiError,
		Request: requestInfo,
	}
}

// WriteErrorResponse writes a structured error response
func WriteErrorResponse(w http.ResponseWriter, r *http.Request, apiError APIError) {
	response := NewErrorResponse(apiError, r)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apiError.Status)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Fallback to simple error if JSON encoding fails
		http.Error(w, apiError.Message, apiError.Status)
	}
}

// Common error helpers for specific scenarios
func InvalidJSONError(r *http.Request) APIError {
	return NewAPIError(
		"Invalid JSON payload in request body",
		ErrorCodeInvalidJSON,
		http.StatusBadRequest,
	)
}

func MissingFieldError(field string) APIError {
	return NewAPIError(
		fmt.Sprintf("Missing required field: %s", field),
		ErrorCodeMissingField,
		http.StatusBadRequest,
	)
}

func InvalidFieldError(field, expectedFormat string) APIError {
	return NewAPIError(
		fmt.Sprintf("Invalid value for field '%s'. Expected: %s", field, expectedFormat),
		ErrorCodeInvalidField,
		http.StatusBadRequest,
	)
}

func ValidationError(message string, fieldErrors []FieldError) APIError {
	return NewValidationError(message, fieldErrors)
}

func UnauthorizedError() APIError {
	return ErrorUnauthorized
}

func ForbiddenError() APIError {
	return ErrorForbidden
}

func NotFoundError(resource string) APIError {
	return APIError{
		Error:   "Resource not found",
		Message: fmt.Sprintf("%s not found", resource),
		Code:    ErrorCodeNotFound,
		Status:  http.StatusNotFound,
	}
}

func RateLimitError() APIError {
	return ErrorRateLimited
}

func InternalError(err error) APIError {
	return APIError{
		Error:   "Internal server error",
		Message: "An unexpected error occurred",
		Code:    ErrorCodeInternalError,
		Status:  http.StatusInternalServerError,
		Details: map[string]interface{}{
			"error_id": "err_internal",
			"debug":    err.Error(),
		},
	}
}
