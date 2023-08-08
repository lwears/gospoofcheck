package shared

import "errors"

// InvalidDomainError indicates that the domain name is invalid
var InvalidDomainError = errors.New("invalid domain name")

// InvalidResponseError indicates that the response is invalid
var InvalidResponseError = errors.New("invalid response status code returned by the server")
