// internal/httpvalidator/validator.go
package httpvalidator

import "github.com/go-playground/validator/v10"

type Validator struct {
	v *validator.Validate
}

func New() *Validator {
	return &Validator{v: validator.New()}
}

func (cv *Validator) Validate(i interface{}) error {
	return cv.v.Struct(i)
}
