package utils

import (
	"reflect"
	"strings"

	"github.com/gorilla/schema"
)

var decoder *schema.Decoder
var encoder *schema.Encoder

func decodeScopeSlice(v string) reflect.Value {
	if v == "" {
		return reflect.ValueOf([]Scope{})
	}

	scopes := make([]Scope, 0)
	for _, scope := range strings.Split(strings.Trim(v, " "), " ") {
		scopes = append(scopes, Scope(scope))
	}

	return reflect.ValueOf(scopes)
}

func encodeScopeSlice(v reflect.Value) string {
	if v.Len() == 0 {
		return ""
	}

	scopes := make([]string, v.Len())
	for i := 0; i < v.Len(); i++ {
		scopes[i] = string(v.Index(i).Interface().(Scope))
	}
	return strings.Join(scopes, " ")
}

func NewCustomDecoder() *schema.Decoder {
	if decoder != nil {
		return decoder
	}

	decoder = schema.NewDecoder()

	decoder.RegisterConverter(([]Scope)(nil), decodeScopeSlice)

	return decoder
}

func NewCustomEncoder() *schema.Encoder {
	if encoder != nil {
		return encoder
	}

	encoder = schema.NewEncoder()

	encoder.RegisterEncoder(([]Scope)(nil), encodeScopeSlice)

	return encoder
}
