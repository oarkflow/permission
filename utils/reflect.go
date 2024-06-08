package utils

import (
	"reflect"
)

func GetFields(v reflect.Value) []any {
	fields := make([]any, 0)
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fields = append(fields, v.Field(i).Interface())
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			fields = append(fields, v.MapIndex(key).Interface())
		}
	}
	return fields
}
