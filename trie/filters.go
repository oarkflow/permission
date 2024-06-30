package trie

func IsNil(value any) bool {
	return value == nil
}

func MatchesFilter(value, filter any) bool {
	return !IsNil(filter) && value == filter
}

func FilterByFields[T DataProps](filter *T, row *T, fields ...func(*T) any) bool {
	for _, field := range fields {
		if IsNil(field(row)) || !MatchesFilter(field(row), field(filter)) {
			return false
		}
	}
	return true
}
