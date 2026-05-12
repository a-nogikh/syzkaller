package aidb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppendUnique(t *testing.T) {
	res := make(map[string]any)

	appendUnique(res, "key", "val1")
	require.Equal(t, map[string]any{"key": []any{"val1"}}, res)

	appendUnique(res, "key", "val2")
	require.Equal(t, map[string]any{"key": []any{"val1", "val2"}}, res)

	appendUnique(res, "key", "val1")
	require.Equal(t, map[string]any{"key": []any{"val1", "val2"}}, res)

	appendUnique(res, "key", "")
	require.Equal(t, map[string]any{"key": []any{"val1", "val2"}}, res)
}
