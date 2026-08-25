package backend

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Expected codes were produced by @playeveryware/totp (D:\pe\build\npm-pew-totp)
// with Date stubbed to the given unix time.
func TestSteamCode_MatchesReferenceImplementation(t *testing.T) {
	cases := []struct {
		key  string
		unix int64
		code string
	}{
		{"steam://JBSWY3DPEHPK3PXP", 59, "2YXGV"},
		{"steam://JBSWY3DPEHPK3PXP", 1111111109, "CWDGV"},
		{"steam://JBSWY3DPEHPK3PXP", 1756134853, "WCHVH"},
		{"STEAM://jbsw y3dp-ehpk 3pxp=", 1756134853, "WCHVH"},
		{"steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1234567890, "VHHQY"},
		{"steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 20000000000, "R5DMB"},
	}

	for _, c := range cases {
		normalized, err := normalizeKey(c.key)
		require.NoError(t, err, c.key)
		secret, err := decodeKey(normalized)
		require.NoError(t, err, c.key)

		assert.Equal(t, c.code, steamCode(secret, time.Unix(c.unix, 0)), "%s @ %d", c.key, c.unix)
	}
}

func TestSteamCode_StableWithinPeriod(t *testing.T) {
	secret, _ := decodeKey("JBSWY3DPEHPK3PXP")
	start := time.Unix(1756134840, 0) // multiple of 30

	first := steamCode(secret, start)
	for i := int64(1); i < steamPeriod; i++ {
		assert.Equal(t, first, steamCode(secret, start.Add(time.Duration(i)*time.Second)))
	}
	assert.NotEqual(t, first, steamCode(secret, start.Add(steamPeriod*time.Second)))
}

func TestSteamCode_OnlyUsesAlphabet(t *testing.T) {
	secret, _ := decodeKey("JBSWY3DPEHPK3PXP")
	for i := int64(0); i < 500; i++ {
		code := steamCode(secret, time.Unix(i*steamPeriod, 0))
		require.Len(t, code, steamCodeLength)
		for _, ch := range code {
			assert.Contains(t, steamAlphabet, string(ch))
		}
	}
}

func TestNormalizeKey_Prefix(t *testing.T) {
	n, err := normalizeKey("steam://JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", n)

	n, err = normalizeKey("STEAM://JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", n)

	n, err = normalizeKey("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", n)
}

func TestNormalizeKey_SeparatorsCaseAndPadding(t *testing.T) {
	n, err := normalizeKey("  jbsw y3dp-ehpk_3pxp  ")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", n)

	// 10 chars needs padding to 16
	n, err = normalizeKey("JBSWY3DPEH")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEH======", n)

	// already padded
	n, err = normalizeKey("JBSWY3DPEH======")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEH======", n)
}

func TestNormalizeKey_Invalid(t *testing.T) {
	_, err := normalizeKey("")
	assert.Error(t, err)

	_, err = normalizeKey("steam://")
	assert.Error(t, err)

	_, err = normalizeKey("steam://JBSWY3DP1HPK3PXP") // '1' is not base32
	assert.Error(t, err)

	_, err = normalizeKey("JBSWY3DP!HPK3PXP")
	assert.Error(t, err)

	_, err = normalizeKey("A") // padded to "A=======" which is an invalid base32 quantum
	assert.Error(t, err)
}
