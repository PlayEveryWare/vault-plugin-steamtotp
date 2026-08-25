package backend

import (
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readCode(t *testing.T, tb *testBackend, name string) (*logical.Response, error) {
	t.Helper()
	return tb.HandleRequest(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "code/" + name,
	})
}

func TestPathCode_Read(t *testing.T) {
	tb := createTestBackend(t)
	// 1756134853 is 13s into the window starting at 1756134840; the window ends at 1756134870.
	tb.now = func() time.Time { return time.Unix(1756134853, 0) }

	_, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "steam://JBSWY3DPEHPK3PXP"})
	require.NoError(t, err)

	resp, err := readCode(t, tb, "pew")
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), resp.Error())

	assert.Equal(t, "WCHVH", resp.Data["code"]) // reference vector from npm-pew-totp
	assert.Equal(t, int64(17), resp.Data["expires_in"])
	assert.Equal(t, int64(1756134870), resp.Data["valid_until"])
	assert.Equal(t, steamPeriod, resp.Data["period"])

	secret, _ := decodeKey("JBSWY3DPEHPK3PXP")
	assert.Equal(t, steamCode(secret, time.Unix(1756134870, 0)), resp.Data["next_code"])
	assert.NotEqual(t, resp.Data["code"], resp.Data["next_code"])

	// the key itself never leaks
	for _, v := range resp.Data {
		if str, ok := v.(string); ok {
			assert.NotContains(t, str, "JBSWY3DP")
		}
	}
}

func TestPathCode_Read_WindowBoundaries(t *testing.T) {
	tb := createTestBackend(t)
	_, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "JBSWY3DPEHPK3PXP"})
	require.NoError(t, err)

	// exactly at the start of a window: full period remains
	tb.now = func() time.Time { return time.Unix(1756134840, 0) }
	resp, err := readCode(t, tb, "pew")
	require.NoError(t, err)
	assert.Equal(t, int64(30), resp.Data["expires_in"])
	startCode := resp.Data["code"]
	startNext := resp.Data["next_code"]

	// last second of the window
	tb.now = func() time.Time { return time.Unix(1756134869, 0) }
	resp, err = readCode(t, tb, "pew")
	require.NoError(t, err)
	assert.Equal(t, int64(1), resp.Data["expires_in"])
	assert.Equal(t, startCode, resp.Data["code"])

	// first second of the next window: previous next_code becomes code
	tb.now = func() time.Time { return time.Unix(1756134870, 0) }
	resp, err = readCode(t, tb, "pew")
	require.NoError(t, err)
	assert.Equal(t, int64(30), resp.Data["expires_in"])
	assert.Equal(t, startNext, resp.Data["code"])
}

func TestPathCode_Read_UnknownKey(t *testing.T) {
	tb := createTestBackend(t)

	resp, err := readCode(t, tb, "nope")
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "unknown key: nope")
}

func TestPathCode_Read_UsesRealClockByDefault(t *testing.T) {
	tb := createTestBackend(t)
	_, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "JBSWY3DPEHPK3PXP"})
	require.NoError(t, err)

	before := time.Now().Unix()
	resp, err := readCode(t, tb, "pew")
	require.NoError(t, err)

	expiresIn := resp.Data["expires_in"].(int64)
	assert.GreaterOrEqual(t, expiresIn, int64(1))
	assert.LessOrEqual(t, expiresIn, int64(steamPeriod))
	assert.GreaterOrEqual(t, resp.Data["valid_until"].(int64), before)
}
