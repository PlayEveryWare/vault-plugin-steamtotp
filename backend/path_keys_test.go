package backend

import (
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeKey(t *testing.T, tb *testBackend, name string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return tb.HandleRequest(t, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/" + name,
		Data:      data,
	})
}

func TestPathKeys_Write_Read_Delete(t *testing.T) {
	tb := createTestBackend(t)

	resp, err := writeKey(t, tb, "pew", map[string]interface{}{
		"key":          "steam://jbsw y3dp-ehpk 3pxp",
		"account_name": "pewbuild",
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), resp.Error())

	// stored form is normalized
	stored, err := getKey(t.Context(), tb.Storage, "pew")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", stored.Key)
	assert.Equal(t, "pewbuild", stored.AccountName)

	// read returns metadata only, never the key
	resp, err = tb.HandleRequest(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/pew",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), resp.Error())
	assert.Equal(t, "pewbuild", resp.Data["account_name"])
	_, hasKey := resp.Data["key"]
	assert.False(t, hasKey)
	for _, v := range resp.Data {
		assert.NotContains(t, v, "JBSWY3DP")
	}

	// delete
	resp, err = tb.HandleRequest(t, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/pew",
	})
	require.NoError(t, err)
	assert.Nil(t, resp)

	resp, err = tb.HandleRequest(t, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/pew",
	})
	require.NoError(t, err)
	assert.Nil(t, resp)
}

// Vault routes a write to a non-existent path as CreateOperation when an
// ExistenceCheck is defined; make sure both create and update are handled.
func TestPathKeys_Create_Then_Update(t *testing.T) {
	tb := createTestBackend(t)

	checkFound, exists, err := tb.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/pew",
		Storage:   tb.Storage,
	})
	require.NoError(t, err)
	assert.True(t, checkFound)
	assert.False(t, exists)

	resp, err := tb.HandleRequest(t, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/pew",
		Data:      map[string]interface{}{"key": "JBSWY3DPEHPK3PXP"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), resp.Error())

	checkFound, exists, err = tb.HandleExistenceCheck(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/pew",
		Storage:   tb.Storage,
	})
	require.NoError(t, err)
	assert.True(t, checkFound)
	assert.True(t, exists)

	resp, err = tb.HandleRequest(t, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keys/pew",
		Data:      map[string]interface{}{"key": "GEZDGNBVGY3TQOJQ"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), resp.Error())
}

func TestPathKeys_Write_Overwrites(t *testing.T) {
	tb := createTestBackend(t)

	_, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "JBSWY3DPEHPK3PXP", "account_name": "a"})
	require.NoError(t, err)

	_, err = writeKey(t, tb, "pew", map[string]interface{}{"key": "GEZDGNBVGY3TQOJQ", "account_name": "b"})
	require.NoError(t, err)

	stored, err := getKey(t.Context(), tb.Storage, "pew")
	require.NoError(t, err)
	assert.Equal(t, "GEZDGNBVGY3TQOJQ", stored.Key)
	assert.Equal(t, "b", stored.AccountName)
}

func TestPathKeys_Write_MissingKey(t *testing.T) {
	tb := createTestBackend(t)

	resp, err := writeKey(t, tb, "pew", map[string]interface{}{"account_name": "x"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "key value is required")
}

func TestPathKeys_Write_InvalidKey(t *testing.T) {
	tb := createTestBackend(t)

	resp, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "steam://not!valid"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "invalid key")

	stored, err := getKey(t.Context(), tb.Storage, "pew")
	require.NoError(t, err)
	assert.Nil(t, stored)
}

func TestPathKeys_Write_StorageError(t *testing.T) {
	tb := createTestBackend(t)
	tb.Storage.PutError = errors.New("boom")

	_, err := writeKey(t, tb, "pew", map[string]interface{}{"key": "JBSWY3DPEHPK3PXP"})
	require.Error(t, err)
}

func TestPathKeys_List(t *testing.T) {
	tb := createTestBackend(t)

	resp, err := tb.HandleRequest(t, &logical.Request{Operation: logical.ListOperation, Path: "keys/"})
	require.NoError(t, err)
	assert.Empty(t, resp.Data["keys"])

	for _, n := range []string{"alpha", "beta", "user@example.com"} {
		_, err := writeKey(t, tb, n, map[string]interface{}{"key": "JBSWY3DPEHPK3PXP"})
		require.NoError(t, err)
	}

	resp, err = tb.HandleRequest(t, &logical.Request{Operation: logical.ListOperation, Path: "keys/"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"alpha", "beta", "user@example.com"}, resp.Data["keys"])
}
