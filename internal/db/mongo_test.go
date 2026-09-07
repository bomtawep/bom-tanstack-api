//go:build integration

package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
)

func TestEnsureIndexes_CreatesUniqueEmailIndex(t *testing.T) {
	ctx := context.Background()

	container, err := tcmongodb.Run(ctx, "mongo:7")
	require.NoError(t, err)
	defer container.Terminate(ctx)

	uri, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	client, err := Connect(ctx, uri)
	require.NoError(t, err)
	defer client.Disconnect(ctx)

	database := client.Database("testdb")
	require.NoError(t, EnsureIndexes(ctx, database))

	cursor, err := database.Collection("users").Indexes().List(ctx)
	require.NoError(t, err)
	var indexes []map[string]interface{}
	require.NoError(t, cursor.All(ctx, &indexes))

	found := false
	for _, idx := range indexes {
		if key, ok := idx["key"].(map[string]interface{}); ok {
			if _, hasEmail := key["email"]; hasEmail {
				found = true
				assert.Equal(t, true, idx["unique"])
			}
		}
	}
	assert.True(t, found, "expected a unique index on users.email")
}
