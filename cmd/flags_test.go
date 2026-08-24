package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every flag each command marks as required, in one place. cobra records a required
// flag as an annotation on the flag itself, so a MarkFlagRequired call naming a flag
// that does not exist marks nothing - and the returned error used to be discarded
// everywhere, which is how kv-read ended up requiring "kv-keys" while declaring
// "stream-keys". This table fails if a flag is renamed and its requirement silently
// stops applying.
func TestCommandsMarkTheirRequiredFlags(t *testing.T) {
	for _, tc := range []struct {
		cmd      *cobra.Command
		required []string
	}{
		{downloadCmd, []string{"file"}},
		{deployCmd, []string{"url", "key", "bytecode"}},
		{uploadCmd, []string{"url", "key", "file"}},
		{uploadDirCmd, []string{"url", "key", "file"}},
		{extendCmd, []string{"tx"}},
		{kvWriteCmd, []string{"stream-id", "stream-keys", "stream-values", "url", "key"}},
		{kvReadCmd, []string{"stream-id", "stream-keys", "node"}},
	} {
		t.Run(tc.cmd.Name(), func(t *testing.T) {
			for _, name := range tc.required {
				flag := tc.cmd.Flags().Lookup(name)
				require.NotNil(t, flag, "%s: flag %q is marked required but not declared", tc.cmd.Name(), name)

				_, isRequired := flag.Annotations[cobra.BashCompOneRequiredFlag]
				assert.True(t, isRequired, "%s: flag %q must be required", tc.cmd.Name(), name)
			}
		})
	}
}

// kv-read declared --stream-keys and required "kv-keys", so the documented mandatory
// input was never enforced and the command could run with no keys at all.
func TestKvReadCmd_RequiresStreamKeysNotKvKeys(t *testing.T) {
	assert.Nil(t, kvReadCmd.Flags().Lookup("kv-keys"), "no such flag is declared")

	flag := kvReadCmd.Flags().Lookup("stream-keys")
	require.NotNil(t, flag)
	_, isRequired := flag.Annotations[cobra.BashCompOneRequiredFlag]
	assert.True(t, isRequired, "the declared flag is the one that must be required")
}

// upload-dir accepts --indexer through the shared binding but always builds a direct
// uploader, so it used to pass validation and fail later with an empty node list.
func TestValidateUploadDirArgs(t *testing.T) {
	assert.NoError(t, validateUploadDirArgs(&uploadArgument{node: []string{"http://localhost:5678"}}))
	assert.NoError(t, validateUploadDirArgs(&uploadArgument{}))

	err := validateUploadDirArgs(&uploadArgument{indexer: "http://localhost:12345"})
	require.Error(t, err)
	assert.ErrorIs(t, err, errUploadDirIndexerUnsupported)
	assert.Contains(t, err.Error(), "--node", "the message should say what to use instead")
}
