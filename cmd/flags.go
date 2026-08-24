package cmd

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// errUploadDirIndexerUnsupported is returned when upload-dir is given --indexer, which
// it accepts through the shared flag binding but cannot act on.
var errUploadDirIndexerUnsupported = errors.New(
	"upload-dir does not support --indexer; specify storage nodes with --node")

// mustMarkFlagRequired marks flags as required, failing loudly if one does not exist.
//
// cobra returns an error for an unknown flag name and every call site discarded it, so
// a mistyped name silently marked nothing required - which is how kv-read came to
// require a flag called "kv-keys" while declaring "stream-keys". Running at init time,
// a fatal here surfaces the mistake on the next invocation rather than leaving the
// command quietly accepting input it documents as mandatory.
func mustMarkFlagRequired(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"command": cmd.Name(),
				"flag":    name,
			}).Fatal("Failed to mark flag as required")
		}
	}
}

// validateUploadDirArgs rejects flag combinations upload-dir cannot honour.
//
// bindUploadFlags is shared with upload, so upload-dir also accepts --indexer and
// MarkFlagsOneRequired treats it as satisfying the node requirement - but uploadDir
// always builds a direct uploader from --node. An --indexer-only invocation therefore
// passed validation and then failed later with an empty node list, which says nothing
// about the flag being unsupported.
func validateUploadDirArgs(args *uploadArgument) error {
	if args.indexer != "" {
		return errUploadDirIndexerUnsupported
	}

	return nil
}
