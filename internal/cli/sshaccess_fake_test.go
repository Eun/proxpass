package cli

import (
	"context"

	"proxpass/internal/models"
)

// fakeSSHKeys is a test SSHKeyService: it returns canned public-key material
// and a canned reachability answer, so the CLI's reporting can be tested
// without a real key file or a live host. The real file read and dial are
// exercised server-side in internal/api.
type fakeSSHKeys struct {
	pub  string
	path string
	err  error // returned by SSHPublicKey
	// reachErr is what CheckInstanceSSHAccess returns (nil = reachable).
	reachErr error
	// lastInst records the instance passed to CheckInstanceSSHAccess.
	lastInst *models.ProxmoxInstance
}

func (f *fakeSSHKeys) SSHPublicKey(context.Context) (pub, path string, err error) {
	return f.pub, f.path, f.err
}

func (f *fakeSSHKeys) CheckInstanceSSHAccess(_ context.Context, inst *models.ProxmoxInstance) error {
	f.lastInst = inst
	return f.reachErr
}
