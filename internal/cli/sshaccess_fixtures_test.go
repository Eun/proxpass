package cli

// Fixture values shared by the SSH access tests.
const (
	testInstanceName = "pve"
	testLoopback     = "127.0.0.1"
	testSSHUser      = "root"
	// testKeyPath and testPubKey stand in for what the key service resolves:
	// the key's path and a canned authorized_keys line. The real file read
	// and public-key derivation are tested in internal/api.
	testKeyPath = "/var/lib/proxpass/ssh/proxpass_key"
	testPubKey  = "ssh-ed25519 AAAAexamplekey proxpass\n"
)

// Fixture values shared across the CLI tests more widely.
const (
	testRomeURL = "https://rome:8006"
	// flagArgName is "--name" as it appears on a command line, as distinct
	// from flagName which is the flag's declared name.
	flagArgName = "--name"
	// cmdInstance is the "instance" subcommand word, as typed.
	cmdInstance = "instance"
)
