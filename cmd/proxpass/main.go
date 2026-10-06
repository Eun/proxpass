// Command proxpass is the Proxmox SSH proxy.
//
// It no longer implements an SSH server. OpenSSH's sshd owns the protocol and
// invokes this binary in three roles:
//
//	proxpass serve            long-running: guest discovery + the NSS
//	                          directory API that sshd resolves users through
//	proxpass authorized-keys  sshd AuthorizedKeysCommand
//	proxpass session          sshd ForceCommand, i.e. the user's login shell
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ucli "github.com/urfave/cli/v3"

	"proxpass/internal/api"
	"proxpass/internal/cli"
	"proxpass/internal/console"
	"proxpass/internal/db"
	"proxpass/internal/proxmox"
	"proxpass/internal/session"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmd := &ucli.Command{
		Name:  "proxpass",
		Usage: "Proxmox SSH proxy",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name: "data",
				Usage: "SQLite file path, or a postgres:// URL " +
					"(e.g. postgres://user:pass@host/proxpass?sslmode=disable)",
				Value:   "/var/lib/proxpass/proxpass.db",
				Sources: ucli.EnvVars("PROXPASS_DATA"),
			},
			&ucli.StringFlag{
				Name:    "log-level",
				Usage:   "log level (debug, info, warn, error)",
				Value:   "info",
				Sources: ucli.EnvVars("PROXPASS_LOG_LEVEL"),
			},
			&ucli.StringFlag{
				Name:    "admin-key",
				Usage:   "admin SSH public key (authorized_keys format)",
				Sources: ucli.EnvVars("PROXPASS_ADMIN_KEY"),
			},
			&ucli.StringFlag{
				Name: "public-endpoint",
				Usage: "hostname clients use to reach this proxpass " +
					"(shown in the status bar)",
				Sources: ucli.EnvVars("PROXPASS_PUBLIC_ENDPOINT"),
			},
		},
		Commands: []*ucli.Command{
			serveCommand(),
			authorizedKeysCommand(),
			sessionCommand(),
		},
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := cmd.Run(ctx, os.Args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func serveCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "serve",
		Usage: "run guest discovery and the NSS directory API",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:    "listen",
				Usage:   "address for the NSS directory API",
				Value:   "127.0.0.1:8080",
				Sources: ucli.EnvVars("PROXPASS_LISTEN"),
			},
			&ucli.DurationFlag{
				Name:    "discovery-interval",
				Usage:   "guest discovery poll interval",
				Value:   5 * time.Minute,
				Sources: ucli.EnvVars("PROXPASS_DISCOVERY_INTERVAL"),
			},
		},
		Action: runServe,
	}
}

func runServe(ctx context.Context, cmd *ucli.Command) error {
	listenAddr := cmd.String("listen")
	dataPath := cmd.String("data")
	interval := cmd.Duration("discovery-interval")

	logger := log.New(os.Stdout, "proxpass: ", log.LstdFlags)
	logger.Printf("config: listen=%s data=%s discovery-interval=%s",
		listenAddr, dataPath, interval)

	// Resolve the uid/gid layout before anything else: an invalid one must
	// fail at startup rather than after sshd has accepted a key, where it
	// surfaces as "setresuid ...: Invalid argument".
	ids, err := api.LoadIDLayout(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("id layout: %w", err)
	}
	logger.Printf("id layout: admin uid=%d gid=%d, client gid=%d, uid base=%d, gid base=%d, max=%d",
		ids.AdminUID, ids.AdminGroupGID, ids.SharedGroupGID,
		ids.UIDBase, ids.GIDBase, ids.MaxID)

	repo, err := db.NewRepository(dataPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	// Persist the admin key supplied via --admin-key/PROXPASS_ADMIN_KEY.
	//
	// sshd runs AuthorizedKeysCommand with a scrubbed environment, so that
	// process cannot see PROXPASS_ADMIN_KEY. Storing the key here is what
	// makes it visible to the key lookup; otherwise the admin can never log
	// in and sshd just reports "Failed publickey".
	if err := storeAdminKey(ctx, repo, cmd.String("admin-key"), logger); err != nil {
		return err
	}

	// Same reason as the admin key: a session cannot see this in its
	// environment, so serve writes it down where the session can read it.
	if err := storePublicEndpoint(ctx, repo, cmd.String("public-endpoint"), logger); err != nil {
		return err
	}

	// Guest discovery runs in the background; the directory API blocks.
	discovery := proxmox.NewDiscovery(
		repo, interval, logger, proxmox.DefaultDiscovererFactory)
	go discovery.Run(ctx)

	logger.Printf("serving directory API on %s", listenAddr)
	if err := api.NewServerWithIDs(repo, logger, ids).ListenAndServe(ctx, listenAddr); err != nil {
		return err
	}
	logger.Println("shutting down")
	return nil
}

// exchangeIdentity spends the minted token for a session credential.
//
// Returns a nil client and a nil identity when there is no token or the
// exchange failed, leaving the caller to fall back to the database. The
// error is reported so an operator can see WHY a session fell back: after
// the file permissions are tightened, a client that falls back does not
// work at all, and the reason needs to be in the log.
func exchangeIdentity(
	ctx context.Context, mintedToken string,
) (*session.APIClient, *session.Identity, error) {
	if mintedToken == "" {
		return nil, nil, errors.New(
			"no session token in the environment; is PermitUserEnvironment set?")
	}

	client := session.NewAPIClient(sessionAPIBaseURL)
	id, err := client.Exchange(ctx, mintedToken)
	if err != nil {
		return nil, nil, err
	}
	identity := &session.Identity{
		LoginName:    id.LoginName,
		IdentityName: id.IdentityName,
		IsAdmin:      id.IsAdmin,
	}
	if id.ClientID != nil {
		identity.ClientID = *id.ClientID
	}
	return client, identity, nil
}

// sessionDirectory returns where a session reads from.
//
// Always the API now: no session holds a database handle, so there is one
// implementation rather than a choice between two.
func sessionDirectory(client *session.APIClient) session.Directory {
	return &session.APIDirectory{Client: client}
}

// sessionAPIBaseURL is where the loopback directory listens.
//
// Deliberately a constant and NOT configurable by environment. A session
// sends its credential here and believes what comes back, so anything able
// to change this address could collect the credential and answer with an
// identity and a set of guests of its own choosing.
//
// sshd gives a session a scrubbed environment and the drop-in admits only
// PROXPASS_DISABLE_STATUSBAR and PROXPASS_SESSION_TOKEN, so a client cannot
// set this today -- this is to keep that true if the drop-in ever widens.
// It matches the default of `proxpass serve --listen'; a deployment that
// moves the listener has to change both.
const sessionAPIBaseURL = "http://127.0.0.1:8080"

// storeAdminKey records the startup admin key in the database if it is not
// already present, so that later "authorized-keys" invocations can find it.
func storeAdminKey(ctx context.Context, repo db.Repository, rawKey string, logger *log.Logger) error {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return nil
	}
	// Reject a malformed key at startup rather than silently never
	// authorizing anybody. The validation is strict about being a single
	// entry: a multi-line value here would install several admin
	// credentials, only one of which anybody reviewed.
	rawKey, err := cli.ValidatePublicKey(rawKey)
	if err != nil {
		return fmt.Errorf("invalid --admin-key: %w", err)
	}

	existing, err := repo.ListAdminKeys(ctx)
	if err != nil {
		return fmt.Errorf("listing admin keys: %w", err)
	}
	for _, k := range existing {
		if strings.TrimSpace(k) == rawKey {
			return nil
		}
	}
	if err := repo.AddAdminKey(ctx, rawKey); err != nil {
		return fmt.Errorf("storing admin key: %w", err)
	}
	logger.Println("admin key from configuration stored")
	return nil
}

// storePublicEndpoint records the hostname clients use to reach this proxpass,
// so that a session can show it in the status bar.
//
// A session cannot read this from its environment: sshd builds a fresh one and
// does not inherit the container's, so the value reaches `proxpass serve' and
// nothing else. It is written to the database for the same reason the admin
// key is, and read back from there.
//
// Unlike the admin key it is updated rather than added, because it describes
// the deployment rather than granting anything: changing the compose file and
// restarting should change what sessions display. Clearing it removes the
// stored value, so the status bar stops showing an endpoint that is no longer
// right instead of keeping a stale one forever.
func storePublicEndpoint(ctx context.Context, repo db.Repository, endpoint string, logger *log.Logger) error {
	endpoint = strings.TrimSpace(endpoint)

	current, err := repo.GetSetting(ctx, db.SettingPublicEndpoint)
	if err != nil {
		return fmt.Errorf("reading public endpoint: %w", err)
	}
	if current == endpoint {
		return nil
	}
	if err := repo.SetSetting(ctx, db.SettingPublicEndpoint, endpoint); err != nil {
		return fmt.Errorf("storing public endpoint: %w", err)
	}
	if endpoint == "" {
		logger.Println("public endpoint cleared")
		return nil
	}
	logger.Printf("public endpoint set to %q", endpoint)
	return nil
}

func authorizedKeysCommand() *ucli.Command {
	return &ucli.Command{
		Name:      "authorized-keys",
		Usage:     "print authorized_keys lines for a user (sshd AuthorizedKeysCommand)",
		ArgsUsage: "<username>",
		Action:    runAuthorizedKeys,
	}
}

func runAuthorizedKeys(ctx context.Context, cmd *ucli.Command) error {
	user := cmd.Args().First()
	if user == "" {
		// sshd should always pass a user, but never fail loudly here: any
		// stdout noise would be parsed as a key.
		return nil
	}

	repo, err := db.NewRepository(cmd.String("data"))
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = repo.Close() }()

	return session.WriteAuthorizedKeys(
		ctx, os.Stdout, repo, user, cmd.String("admin-key"))
}

func sessionCommand() *ucli.Command {
	return &ucli.Command{
		Name:  "session",
		Usage: "run a client session (sshd ForceCommand)",
		Flags: []ucli.Flag{
			&ucli.StringFlag{
				Name:    "user",
				Usage:   "login name; defaults to $USER",
				Sources: ucli.EnvVars("USER"),
			},
			&ucli.StringFlag{
				Name:    "command",
				Usage:   "requested command; defaults to $SSH_ORIGINAL_COMMAND",
				Sources: ucli.EnvVars("SSH_ORIGINAL_COMMAND"),
			},
		},
		Action: runSession,
	}
}

func runSession(ctx context.Context, cmd *ucli.Command) error {
	user := cmd.String("user")
	if user == "" {
		return fmt.Errorf("no user; sshd should set $USER")
	}

	// Try the API first, and do NOT open the database to do it.
	//
	// A client session has no read access to the database file any more --
	// that is the whole point of this design -- so opening it here would
	// fail before the session had a chance to work. The exchange also
	// returns the identity, so the usual path needs no database at all.
	//
	// The minted token is spent either way: take it from the environment
	// before anything else, so it is not inherited by anything this
	// process starts.
	mintedToken := session.TakeTokenFromEnv()
	apiClient, identity, apiErr := exchangeIdentity(ctx, mintedToken)
	if apiClient != nil {
		defer func() {
			if err := apiClient.Revoke(context.WithoutCancel(ctx)); err != nil {
				log.Printf("proxpass: revoking the session credential: %v", err)
			}
		}()
	}

	// There is no database fallback. If the exchange did not work this
	// session cannot run.
	//
	// It used to fall back to opening the file and resolving the identity
	// from $SSH_USER_AUTH. That path is gone: the database is 0600 and no
	// session runs as root, so it could not have worked anyway, and
	// $SSH_USER_AUTH is written into the session's own /tmp where the
	// session user can rewrite it -- a forgeable answer to "who are you".
	// The token is the trustworthy one, so it is the only one.
	if identity == nil {
		return fmt.Errorf(
			"could not reach the proxpass API (%w); a session cannot run "+
				"without it -- check that `proxpass serve' is up and that "+
				"sshd sets %s", apiErr, session.TokenEnv)
	}

	// An administrator gets a repository served by the API, not the file.
	//
	// The admin CLI writes, so it needs a full db.Repository -- and it gets
	// one, backed by the loopback API. The commands are untouched: they
	// call the same interface they always did. This is what lets the file
	// be closed to every session, administrator included.
	var repo db.Repository
	if identity.IsAdmin {
		repo = session.NewAdminRepository(apiClient)
	}

	term, restore := currentTerminal()
	defer restore()

	// Sessions log to stderr, which on an interactive login is the user's
	// terminal: stdout carries the guest console. The log writer therefore
	// has to go through UIErr as well, or raw mode turns each log line's
	// newline into a bare LF and the messages staircase across whatever the
	// session is drawing.
	logger := log.New(term.UIErr(), "proxpass: ", log.LstdFlags)

	// Where this session gets its view of the cluster.
	//
	// A client is served by the loopback API and holds NO database handle:
	// the database contains Proxmox API token secrets and instance SSH
	// private keys, and a session that can read them can take over the
	// cluster. An administrator keeps the handle, because the admin CLI
	// writes and the session API is read-only.
	//
	// When the exchange fails the session falls back to the database. That
	// is not a security decision it gets to make -- it is what the session
	// could already do, and the file permissions are what actually stop a
	// client reading it. Logging the reason matters, because after the
	// permissions are tightened a failure here is how an operator finds
	// out something is wrong.
	dir := sessionDirectory(apiClient)
	if apiErr != nil {
		logger.Printf("the session API was not usable (%v); "+
			"reading the database directly", apiErr)
	}

	// The endpoint comes from the directory, not the flag: sshd gives this
	// process a fresh environment, so PROXPASS_PUBLIC_ENDPOINT is never set
	// here. `proxpass serve' recorded it for exactly this reason. A failure
	// to read it must not cost the user their session -- the endpoint is
	// cosmetic -- so it degrades to the shorter label.
	publicEndpoint, err := dir.PublicEndpoint(ctx)
	if err != nil {
		logger.Printf("reading the public endpoint: %v", err)
		publicEndpoint = ""
	}

	code := session.Run(ctx, &session.Deps{
		Dir:          dir,
		Repo:         repo,
		Discoverer:   proxmox.DefaultDiscovererFactory,
		Proxier:      console.DefaultProxier{PublicEndpoint: publicEndpoint},
		Logger:       logger,
		Terminal:     term,
		LoginName:    identity.LoginName,
		IdentityName: identity.IdentityName,
		IsAdmin:      identity.IsAdmin,
		ClientID:     identity.ClientID,
		Command:      cmd.String("command"),
	})
	// The session already reported any problem to the user, so surface the
	// status without printing a second, redundant error. Restore the
	// terminal explicitly first: ucli.Exit unwinds through os.Exit, which
	// would skip the deferred restore.
	if code != 0 {
		restore()
		return ucli.Exit("", code)
	}
	return nil
}
