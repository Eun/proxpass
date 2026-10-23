# Client connections

## Client Connections

**Your key identifies you — the login name does not matter.** proxpass looks
up the key that authenticated and resolves it to a client (or to the
administrator); the name before the `@` is ignored. So all of these are the
same client:

```bash
ssh -p 2222 proxpass-host           # whatever your local username is
ssh -p 2222 alice@proxpass-host     # your client name
ssh -p 2222 anything@proxpass-host  # any name at all
```

A key that matches no client and no admin key is refused outright: proxpass
never falls back to trusting the name.

There are two ways to name a guest: as the **login name**, or through
**`guest connect`**. With neither you get the interactive picker.

> **The login name decides where a command runs.** `ssh ct100@host whoami`
> runs `whoami` *inside* ct100, because the login name addresses that
> container. proxpass's own CLI stays reachable under any name that is not a
> guest, and under `admin` whatever happens — so `ssh admin@host guest ls` is
> always the CLI. `admin` is the only name reserved that way: if a guest is
> called `alice`, then `ssh alice@host guest ls` runs in *that guest*.

```bash
# Interactive picker
ssh -p 2222 alice@proxpass-host

# As the login name (no -t needed)
ssh -p 2222 ct100@proxpass-host
ssh -p 2222 100@proxpass-host
ssh -p 2222 webserver@proxpass-host
ssh -p 2222 ct101@rome@proxpass-host     # instance-qualified

# Through the CLI (a PTY is required)
ssh -t -p 2222 alice@proxpass-host guest connect ct100
ssh -t -p 2222 alice@proxpass-host guest connect ct101@rome

# Run a command IN the guest, like any other ssh
ssh -p 2222 ct100@proxpass-host whoami
ssh -p 2222 ct100@proxpass-host cat /etc/os-release
ssh -t -p 2222 ct100@proxpass-host top     # -t for anything interactive

# And to see what you may reach
ssh -p 2222 alice@proxpass-host guest ls
```

`guest ls` and `guest connect` are available to clients as well as
administrators, and both are scoped to the guests your key grants access to.

> **A bare guest identifier as the command — `ssh host ct100` — is no longer
> accepted.** A single token had to be guessed at (a guest, or a mistyped
> command?), and the guess was observable: `ssh host bogus` said "unknown
> command" while `ssh host ct999` reported a resolution failure. Use
> `guest connect ct100` or the login-name form.

### Guest name as the login name

A guest identifier also works as the **login name**, which is shorter to
type and needs no `-t`:

```bash
ssh -p 2222 ct100@proxpass-host        # same as: ssh -t … alice@host ct100
ssh -p 2222 100@proxpass-host
ssh -p 2222 webserver@proxpass-host
```

A name that matches no guest is just a login name, so `ssh admin@host` and
`ssh alice@host` still open the picker.

Three limitations follow from it being a login name rather than an argument:

- **Only guests you may already reach.** The name is resolved against the
  guests your key grants access to, so it is a shortcut, never a way in. A
  guest that exists but is not yours is treated exactly like one that does
  not exist — you get the picker, not an error — so the login name cannot be
  used to probe for machines.
- **`admin` always means "browse".** It opens the picker even if a guest
  shares the name, since guest names come from Proxmox and proxpass does not
  control them — so there is always a way back to the list. It is the only
  reserved name: a client called `web` does not stop `ssh web@host` from
  reaching the container called `web`. That costs the client nothing,
  because the login name is not a credential — identity comes from the key,
  so she can browse under `admin` and still be herself.
- **Instance-qualified names work here too.** `ssh ct101@rome@proxpass-host`
  selects ct101 on `rome`. ssh splits `user@host` on the last `@`, so the
  username arrives as `ct101@rome`; proxpass then splits that on its own
  last `@`, treating the suffix as an instance only when one really has
  that name. A guest whose name itself contains `@` therefore still works,
  and a client named `tobias@corp` is not mistaken for a qualified target.
- **Names longer than 256 characters** are rejected, as are names containing
  `/`, `%`, `?`, `#` or a space. Guests named that way remain reachable via
  the argument form and the picker.

Add this to `~/.ssh/config` to avoid typing `-t` every time:

```
Host proxpass-host
    Port 2222
    User alice
    RequestTTY yes
```

### Running one command

Passing a command runs it **in the guest**, like any other `ssh`:

```bash
ssh ct100@proxpass-host ip addr        # the container's interfaces
ssh ct100@proxpass-host hostname       # the container's hostname
```

It sees the same machine an interactive session does — same filesystem,
processes, hostname and **network** — because the command enters every one
of the container's namespaces. The one deliberate difference is the shell:
a command gets a **non-login** `sh -c`, exactly as `sshd` does, so a
profile banner cannot land in the middle of your output. An interactive
session gets a login shell, where that banner is wanted.

> Before v0.0.19 a command entered every namespace **except the network
> one**, so `ip addr` and `ss` reported the *Proxmox node's* interfaces
> while `hostname` in the same command correctly reported the container's.
> Anything that merely opened a socket was also using the node's stack.
> The same release put commands and transfers **into the container's
> cgroup**, so they are bound by its memory and CPU limits; before it,
> `nproc` on a one-CPU container reported the node's full count and a
> runaway command billed its memory to the node.

Two differences from an interactive session remain, both deliberate:

| | |
|---|---|
| **No AppArmor or seccomp** | A command runs unconfined, where `pct enter` applies the container's profile and filter. `nsenter` has no flag for this, and the alternative (`lxc-attach`) decides on its own whether to allocate a terminal — which corrupts binary output and is why it is not used. |
| **No supplementary groups** | `id` reports `groups=0` rather than the container root's full list. This errs safe — the node's groups are dropped, not carried in — but a file readable only through a supplementary group is readable in the console and not over `scp`. |

Environment variables such as `HOME`, `SHELL` and `$HOSTNAME` describe the
*node*, not the container. That matches `pct enter`, which leaks the same
set, so `hostname` and `$HOSTNAME` can disagree in both.

