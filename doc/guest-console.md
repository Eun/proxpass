# The guest console

How a client experiences a guest console: the interactive picker, the status bar, resizing, and leaving a session.

## The picker

Connecting without a command opens an interactive picker over everything you
may reach — guests and Proxmox nodes together:

```
proxpass — available to admin

  ID     NAME ▲            STATUS   HOST
▸ node   pve1              -        pve1
  ct103  merge-with-label  running  pve1
  ct126  mautrix-telegram  running  pve1
  ct118  mautrix-whatsapp  running  pve2

  51 targets · sort: name
  ↑/↓ move · type to filter · ⏎ connect · tab sort · esc clear · ctrl+c quit
```

A node is the row with `node` in the `ID` column; selecting it opens a shell
on the Proxmox host, exactly as `ssh <node>@proxpass` would. Nodes you have
not been granted are not listed, and neither is one with no `--ssh-host`,
since it could not be opened.

Typing filters the list as a fuzzy subsequence match, so `mw` finds
`mautrix-whatsapp` and `118` finds `ct118`. Each of the name, the type+VMID
and the host is matched on its own, and a hit on the name ranks highest —
and because `node` is matched as a node row's id, typing it narrows the list
to the nodes.

### Sorting

**`Tab`** cycles the sort column and **`Shift+Tab`** goes back. The `▲` in
the header marks the active column and the status line names it:

| Column | Order |
| --- | --- |
| `ID` | numeric by VMID, so `ct99` comes before `ct118`; nodes group at the top, having no VMID |
| `NAME` | alphabetical |
| `STATUS` | running first, since those are the ones you can enter; a node ranks with them, being always connectable |
| `HOST` | alphabetical by Proxmox host; a node sorts with the guests that live on it |

`Tab` walks those in the order the header prints them, left to right. The
picker **opens** sorted by `NAME`, which is what you want when scanning a
list of guests, and the first `Tab` starts the walk at `ID` rather than
continuing from where the list happens to rest:

```
name (open) → id → name → status → host → id → ...
```

`Shift+Tab` is the exact inverse, and from a freshly opened picker it starts
at the other end of the cycle, `HOST`.

Tab is used rather than a letter because every printable key goes into the
filter — binding `s` would make it impossible to type a guest called
`staging`.

While a filter is active the list stays ordered by **match relevance**, which
is the point of filtering, and the status line says `sort: best match`.
Pressing `Tab` then still records your choice and applies it as soon as you
clear the filter.

Without a PTY — `ssh host` with input redirected, for instance — the picker
falls back to a plain numbered prompt so scripted use keeps working. That
table shows the same four columns but has no hotkeys.

## The status bar

While you are attached to a guest console, the bottom row shows which guest
you are on and how to leave it:

```
 webserver@pve1 (ct100)                        Ctrl+A X: disconnect
```

The name reads as the login form that reaches the same guest: the guest, then
the instance it runs on. Set [`--public-endpoint`](configuration.md#public-endpoint) and the
hostname your users connect to is appended, so a session names itself in full:

```
 webserver@pve1@proxpass.example.com (ct100)   Ctrl+A X: disconnect
```

proxpass reserves that row with a **scroll region** (`DECSTBM`) and asks the
guest for a PTY one row shorter, so the terminal scrolls the guest's output
natively and never touches the bar. Guest output is forwarded verbatim —
proxpass does not re-render it — and the bar itself is repainted only when
its text changes, at most once per 50 ms.

That matters because of how this used to work: the previous implementation
parsed all guest output through a VT100 emulator and redrew the whole screen
on every write, which measured **26 MB/s** and made watching logs unusable.
The current approach measures **~5 GB/s**, roughly 190× faster, so there is
no longer a throughput reason to turn it off.

When a full-screen application takes over — vim, top, less — the bar detects
the switch to the alternate screen, releases the scroll region and stops
drawing, so the application gets the whole terminal. It comes back when the
application exits.

Taking the row back is the delicate half. Leaving the alternate screen
restores the normal screen's cursor along with its scroll region — that
restore is what returns you to the prompt you ran `vim` from — so the bar has
to reinstate its region without disturbing the position the terminal just put
back. It does that the same way it does on a resize: `DECSC`/`DECRC` around
the `DECSTBM`, in one write.

It also stands aside for a guest that takes the screen's geometry for itself.
An application setting its own scroll region replaces the bar's reservation,
so the bar reinstates it; one setting origin mode (DECOM) makes the bar's row
unaddressable, so the bar stops drawing until the mode is cleared rather than
painting over the guest's bottom line.

The bar also stands aside when the guest saves its cursor. A terminal has only
one slot to save a cursor position in, and terminfo's `sc`/`rc` capabilities
are exactly the sequences the bar uses, so a shell redrawing its line — which
is what an arrow key or Home/End causes — is competing for the same slot. The
bar notices the save and skips its repaint until the guest restores, rather
than overwriting the position the guest is about to return to. An unmatched
save releases the bar after a second, so a guest that saves and never restores
costs a late bar rather than a missing one.

### Resizing

A resize is one of the moments the bar has to touch the guest's cursor,
because `DECSTBM` **moves it**. DEC's own specification requires that — the
VT100 User Guide says of `DECSTBM` "the cursor is placed in the home position", and
the VT510 manual is blunter: "DECSTBM moves the cursor to column 1, line 1 of
the page." Every terminal checked implements it (xterm, VTE, alacritty, kitty,
foot, wezterm, st, Windows Terminal, tmux, GNU screen, iTerm2); none leaves
the cursor alone.

Reinstalling the region after a resize is mandatory rather than tidying up:
terminals discard the scroll region when the window changes size — xterm's
`ScreenResize` calls `resetMargins`, VTE's `set_size` calls
`reset_scrolling_region` — so until proxpass reinstalls it, the bar's row is
not reserved at all. The reinstall is therefore unavoidable, it homes the
cursor, and the bar has to put the cursor back. It does that by bracketing the
region change with `DECSC`/`DECRC` in a single write, skipping the save when
the guest is already holding the slot.

This matters most on a **VM serial console**. A container console is a PTY, so
a resize reaches the guest as `SIGWINCH` and the shell redraws, which hides a
misplaced cursor. A VM serial console is an emulated UART with no window-size
concept: neither transport can deliver the new size, and the guest's geometry
stays frozen for the session. Nothing redraws, so anything done to the cursor
there is permanent — which is why resize bugs showed up on VMs first. If a VM
guest's idea of the screen size matters to you, run `resize` or
`stty rows … cols …` inside it; that is the only way it can learn.

A terminal dragged below four rows gives the row back rather than keeping a
reservation it is too small for, and takes it again when the window grows.

One case is left deliberately unfixed. `DECRC` clamps to the screen rather
than to the scroll region, so a window shrunk past the guest's cursor leaves
that cursor on the bar's row, where the guest writes over the bar until it
positions itself again — a shell does that at its next prompt. The bar keeps
repainting throughout, so it is never lost. Correcting it properly would mean
parsing the guest's output to track the cursor, which is the design this bar
exists to avoid; the previous behavior traded this rare case for moving the
cursor on *every* resize, which was the bug.

Set `PROXPASS_DISABLE_STATUSBAR=1` to turn the bar off; the guest then gets
the full terminal height. The bar also disables itself without a PTY or on a
terminal shorter than four rows.

It is read from the **session's** environment, and sshd builds that from
scratch rather than inheriting the container's, so it has to be sent with the
connection:

```bash
ssh -o SetEnv=PROXPASS_DISABLE_STATUSBAR=1 -p 2222 admin@proxpass-host
```

Or once, in `~/.ssh/config`:

```
Host proxpass-host
    SetEnv PROXPASS_DISABLE_STATUSBAR=1
```

Setting it on the container (`docker run -e …`) has no effect, because sshd
does not pass its own environment to a session. The image's sshd config
accepts this one variable by name; it deliberately does not accept
`PROXPASS_*` as a pattern, since `PROXPASS_ADMIN_KEY` and `PROXPASS_DATA`
also configure the session binary.

## Leaving a guest console

Normally you leave a console the way you would any shell: `exit`, `logout`,
or `Ctrl+D`. When that is not possible — a wedged process, a full-screen
application that has swallowed your keys — press **`Ctrl+A X`** to disconnect.
The sequence is handled by proxpass rather than the guest, so it works even
when the guest has stopped responding. The status bar shows the reminder; when
there is no bar, proxpass prints it once as you connect.

Note that `Ctrl+A` is also start-of-line in most shells and the default
prefix for `screen` and `tmux`. A lone `Ctrl+A` is passed through to the
guest unchanged, so only the two-key sequence disconnects, but if you run
`screen` or `tmux` inside a guest you will be nesting prefixes.

