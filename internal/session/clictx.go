package session

import (
	"context"
	"time"
)

// detachValues returns ctx with its cancellation and deadline intact but all
// of its values hidden.
//
// It exists because urfave/cli stores the command it is running in the
// context, and a command tree started with that context adopts the stored
// command as its PARENT. For the admin CLI, which runs nested inside the
// "proxpass session" command, that had two visible consequences:
//
//   - Help and usage errors were written to Root().Writer, which resolves to
//     the OUTER root. That command has no writer, so the text went to
//     os.Stdout directly and bypassed the session's terminal -- and with it
//     the raw-mode CRLF translation, so "ssh host help" staircased.
//   - Usage lines read "proxpass session proxpass [command ...]", because
//     FullName walks the same parent chain.
//
// Hiding the values makes the admin CLI a root command in its own right,
// which fixes both. Cancellation still propagates, so a disconnecting client
// still aborts the command.
func detachValues(ctx context.Context) context.Context {
	return valuelessContext{ctx}
}

type valuelessContext struct{ ctx context.Context }

func (c valuelessContext) Deadline() (time.Time, bool) { return c.ctx.Deadline() }
func (c valuelessContext) Done() <-chan struct{}       { return c.ctx.Done() }
func (c valuelessContext) Err() error                  { return c.ctx.Err() }
func (valuelessContext) Value(any) any                 { return nil }
