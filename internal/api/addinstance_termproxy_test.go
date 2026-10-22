package api

// Tests for the AddInstance termproxy version check (the server-side twin of
// the CLI's checkTermProxyVersion). They inject a fake termProxyChecker so no
// Proxmox node is contacted; the real checker is wired in server.go.

import (
	"context"
	"errors"
	"testing"

	"proxpass/internal/models"
)

// A termproxy node whose version check fails is rejected with a 400 carrying
// the checker's reason, and nothing is stored.
func TestAddInstanceRejectsUnsupportedTermproxy(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	var sawInst *models.ProxmoxInstance
	h.WithTermProxyChecker(func(_ context.Context, inst *models.ProxmoxInstance) error {
		sawInst = inst
		return errors.New("proxmox VE 9.0.0 does not support the termproxy console transport")
	})

	body := addInstanceBody() // uses the termproxy console transport
	resp, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("AddInstance returned a hard error: %v", err)
	}
	bad, ok := resp.(AddInstance400JSONResponse)
	if !ok {
		t.Fatalf("AddInstance returned %T, want AddInstance400JSONResponse", resp)
	}
	if bad.Error == "" {
		t.Error("AddInstance 400 carried no error message")
	}
	if sawInst == nil || sawInst.APIURL != body.APIURL {
		t.Errorf("checker got instance %+v, want one with APIURL %q", sawInst, body.APIURL)
	}

	// Nothing was stored.
	list, err := h.ListInstances(ctx, ListInstancesRequestObject{})
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	if got, ok := list.(ListInstances200JSONResponse); !ok || len(got) != 0 {
		t.Errorf("after a rejected add, instances = %v, want none", list)
	}
}

// The check applies only to termproxy: an ssh-console node is stored even when
// the checker would fail, because it is never consulted.
func TestAddInstanceSkipsTermproxyCheckForSSH(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	h.WithTermProxyChecker(func(context.Context, *models.ProxmoxInstance) error {
		t.Error("termProxyChecker must not run for the ssh console transport")
		return errors.New("should not be called")
	})

	body := addInstanceBody()
	body.ConsoleTransport = ProxmoxInstanceConsoleTransportSSH
	body.SSHHost = "pve.example"
	resp, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("AddInstance: %v", err)
	}
	if _, ok := resp.(AddInstance201JSONResponse); !ok {
		t.Fatalf("AddInstance returned %T, want 201 for an ssh node", resp)
	}
}
