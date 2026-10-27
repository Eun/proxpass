package api

// Tests for the UpdateInstance termproxy version check -- the twin of the
// AddInstance check (addinstance_termproxy_test.go). An edit that switches an
// instance TO termproxy must be rejected when the node does not support it, so
// a node added over ssh because termproxy was incompatible cannot be silently
// flipped back. The checker is injected so no Proxmox node is contacted.

import (
	"context"
	"errors"
	"testing"

	"proxpass/internal/models"
)

// seedSSHInstance adds an ssh-console instance (the checker is not consulted
// for ssh) and returns its id, so an update test has an existing row to edit.
func seedSSHInstance(ctx context.Context, t *testing.T, h *SessionHandler) RowID {
	t.Helper()
	body := addInstanceBody()
	body.ConsoleTransport = ProxmoxInstanceConsoleTransportSSH
	body.SSHHost = testSSHHost
	resp, err := h.AddInstance(ctx, AddInstanceRequestObject{Body: &body})
	if err != nil {
		t.Fatalf("seed AddInstance: %v", err)
	}
	created, ok := resp.(AddInstance201JSONResponse)
	if !ok {
		t.Fatalf("seed AddInstance returned %T, want 201", resp)
	}
	return created.ID
}

// updateBody returns an update body for id with the given transport.
func updateBody(transport ProxmoxInstanceConsoleTransport) UpdateInstanceJSONRequestBody {
	body := addInstanceBody()
	body.ConsoleTransport = transport
	return body
}

// Switching an ssh instance to termproxy on a node that does not support it is
// rejected with a 400, and the stored instance keeps its ssh transport.
func TestUpdateInstanceRejectsUnsupportedTermproxy(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	id := seedSSHInstance(ctx, t, h)

	var sawInst *models.ProxmoxInstance
	h.WithTermProxyChecker(func(_ context.Context, inst *models.ProxmoxInstance) error {
		sawInst = inst
		return errors.New("proxmox VE 9.0.0 does not support the termproxy console transport")
	})

	body := updateBody(ProxmoxInstanceConsoleTransportTermproxy)
	resp, err := h.UpdateInstance(ctx, UpdateInstanceRequestObject{ID: id, Body: &body})
	if err != nil {
		t.Fatalf("UpdateInstance returned a hard error: %v", err)
	}
	bad, ok := resp.(UpdateInstance400JSONResponse)
	if !ok {
		t.Fatalf("UpdateInstance returned %T, want UpdateInstance400JSONResponse", resp)
	}
	if bad.Error == "" {
		t.Error("UpdateInstance 400 carried no error message")
	}
	if sawInst == nil || sawInst.ConsoleTransport != models.ConsoleTransportTermProxy {
		t.Errorf("checker got %+v, want a termproxy instance", sawInst)
	}

	// The stored instance must be untouched -- still ssh.
	got, err := h.GetInstance(ctx, GetInstanceRequestObject{ID: id})
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	ok2, is := got.(GetInstance200JSONResponse)
	if !is {
		t.Fatalf("GetInstance returned %T, want 200", got)
	}
	if ok2.ConsoleTransport != ProxmoxInstanceConsoleTransportSSH {
		t.Errorf("after a rejected update the transport is %q, want ssh", ok2.ConsoleTransport)
	}
}

// A supported termproxy update (checker passes) is stored and returns 200.
func TestUpdateInstanceAcceptsSupportedTermproxy(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	id := seedSSHInstance(ctx, t, h)

	h.WithTermProxyChecker(func(context.Context, *models.ProxmoxInstance) error {
		return nil // node supports termproxy
	})

	body := updateBody(ProxmoxInstanceConsoleTransportTermproxy)
	resp, err := h.UpdateInstance(ctx, UpdateInstanceRequestObject{ID: id, Body: &body})
	if err != nil {
		t.Fatalf("UpdateInstance: %v", err)
	}
	okResp, is := resp.(UpdateInstance200JSONResponse)
	if !is {
		t.Fatalf("UpdateInstance returned %T, want 200", resp)
	}
	if okResp.ConsoleTransport != ProxmoxInstanceConsoleTransportTermproxy {
		t.Errorf("updated transport = %q, want termproxy", okResp.ConsoleTransport)
	}
}

// The check applies only to termproxy: updating to an ssh transport never
// consults the checker, even one that would fail.
func TestUpdateInstanceSkipsTermproxyCheckForSSH(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	id := seedSSHInstance(ctx, t, h)

	h.WithTermProxyChecker(func(context.Context, *models.ProxmoxInstance) error {
		t.Error("termProxyChecker must not run for the ssh console transport")
		return errors.New("should not be called")
	})

	body := updateBody(ProxmoxInstanceConsoleTransportSSH)
	body.SSHHost = testSSHHost
	resp, err := h.UpdateInstance(ctx, UpdateInstanceRequestObject{ID: id, Body: &body})
	if err != nil {
		t.Fatalf("UpdateInstance: %v", err)
	}
	if _, ok := resp.(UpdateInstance200JSONResponse); !ok {
		t.Fatalf("UpdateInstance returned %T, want 200 for an ssh node", resp)
	}
}
