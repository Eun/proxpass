package api

import "testing"

// GetVersion returns the configured version to an admin.
func TestGetVersionHandler(t *testing.T) {
	h, _, ctx := newAdminHandler(t)
	h.WithVersion("v1.2.3")

	resp, err := h.GetVersion(ctx, GetVersionRequestObject{})
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	v, ok := resp.(GetVersion200JSONResponse)
	if !ok {
		t.Fatalf("GetVersion returned %T, want 200", resp)
	}
	if v.Version != "v1.2.3" {
		t.Fatalf("GetVersion = %q, want v1.2.3", v.Version)
	}
}

// With no version wired, GetVersion still answers (with "dev") rather than
// an empty string.
func TestGetVersionDefaultsToDev(t *testing.T) {
	h, _, ctx := newAdminHandler(t)

	resp, err := h.GetVersion(ctx, GetVersionRequestObject{})
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	v, ok := resp.(GetVersion200JSONResponse)
	if !ok {
		t.Fatalf("GetVersion returned %T, want 200", resp)
	}
	if v.Version != "dev" {
		t.Fatalf("GetVersion with no version = %q, want dev", v.Version)
	}
}

// A non-admin credential is refused.
func TestGetVersionRequiresAdmin(t *testing.T) {
	h, repo, _ := newAdminHandler(t)
	ctx := clientCtx(t, repo)

	resp, err := h.GetVersion(ctx, GetVersionRequestObject{})
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if _, ok := resp.(GetVersion403JSONResponse); !ok {
		t.Fatalf("GetVersion(non-admin) returned %T, want 403", resp)
	}
}
