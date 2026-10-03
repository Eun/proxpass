package console

import (
	"testing"

	"proxpass/internal/models"
)

// testEndpoint stands in for a deployment's public hostname.
const testEndpoint = "proxpass.example.com"

func TestBarLabel(t *testing.T) {
	guest := func(name string, typ models.GuestType, id int) *models.Guest {
		return &models.Guest{Name: name, Type: typ, ProxmoxID: id}
	}
	inst := func(name string) *models.ProxmoxInstance {
		return &models.ProxmoxInstance{Name: name}
	}

	for _, tc := range []struct {
		name     string
		guest    *models.Guest
		inst     *models.ProxmoxInstance
		endpoint string
		want     string
	}{
		{
			// The documented shape: it reads like the login form a client
			// would type to reach the same guest.
			name:     "with a public endpoint",
			guest:    guest("container1", models.GuestTypeCT, 100),
			inst:     inst("rome"),
			endpoint: testEndpoint,
			want:     "container1@rome@" + testEndpoint + " (ct100)",
		},
		{
			// Nothing announces the endpoint when the deployment has not
			// been told what it is; the qualifier is dropped, not left
			// dangling as a trailing "@".
			name:  "without a public endpoint",
			guest: guest("container1", models.GuestTypeCT, 100),
			inst:  inst("rome"),
			want:  "container1@rome (ct100)",
		},
		{
			name:     "a VM, not a container",
			guest:    guest("builder", models.GuestTypeVM, 204),
			inst:     inst("rome"),
			endpoint: testEndpoint,
			want:     "builder@rome@" + testEndpoint + " (vm204)",
		},
		{
			// A guest name may contain "@" -- names come from Proxmox and
			// are never validated -- so the label is not re-parseable and
			// does not pretend to be. It is still unambiguous because the
			// id in parentheses is.
			name:     "a guest name containing an at sign",
			guest:    guest("mail@relay", models.GuestTypeCT, 101),
			inst:     inst("rome"),
			endpoint: testEndpoint,
			want:     "mail@relay@rome@" + testEndpoint + " (ct101)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := barLabel(tc.guest, tc.inst, tc.endpoint); got != tc.want {
				t.Errorf("barLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The endpoint is carried on the proxier rather than passed per connection,
// so a deployment that has one shows it on every guest it reaches.
func TestDefaultProxierCarriesTheEndpointIntoTheLabel(t *testing.T) {
	p := DefaultProxier{PublicEndpoint: testEndpoint}
	got := barLabel(
		&models.Guest{Name: "container1", Type: models.GuestTypeCT, ProxmoxID: 100},
		&models.ProxmoxInstance{Name: "rome"},
		p.PublicEndpoint)
	const want = "container1@rome@" + testEndpoint + " (ct100)"
	if got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
}
