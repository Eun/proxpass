package proxmox

import (
	"testing"

	"proxpass/internal/models"
)

func TestParsePctList(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   []*models.Guest
		wantN  int
	}{
		{
			name: "multiple entries",
			input: `VMID       Status     Lock         Name
100        running                 mycontainer
101        stopped                 another`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "mycontainer", Status: models.StatusRunning},
				{Type: models.GuestTypeCT, ProxmoxID: 101, Name: "another", Status: models.StatusStopped},
			},
			wantN: 2,
		},
		{
			name:  "empty output",
			input: "",
			wantN: 0,
		},
		{
			name: "header only",
			input: `VMID       Status     Lock         Name`,
			wantN: 0,
		},
		{
			name: "running and stopped statuses",
			input: `VMID       Status     Lock         Name
100        running                 web
101        stopped                 db
102        running                 cache`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "web", Status: models.StatusRunning},
				{Type: models.GuestTypeCT, ProxmoxID: 101, Name: "db", Status: models.StatusStopped},
				{Type: models.GuestTypeCT, ProxmoxID: 102, Name: "cache", Status: models.StatusRunning},
			},
			wantN: 3,
		},
		{
			name: "malformed lines skipped",
			input: `VMID       Status     Lock         Name
100        running                 ok
badline
ab
200        stopped                 also-ok`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "ok", Status: models.StatusRunning},
				{Type: models.GuestTypeCT, ProxmoxID: 200, Name: "also-ok", Status: models.StatusStopped},
			},
			wantN: 2,
		},
		{
			name: "non-numeric VMID skipped",
			input: `VMID       Status     Lock         Name
abc        running                 bad
100        running                 good`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "good", Status: models.StatusRunning},
			},
			wantN: 1,
		},
		{
			name: "too few fields skipped",
			input: `VMID       Status     Lock         Name
100 running
200        running                 ok`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 200, Name: "ok", Status: models.StatusRunning},
			},
			wantN: 1,
		},
		{
			name: "entry with lock field populated",
			input: `VMID       Status     Lock         Name
100        running    backup       locked-ct`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "locked-ct", Status: models.StatusRunning},
			},
			wantN: 1,
		},
		{
			name: "unknown status normalises to stopped",
			input: `VMID       Status     Lock         Name
100        paused                  mystery`,
			want: []*models.Guest{
				{Type: models.GuestTypeCT, ProxmoxID: 100, Name: "mystery", Status: models.StatusStopped},
			},
			wantN: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePctList(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantN {
				t.Fatalf("got %d guests, want %d", len(got), tc.wantN)
			}
			for i, g := range got {
				w := tc.want[i]
				if g.Type != w.Type {
					t.Errorf("[%d] Type = %q, want %q", i, g.Type, w.Type)
				}
				if g.ProxmoxID != w.ProxmoxID {
					t.Errorf("[%d] ProxmoxID = %d, want %d", i, g.ProxmoxID, w.ProxmoxID)
				}
				if g.Name != w.Name {
					t.Errorf("[%d] Name = %q, want %q", i, g.Name, w.Name)
				}
				if g.Status != w.Status {
					t.Errorf("[%d] Status = %q, want %q", i, g.Status, w.Status)
				}
			}
		})
	}
}

func TestParseQmList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []*models.Guest
		wantN int
	}{
		{
			name: "multiple entries",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       200 myvm                 running    2048              32.00 12345
       201 othervm              stopped    1024              20.00 0`,
			want: []*models.Guest{
				{Type: models.GuestTypeVM, ProxmoxID: 200, Name: "myvm", Status: models.StatusRunning},
				{Type: models.GuestTypeVM, ProxmoxID: 201, Name: "othervm", Status: models.StatusStopped},
			},
			wantN: 2,
		},
		{
			name:  "empty output",
			input: "",
			wantN: 0,
		},
		{
			name: "header only",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID`,
			wantN: 0,
		},
		{
			name: "mixed statuses",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       300 web                  running    4096              50.00 9999
       301 worker               stopped    2048              30.00 0
       302 api                  running    8192             100.00 1111`,
			want: []*models.Guest{
				{Type: models.GuestTypeVM, ProxmoxID: 300, Name: "web", Status: models.StatusRunning},
				{Type: models.GuestTypeVM, ProxmoxID: 301, Name: "worker", Status: models.StatusStopped},
				{Type: models.GuestTypeVM, ProxmoxID: 302, Name: "api", Status: models.StatusRunning},
			},
			wantN: 3,
		},
		{
			name: "malformed lines skipped",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       200 myvm                 running    2048              32.00 12345
garbage
xy
       201 othervm              stopped    1024              20.00 0`,
			want: []*models.Guest{
				{Type: models.GuestTypeVM, ProxmoxID: 200, Name: "myvm", Status: models.StatusRunning},
				{Type: models.GuestTypeVM, ProxmoxID: 201, Name: "othervm", Status: models.StatusStopped},
			},
			wantN: 2,
		},
		{
			name: "non-numeric VMID skipped",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       abc badvm                running    2048              32.00 12345
       200 goodvm               running    2048              32.00 12345`,
			want: []*models.Guest{
				{Type: models.GuestTypeVM, ProxmoxID: 200, Name: "goodvm", Status: models.StatusRunning},
			},
			wantN: 1,
		},
		{
			name: "unknown status normalises to stopped",
			input: `      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       200 myvm                 suspended  2048              32.00 0`,
			want: []*models.Guest{
				{Type: models.GuestTypeVM, ProxmoxID: 200, Name: "myvm", Status: models.StatusStopped},
			},
			wantN: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseQmList(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantN {
				t.Fatalf("got %d guests, want %d", len(got), tc.wantN)
			}
			for i, g := range got {
				w := tc.want[i]
				if g.Type != w.Type {
					t.Errorf("[%d] Type = %q, want %q", i, g.Type, w.Type)
				}
				if g.ProxmoxID != w.ProxmoxID {
					t.Errorf("[%d] ProxmoxID = %d, want %d", i, g.ProxmoxID, w.ProxmoxID)
				}
				if g.Name != w.Name {
					t.Errorf("[%d] Name = %q, want %q", i, g.Name, w.Name)
				}
				if g.Status != w.Status {
					t.Errorf("[%d] Status = %q, want %q", i, g.Status, w.Status)
				}
			}
		})
	}
}
