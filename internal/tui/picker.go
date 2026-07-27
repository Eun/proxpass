package tui

import (
	"fmt"
	"io"
	"strings"

	"proxpass/internal/models"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// ----------------------------------------------------------
// Per-session styles
// ----------------------------------------------------------

// guestStyles holds lipgloss styles bound to a specific renderer.
// Using a per-call renderer (backed by the SSH channel writer with the
// client's TERM) ensures bubbletea and lipgloss detect the remote terminal's
// color capabilities instead of falling back to the server's os.Stdout.
type guestStyles struct {
	running lipgloss.Style
	stopped lipgloss.Style
	title   lipgloss.Style
	hint    lipgloss.Style
}

func newGuestStyles(r *lipgloss.Renderer) *guestStyles {
	return &guestStyles{
		running: r.NewStyle().Foreground(lipgloss.Color("10")),  // bright green
		stopped: r.NewStyle().Foreground(lipgloss.Color("240")), // gray
		title:   r.NewStyle().Bold(true).Foreground(lipgloss.Color("205")),
		hint:    r.NewStyle().Foreground(lipgloss.Color("241")).Italic(true),
	}
}

// ----------------------------------------------------------
// list.Item implementation
// ----------------------------------------------------------

// guestItem wraps a Guest for the bubbles/list component.
type guestItem struct {
	guest    *models.Guest
	instName string
	styles   *guestStyles
}

func (i guestItem) FilterValue() string { return i.guest.Name }

func (i guestItem) Title() string {
	name := fmt.Sprintf("%s [%s%d]", i.guest.Name, i.guest.Type, i.guest.ProxmoxID)
	if i.guest.Status == models.StatusRunning {
		return i.styles.running.Render(name)
	}
	return i.styles.stopped.Render(name)
}

func (i guestItem) Description() string {
	parts := []string{i.instName}
	if i.guest.Status != models.StatusRunning {
		parts = append(parts, string(i.guest.Status))
	}
	s := strings.Join(parts, " • ")
	if i.guest.Status != models.StatusRunning {
		return i.styles.stopped.Render(s)
	}
	return i.styles.hint.Render(s)
}

// ----------------------------------------------------------
// Model
// ----------------------------------------------------------

type pickerModel struct {
	list     list.Model
	selected *guestItem
	hint     string // temporary message for stopped-guest selection
	quit     bool
	styles   *guestStyles
}

func newPickerModel(
	guests []*models.Guest,
	instMap map[int64]string,
	width, height int,
	styles *guestStyles,
) pickerModel {
	items := make([]list.Item, 0, len(guests))
	for _, g := range guests {
		items = append(items, guestItem{guest: g, instName: instMap[g.InstanceID], styles: styles})
	}

	delegate := list.NewDefaultDelegate()

	l := list.New(items, delegate, width, height)
	l.Title = styles.title.Render("Select a guest to connect to")
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(true)

	return pickerModel{list: l, styles: styles}
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "enter":
			selected, ok := m.list.SelectedItem().(guestItem)
			if !ok {
				break
			}
			if selected.guest.Status != models.StatusRunning {
				m.hint = fmt.Sprintf("%s is stopped — cannot connect.", selected.guest.Name)
				return m, nil
			}
			m.selected = &selected
			return m, tea.Quit
		}
		if m.hint != "" && msg.String() != "enter" {
			m.hint = ""
		}
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m pickerModel) View() string {
	if m.quit {
		return ""
	}
	view := m.list.View()
	if m.hint != "" {
		view += "\r\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("209")).
			Bold(true).
			Render(m.hint)
	}
	return view
}

// ----------------------------------------------------------
// sshEnviron
// ----------------------------------------------------------

// sshEnviron implements termenv.Environ using only the SSH client's TERM.
// It intentionally omits all server-side variables so the color profile is
// determined purely by what the SSH client advertised.
type sshEnviron struct {
	termType string
}

func (e sshEnviron) Environ() []string {
	return []string{
		"TERM=" + e.termType,
		"CLICOLOR_FORCE=1",
	}
}

func (e sshEnviron) Getenv(key string) string {
	switch key {
	case "TERM":
		return e.termType
	case "CLICOLOR_FORCE":
		return "1"
	}
	return ""
}

// ----------------------------------------------------------
// Public entry point
// ----------------------------------------------------------

// PickGuest presents an interactive list of guests to the user
// over the provided reader/writer (e.g. an SSH channel).
//
// Returns the selected Guest and the name of its instance,
// or nil, "" if the user cancels without making a selection.
//
// width and height are the initial terminal dimensions (columns/rows).
// termType is the TERM value from the SSH pty-req (e.g. "xterm-256color").
//
// Color rendering strategy:
//
//   - A per-session lipgloss.Renderer is created backed by the SSH channel
//     writer with termenv.WithTTY(true) so IsTerminal() is not called on it
//     (the SSH channel is not an *os.File and has no file descriptor).
//   - termenv.WithEnvironment(sshEnviron) feeds the SSH client's TERM into
//     the color-profile detection, giving ANSI256 for xterm-256color etc.
//   - CLICOLOR_FORCE=1 is also injected so colorprofile.Detect() never falls
//     back to NoTTY even when os.Stdout has no TTY (daemon/systemd mode).
//   - All picker styles are created via r.NewStyle() from this per-session
//     renderer, not from the global lipgloss renderer which is tied to
//     os.Stdout.
func PickGuest(
	reader io.Reader,
	writer io.Writer,
	guests []*models.Guest,
	instMap map[int64]string,
	width, height uint32,
	termType string,
) (*models.Guest, string, error) {
	if len(guests) == 0 {
		return nil, "", nil
	}

	w := int(width)
	h := int(height)
	if w == 0 {
		w = 80
	}
	if h == 0 {
		h = 24
	}
	if termType == "" {
		termType = "xterm-256color"
	}

	// Build a per-session lipgloss renderer backed by the SSH channel writer.
	// WithTTY(true) bypasses the Fd()/IsTerminal check (SSH channel has no fd).
	// WithEnvironment(sshEnviron) feeds TERM and CLICOLOR_FORCE=1 for correct
	// color-profile detection independent of the server's os.Environ().
	sshRenderer := lipgloss.NewRenderer(writer,
		termenv.WithTTY(true),
		termenv.WithEnvironment(sshEnviron{termType: termType}),
	)
	styles := newGuestStyles(sshRenderer)
	m := newPickerModel(guests, instMap, w, h, styles)

	// Also pass the env to bubbletea (stored for future use; currently
	// bubbletea v1 doesn't forward it to its internal renderer, but it's
	// correct to set it for forward-compatibility and documentation).
	environ := []string{
		"TERM=" + termType,
		"CLICOLOR_FORCE=1",
	}

	p, err := tea.NewProgram(
		m,
		tea.WithInput(reader),
		tea.WithOutput(writer),
		tea.WithEnvironment(environ),
		tea.WithoutCatchPanics(),
	).Run()
	if err != nil {
		return nil, "", fmt.Errorf("picker: %w", err)
	}

	final, ok := p.(pickerModel)
	if !ok || final.selected == nil {
		return nil, "", nil
	}
	return final.selected.guest, final.selected.instName, nil
}
