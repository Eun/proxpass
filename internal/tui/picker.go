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
		title:   r.NewStyle().Bold(true).Padding(0).Foreground(lipgloss.Color("205")),
		hint:    r.NewStyle().Foreground(lipgloss.Color("241")).Italic(true),
	}
}

// defaultListStyles mirrors bubbles/list.DefaultStyles() but uses r.NewStyle()
// so every style is evaluated against our per-session renderer rather than
// the global lipgloss renderer (which is tied to os.Stdout).
func defaultListStyles(r *lipgloss.Renderer) list.Styles { //nolint:revive // mirrors upstream signature
	verySubduedColor := lipgloss.AdaptiveColor{Light: "#DDDADA", Dark: "#3C3C3C"}
	subduedColor := lipgloss.AdaptiveColor{Light: "#9B9B9B", Dark: "#5C5C5C"}

	var s list.Styles
	s.TitleBar = r.NewStyle().Padding(0, 0, 1, 1) //nolint:mnd

	s.Title = r.NewStyle().Foreground(lipgloss.Color("205"))

	s.Spinner = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#8E8E8E", Dark: "#747373"})

	s.FilterPrompt = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#04B575", Dark: "#ECFD65"})

	s.FilterCursor = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#EE6FF8", Dark: "#EE6FF8"})

	s.DefaultFilterCharacterMatch = r.NewStyle().Underline(true)

	s.StatusBar = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"}).
		Padding(0, 0, 1, 2) //nolint:mnd

	s.StatusEmpty = r.NewStyle().Foreground(subduedColor)

	s.StatusBarActiveFilter = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#1a1a1a", Dark: "#dddddd"})

	s.StatusBarFilterCount = r.NewStyle().Foreground(verySubduedColor)

	s.NoItems = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#909090", Dark: "#626262"})

	s.ArabicPagination = r.NewStyle().Foreground(subduedColor)

	s.PaginationStyle = r.NewStyle().PaddingLeft(2) //nolint:mnd

	s.HelpStyle = r.NewStyle().Padding(1, 0, 0, 2) //nolint:mnd

	s.ActivePaginationDot = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#847A85", Dark: "#979797"}).
		SetString("•")

	s.InactivePaginationDot = r.NewStyle().
		Foreground(verySubduedColor).
		SetString("•")

	s.DividerDot = r.NewStyle().
		Foreground(verySubduedColor).
		SetString(" • ")

	return s
}

// defaultItemStyles mirrors bubbles/list.NewDefaultItemStyles() using r.NewStyle().
func defaultItemStyles(r *lipgloss.Renderer) list.DefaultItemStyles {
	var s list.DefaultItemStyles

	s.NormalTitle = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#1a1a1a", Dark: "#dddddd"})

	s.NormalDesc = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"})

	s.SelectedTitle = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"}).
		Foreground(lipgloss.AdaptiveColor{Light: "#EE6FF8", Dark: "#EE6FF8"})

	s.SelectedDesc = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"}).
		Foreground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"})

	s.DimmedTitle = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"})

	s.DimmedDesc = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#C2B8C2", Dark: "#4D4D4D"})

	s.FilterMatch = r.NewStyle().Underline(true)

	return s
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
	if i.guest.Status == models.StatusRunning {
		return i.styles.running.Render(i.guest.Name)
	}
	return i.styles.stopped.Render(i.guest.Name)
}

func (i guestItem) Description() string {
	parts := []string{
		fmt.Sprintf("%s%d", i.guest.Type, i.guest.ProxmoxID),
		i.instName,
	}
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
	hint     string
	quit     bool
	styles   *guestStyles
}

func newPickerModel(
	guests []*models.Guest,
	instMap map[int64]string,
	width, height int,
	r *lipgloss.Renderer,
) pickerModel {
	styles := newGuestStyles(r)

	items := make([]list.Item, 0, len(guests))
	for _, g := range guests {
		items = append(items, guestItem{guest: g, instName: instMap[g.InstanceID], styles: styles})
	}

	// Build delegate with renderer-aware styles so the selected/normal item
	// border and text colors also use our per-session renderer.
	delegate := list.NewDefaultDelegate()
	delegate.Styles = defaultItemStyles(r)

	l := list.New(items, delegate, width, height)
	l.Title = styles.title.Render("Select a guest to connect to")
	// Override ALL list styles with renderer-aware versions so nothing falls
	// back to the global lipgloss renderer (which is tied to os.Stdout).
	l.Styles = defaultListStyles(r)
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
type sshEnviron struct {
	termType string
}

func (e sshEnviron) Environ() []string {
	return []string{"TERM=" + e.termType, "CLICOLOR_FORCE=1"}
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
// termType is the TERM value from the SSH pty-req (e.g. "xterm-256color").
//
// Color strategy: a per-session lipgloss.Renderer backed by the SSH channel
// writer is created with termenv.WithTTY(true) and the SSH TERM. ALL styles
// — including bubbles/list internal ones — are rebuilt from this renderer so
// colors work regardless of whether os.Stdout is a TTY on the server side.
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

	// Per-session renderer: WithTTY(true) skips the Fd()/IsTerminal() check
	// (SSH channel has no file descriptor). WithEnvironment feeds TERM and
	// CLICOLOR_FORCE=1 for correct color-profile detection.
	sshRenderer := lipgloss.NewRenderer(writer,
		termenv.WithTTY(true),
		termenv.WithEnvironment(sshEnviron{termType: termType}),
	)

	m := newPickerModel(guests, instMap, w, h, sshRenderer)

	environ := []string{"TERM=" + termType, "CLICOLOR_FORCE=1"}

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
