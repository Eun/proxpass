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

// pickerStyles holds all lipgloss styles for the picker, bound to the
// per-session renderer so they work regardless of whether os.Stdout is a TTY.
type pickerStyles struct {
	stoppedHint lipgloss.Style
	// list-component styles (set on l.Styles and delegate.Styles)
	list     list.Styles
	delegate list.DefaultItemStyles
}

func newPickerStyles(r *lipgloss.Renderer) *pickerStyles {
	verySubdued := lipgloss.AdaptiveColor{Light: "#DDDADA", Dark: "#3C3C3C"}
	subdued := lipgloss.AdaptiveColor{Light: "#9B9B9B", Dark: "#5C5C5C"}

	// Running guests get bright-green titles; stopped guests get gray.
	// These colours are placed on the NormalTitle / DimmedTitle styles so
	// that bubbles/list handles truncation, padding and filter-match
	// highlighting correctly (it calls .Inline(true) on these styles before
	// running lipgloss.StyleRunes — pre-rendering ANSI codes in Title() would
	// corrupt the rune-index mapping and produce raw escape codes in the output).
	runningColor := lipgloss.AdaptiveColor{Light: "#007700", Dark: "#00dd00"}
	stoppedColor := lipgloss.AdaptiveColor{Light: "#999999", Dark: "#666666"}

	s := &pickerStyles{
		stoppedHint: r.NewStyle().Foreground(lipgloss.Color("209")).Bold(true),
	}

	// list.Styles — mirrors bubbles/list.DefaultStyles() using r.NewStyle().
	// TitleBar must have zero horizontal padding: the filter input is sized
	// to fill the full terminal width (FilterInput.Width = termWidth - promptWidth),
	// so any left padding here would push the rendered line beyond the terminal
	// width, leaving stale title characters visible when the filter activates.
	// Keep only bottom padding for the blank line between title and items.
	s.list.TitleBar = r.NewStyle().Padding(0, 0, 1, 0) //nolint:mnd
	s.list.Title = r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205"))
	s.list.Spinner = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#8E8E8E", Dark: "#747373"})
	s.list.FilterPrompt = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#04B575", Dark: "#ECFD65"})
	s.list.FilterCursor = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#EE6FF8", Dark: "#EE6FF8"})
	s.list.DefaultFilterCharacterMatch = r.NewStyle().Underline(true)
	s.list.StatusBar = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"}).
		Padding(0, 0, 1, 2) //nolint:mnd
	s.list.StatusEmpty = r.NewStyle().Foreground(subdued)
	s.list.StatusBarActiveFilter = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#1a1a1a", Dark: "#dddddd"})
	s.list.StatusBarFilterCount = r.NewStyle().Foreground(verySubdued)
	s.list.NoItems = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#909090", Dark: "#626262"})
	s.list.ArabicPagination = r.NewStyle().Foreground(subdued)
	s.list.PaginationStyle = r.NewStyle().PaddingLeft(2)  //nolint:mnd
	s.list.HelpStyle = r.NewStyle().Padding(1, 0, 0, 2)   //nolint:mnd
	s.list.ActivePaginationDot = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#847A85", Dark: "#979797"}).
		SetString("•")
	s.list.InactivePaginationDot = r.NewStyle().Foreground(verySubdued).SetString("•")
	s.list.DividerDot = r.NewStyle().Foreground(verySubdued).SetString(" • ")

	// list.DefaultItemStyles — the delegate applies these styles to the plain
	// strings returned by guestItem.Title() / Description().  Do NOT pre-render
	// ANSI codes in those methods; let the delegate do all colouring here so
	// that filter-match highlighting (lipgloss.StyleRunes) works correctly.
	s.delegate.NormalTitle = r.NewStyle().
		PaddingLeft(1).
		Foreground(runningColor)
	s.delegate.NormalDesc = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"})
	s.delegate.SelectedTitle = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"}).
		Foreground(lipgloss.AdaptiveColor{Light: "#EE6FF8", Dark: "#EE6FF8"})
	s.delegate.SelectedDesc = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"}).
		Foreground(lipgloss.AdaptiveColor{Light: "#F793FF", Dark: "#AD58B4"})
	s.delegate.DimmedTitle = r.NewStyle().
		PaddingLeft(1).
		Foreground(stoppedColor)
	s.delegate.DimmedDesc = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#C2B8C2", Dark: "#4D4D4D"})
	s.delegate.FilterMatch = r.NewStyle().Underline(true)

	return s
}

// ----------------------------------------------------------
// list.Item implementation
// ----------------------------------------------------------

// guestItem wraps a Guest for the bubbles/list component.
//
// IMPORTANT: Title() and Description() must return PLAIN TEXT with no ANSI
// escape codes.  The delegate's Render() method applies styles itself and also
// calls lipgloss.StyleRunes() for filter-match highlighting.  StyleRunes maps
// rune indices from FilterValue() (plain text) onto the Title() string — if
// that string already contains escape codes the indices are wrong and raw codes
// appear in the output.
type guestItem struct {
	guest    *models.Guest
	instName string
}

func (i guestItem) FilterValue() string { return i.guest.Name }

// Title returns the plain guest name.  Colour is applied by the delegate via
// NormalTitle / DimmedTitle / SelectedTitle styles.
func (i guestItem) Title() string {
	return i.guest.Name
}

// Description returns plain metadata.  Colour is applied by the delegate.
func (i guestItem) Description() string {
	parts := []string{
		fmt.Sprintf("%s%d", i.guest.Type, i.guest.ProxmoxID),
		i.instName,
	}
	if i.guest.Status != models.StatusRunning {
		parts = append(parts, string(i.guest.Status))
	}
	return strings.Join(parts, " • ")
}

// ----------------------------------------------------------
// Model
// ----------------------------------------------------------

type pickerModel struct {
	list     list.Model
	styles   *pickerStyles
	selected *guestItem
	hint     string // message shown when a stopped guest is selected
	quit     bool
}

func newPickerModel(
	guests []*models.Guest,
	instMap map[int64]string,
	width, height int,
	r *lipgloss.Renderer,
) pickerModel {
	styles := newPickerStyles(r)

	items := make([]list.Item, 0, len(guests))
	for _, g := range guests {
		items = append(items, guestItem{guest: g, instName: instMap[g.InstanceID]})
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles = styles.delegate

	l := list.New(items, delegate, width, height)
	l.Title = "Select a guest to connect to"
	l.Styles = styles.list
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(true)

	return pickerModel{list: l, styles: styles}
}

func (m pickerModel) Init() tea.Cmd {
	// Send a WindowSizeMsg on startup so the bubbletea renderer learns the
	// terminal width. Without this, p.ttyOutput is nil (SSH channel has no
	// file descriptor), r.width stays 0, and EraseLineRight is never emitted
	// — leaving stale characters when a shorter line replaces a longer one.
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: m.list.Width(), Height: m.list.Height()}
	}
}

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// While the filter input is active the list handles esc/q itself
		// (esc cancels filtering, q is typed into the filter). Only intercept
		// these keys when we are NOT actively filtering.
		if m.list.FilterState() != list.Filtering {
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
		view += "\r\n" + m.styles.stoppedHint.Render(m.hint)
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
	// CLICOLOR_FORCE=1 for correct color-profile detection independent of
	// whether os.Stdout is a TTY on the server side.
	sshRenderer := lipgloss.NewRenderer(writer,
		termenv.WithTTY(true),
		termenv.WithEnvironment(sshEnviron{termType: termType}),
	)

	m := newPickerModel(guests, instMap, w, h, sshRenderer)

	p, err := tea.NewProgram(
		m,
		tea.WithInput(reader),
		tea.WithOutput(writer),
		tea.WithEnvironment([]string{"TERM=" + termType, "CLICOLOR_FORCE=1"}),
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
