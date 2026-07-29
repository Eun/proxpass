package tui

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"proxpass/internal/models"
	"proxpass/pkg/statusbar"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	gossh "golang.org/x/crypto/ssh"
)

// Color constants used in pickerStyles.
const (
	colorEE6FF8 = "#EE6FF8" // selected title / filter cursor highlight.
	colorAD58B4 = "#AD58B4" // selected item border (dark).
	colorF793FF = "#F793FF" // selected item border (light).
)

// filterSep separates the name and description inside FilterValue() so the
// fuzzy filter searches both fields. We use a space so the combined string is
// natural text; the separator itself can never be a match target because fuzzy
// scoring skips the separator position when we split indices at nameLen.
// We cannot use NUL (\x00) because the fuzzy library treats nextc==0 as
// end-of-string and panics when it tries to access runes[patternIndex+1]
// after prematurely committing a match at the NUL byte.
const filterSep = " "

// ----------------------------------------------------------
// Per-session styles
// ----------------------------------------------------------

// pickerStyles holds all lipgloss styles for the picker, bound to the
// per-session renderer so they work regardless of whether os.Stdout is a TTY.
type pickerStyles struct {
	stoppedDialog        lipgloss.Style // outer dialog box
	stoppedDialogText    lipgloss.Style // text inside the dialog
	stoppedSelectedTitle lipgloss.Style
	stoppedSelectedDesc  lipgloss.Style
	// list-component styles (set on l.Styles and delegate.Styles)
	list     list.Styles
	delegate list.DefaultItemStyles
}

func newPickerStyles(r *lipgloss.Renderer) *pickerStyles {
	verySubdued := lipgloss.AdaptiveColor{Light: "#DDDADA", Dark: "#3C3C3C"}
	subdued := lipgloss.AdaptiveColor{Light: "#9B9B9B", Dark: "#5C5C5C"}

	stoppedColor := lipgloss.AdaptiveColor{Light: "#999999", Dark: "#666666"}

	s := &pickerStyles{
		stoppedDialog: r.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("209")).
			Padding(1, 3). //nolint:mnd // magic number from color/terminal protocol spec
			Align(lipgloss.Center),
		stoppedDialogText: r.NewStyle().
			Foreground(lipgloss.Color("209")).
			Bold(true),
	}

	// list.Styles — mirrors bubbles/list.DefaultStyles() using r.NewStyle().
	// TitleBar must have zero horizontal padding: the filter input is sized
	// to fill the full terminal width (FilterInput.Width = termWidth - promptWidth),
	// so any left padding here would push the rendered line beyond the terminal
	// width, leaving stale title characters visible when the filter activates.
	// Keep only bottom padding for the blank line between title and items.
	s.list.TitleBar = r.NewStyle().Padding(0, 0, 1, 0) //nolint:mnd // magic number from color/terminal protocol spec
	s.list.Title = r.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205"))
	s.list.Spinner = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#8E8E8E", Dark: "#747373"})
	s.list.FilterPrompt = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#04B575", Dark: "#ECFD65"})
	s.list.FilterCursor = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: colorEE6FF8, Dark: colorEE6FF8})
	s.list.DefaultFilterCharacterMatch = r.NewStyle().Underline(true)
	s.list.StatusBar = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"}).
		Padding(0, 0, 1, 2) //nolint:mnd // magic number from color/terminal protocol spec
	s.list.StatusEmpty = r.NewStyle().Foreground(subdued)
	s.list.StatusBarActiveFilter = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#1a1a1a", Dark: "#dddddd"})
	s.list.StatusBarFilterCount = r.NewStyle().Foreground(verySubdued)
	s.list.NoItems = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#909090", Dark: "#626262"})
	s.list.ArabicPagination = r.NewStyle().Foreground(subdued)
	s.list.PaginationStyle = r.NewStyle().PaddingLeft(2) //nolint:mnd // magic number from color/terminal protocol spec
	s.list.HelpStyle = r.NewStyle().Padding(1, 0, 0, 2)  //nolint:mnd // magic number from color/terminal protocol spec
	s.list.ActivePaginationDot = r.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#847A85", Dark: "#979797"}).
		SetString("•")
	s.list.InactivePaginationDot = r.NewStyle().Foreground(verySubdued).SetString("•")
	s.list.DividerDot = r.NewStyle().Foreground(verySubdued).SetString(" • ")

	// list.DefaultItemStyles — the delegate applies these styles to the plain
	// strings returned by guestItem.Title() / Description().  Do NOT pre-render
	// ANSI codes in those methods; let the delegate do all coloring here so
	// that filter-match highlighting (lipgloss.StyleRunes) works correctly.
	runningColor := lipgloss.AdaptiveColor{Light: "#007700", Dark: "#00dd00"}
	s.delegate.NormalTitle = r.NewStyle().
		PaddingLeft(1).
		Foreground(runningColor)
	s.delegate.NormalDesc = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#A49FA5", Dark: "#777777"})
	s.delegate.SelectedTitle = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: colorF793FF, Dark: colorAD58B4}).
		Foreground(lipgloss.AdaptiveColor{Light: colorEE6FF8, Dark: colorEE6FF8})
	s.delegate.SelectedDesc = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(lipgloss.AdaptiveColor{Light: colorF793FF, Dark: colorAD58B4}).
		Foreground(lipgloss.AdaptiveColor{Light: colorF793FF, Dark: colorAD58B4})
	s.delegate.DimmedTitle = r.NewStyle().
		PaddingLeft(1).
		Foreground(stoppedColor)
	s.delegate.DimmedDesc = r.NewStyle().
		PaddingLeft(1).
		Foreground(lipgloss.AdaptiveColor{Light: "#C2B8C2", Dark: "#4D4D4D"})
	s.delegate.FilterMatch = r.NewStyle().Underline(true)

	// stoppedSelectedTitle/Desc: dimmed border + dimmed text for selected stopped guests.
	s.stoppedSelectedTitle = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(stoppedColor).
		Foreground(stoppedColor)
	s.stoppedSelectedDesc = r.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(stoppedColor).
		Foreground(lipgloss.AdaptiveColor{Light: "#C2B8C2", Dark: "#4D4D4D"})

	return s
}

// ----------------------------------------------------------
// list.Item implementation
// ----------------------------------------------------------

// guestItem wraps a Guest for the bubbles/list component.
//
// FilterValue() returns "name\x00description" so the filter searches both
// fields. The NUL separator is never present in real text, making it safe to
// split match indices at the name-boundary rune offset.
//
// Title() and Description() return PLAIN TEXT — no ANSI codes. All styling is
// applied by guestDelegate.Render so that lipgloss.StyleRunes can operate on
// clean strings and rune indices are correct.
type guestItem struct {
	guest    *models.Guest
	instName string
}

// FilterValue combines name and description with a NUL separator so the fuzzy
// filter searches both fields with a single pass.
func (i guestItem) FilterValue() string {
	return i.guest.Name + filterSep + i.description()
}

func (i guestItem) Title() string { return i.guest.Name }

func (i guestItem) Description() string { return i.description() }

func (i guestItem) description() string {
	parts := []string{
		fmt.Sprintf("%s%d", i.guest.Type, i.guest.ProxmoxID),
		i.instName,
	}
	if i.guest.Status != models.StatusRunning {
		parts = append(parts, string(i.guest.Status))
	}
	return strings.Join(parts, " • ")
}

func (i guestItem) isStopped() bool {
	return i.guest.Status != models.StatusRunning
}

// ----------------------------------------------------------
// Custom delegate
// ----------------------------------------------------------

// guestDelegate wraps list.DefaultDelegate and overrides Render to:
//   - dim stopped guests (normal or selected)
//   - highlight filter matches in both title AND description
type guestDelegate struct {
	list.DefaultDelegate
	styles *pickerStyles
}

//nolint:gocritic // list.Model is interface-typed; hugeParam does not apply to interface values
func (d *guestDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	gi, ok := item.(guestItem)
	if !ok {
		d.DefaultDelegate.Render(w, m, index, item)
		return
	}

	isSelected := index == m.Index()
	isFiltering := m.FilterState() == list.Filtering
	isFiltered := m.FilterState() == list.Filtering || m.FilterState() == list.FilterApplied
	emptyFilter := isFiltering && m.FilterValue() == ""

	title := gi.Title()
	desc := gi.Description()

	s := &d.Styles

	// Width available for text (excluding padding and border).
	textWidth := m.Width() - s.NormalTitle.GetPaddingLeft() - s.NormalTitle.GetPaddingRight()
	title = ansi.Truncate(title, textWidth, "…")
	desc = ansi.Truncate(desc, textWidth, "…")

	// Determine title and desc styles based on item state.
	var titleStyle, descStyle lipgloss.Style
	switch {
	case emptyFilter:
		titleStyle = s.DimmedTitle
		descStyle = s.DimmedDesc
	case gi.isStopped() && isSelected && !isFiltering:
		titleStyle = d.styles.stoppedSelectedTitle
		descStyle = d.styles.stoppedSelectedDesc
	case gi.isStopped():
		titleStyle = s.DimmedTitle
		descStyle = s.DimmedDesc
	case isSelected && !isFiltering:
		titleStyle = s.SelectedTitle
		descStyle = s.SelectedDesc
	default:
		titleStyle = s.NormalTitle
		descStyle = s.NormalDesc
	}

	// Apply filter-match highlighting when there are matches.
	if isFiltered && !emptyFilter { //nolint:nestif // filter-match index splitting requires nested conditions
		rawMatches := m.MatchesForItem(index)
		if len(rawMatches) > 0 {
			titleRunes := utf8.RuneCountInString(gi.Title())
			// +1 for the NUL separator in FilterValue().
			descOffset := titleRunes + 1

			var titleMatches, descMatches []int
			for _, idx := range rawMatches {
				switch {
				case idx < titleRunes:
					titleMatches = append(titleMatches, idx)
				case idx >= descOffset:
					descMatches = append(descMatches, idx-descOffset)
				}
			}

			if len(titleMatches) > 0 {
				unmatched := titleStyle.Inline(true)
				matched := unmatched.Inherit(s.FilterMatch)
				title = lipgloss.StyleRunes(title, titleMatches, matched, unmatched)
			}
			if len(descMatches) > 0 {
				unmatched := descStyle.Inline(true)
				matched := unmatched.Inherit(s.FilterMatch)
				desc = lipgloss.StyleRunes(desc, descMatches, matched, unmatched)
			}
		}
	}

	title = titleStyle.Render(title)
	desc = descStyle.Render(desc)

	if d.ShowDescription {
		fmt.Fprintf(w, "%s\n%s", title, desc)
	} else {
		fmt.Fprintf(w, "%s", title)
	}
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

	delegate := &guestDelegate{DefaultDelegate: list.NewDefaultDelegate(), styles: styles}
	delegate.Styles = styles.delegate

	l := list.New(items, delegate, width, height)
	l.Title = "Select a guest to connect to"
	l.Styles = styles.list
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(true)

	return pickerModel{list: l, styles: styles}
}

func (m *pickerModel) Init() tea.Cmd {
	// Send a WindowSizeMsg on startup so the bubbletea renderer learns the
	// terminal width. Without this, p.ttyOutput is nil (SSH channel has no
	// file descriptor), r.width stays 0, and EraseLineRight is never emitted
	// — leaving stale characters when a shorter line replaces a longer one.
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: m.list.Width(), Height: m.list.Height()}
	}
}

func (m *pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// While the stopped-guest dialog is visible, enter and esc dismiss it;
		// ctrl+c still quits. No keys are forwarded to the list in this state.
		if m.hint != "" {
			switch msg.String() {
			case "ctrl+c":
				m.quit = true
				return m, tea.Quit
			default:
				m.hint = ""
			}
			return m, nil
		}

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
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m *pickerModel) View() string {
	if m.quit {
		return ""
	}
	listView := m.list.View()
	if m.hint == "" {
		return listView
	}

	// A stopped guest was selected: show a centered dialog over the list.
	// lipgloss.Place centers the dialog within the terminal dimensions and
	// fills the surrounding space with spaces, effectively replacing the list
	// background. The list is still visible in the terminal's scroll buffer but
	// the focused view is the dialog — the user dismisses it with any key.
	dialog := m.styles.stoppedDialog.Render(
		m.styles.stoppedDialogText.Render(m.hint),
	)
	return lipgloss.Place(
		m.list.Width(), m.list.Height(),
		lipgloss.Center, lipgloss.Center,
		dialog,
	)
}

// ----------------------------------------------------------
// sshEnviron
// ----------------------------------------------------------

// sshEnviron implements termenv.Environ using the SSH client's TERM.
// CLICOLOR_FORCE is set only when the client's terminal actually supports
// colors; on dumb/Ascii-profile clients we do not force colors so that
// lipgloss detects the Ascii profile and suppresses all ANSI codes.
type sshEnviron struct {
	termType string
	hasColor bool // true when the client supports at least ANSI colors
}

func newSSHEnviron(termType, colorTerm, noColor string) sshEnviron {
	// Use statusbar.ColorProfileFromEnv instead of termenv.NewOutput(nil, ...)
	// because termenv's ColorProfile() always returns Ascii when there is no
	// real TTY fd (isTTY() == false). Our helper replicates the same TERM /
	// COLORTERM / NO_COLOR logic without the fd check.
	p := statusbar.ColorProfileFromEnv(termType, colorTerm, noColor)
	return sshEnviron{termType: termType, hasColor: p != termenv.Ascii}
}

func (e sshEnviron) Environ() []string {
	env := []string{"TERM=" + e.termType}
	if e.hasColor {
		env = append(env, "CLICOLOR_FORCE=1")
	}
	return env
}

func (e sshEnviron) Getenv(key string) string {
	switch key {
	case "TERM":
		return e.termType
	case "CLICOLOR_FORCE":
		if e.hasColor {
			return "1"
		}
		return ""
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
// reqs is the live SSH channel request stream. PickGuest reads window-change
// requests from it and forwards them as tea.WindowSizeMsg to the bubbletea
// program so the picker resizes when the user resizes their terminal. The
// channel is NOT drained — the caller must continue reading it after
// PickGuest returns (e.g. to pass it to ProxyToGuest).
//
// termType is the TERM value (e.g. "xterm-256color") — from pty-req or SSH env.
// colorTerm is the COLORTERM value (e.g. "truecolor") — from SSH env, may be empty.
// noColor is the NO_COLOR value — non-empty disables all color output.
func PickGuest(
	reader io.Reader,
	writer io.Writer,
	guests []*models.Guest,
	instMap map[int64]string,
	width, height uint32,
	termType, colorTerm, noColor string,
	reqs <-chan *gossh.Request,
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
	// optionally CLICOLOR_FORCE=1 for correct color-profile detection,
	// independent of whether os.Stdout is a TTY on the server side.
	// CLICOLOR_FORCE is only set when the client actually supports colors;
	// dumb/Ascii-profile clients get a plain no-color rendering.
	env := newSSHEnviron(termType, colorTerm, noColor)
	sshRenderer := lipgloss.NewRenderer(writer,
		termenv.WithTTY(true),
		termenv.WithEnvironment(env),
	)

	m := newPickerModel(guests, instMap, w, h, sshRenderer)

	prog := tea.NewProgram(
		&m,
		tea.WithInput(reader),
		tea.WithOutput(writer),
		tea.WithEnvironment(env.Environ()),
		tea.WithoutCatchPanics(),
	)

	// Forward SSH window-change requests as tea.WindowSizeMsg so the picker
	// resizes when the user resizes their terminal. We stop forwarding as
	// soon as the program exits (stopFwd is closed). Non-window-change
	// requests are replied to with false and discarded.
	stopFwd := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopFwd:
				return
			case req, ok := <-reqs:
				if !ok {
					return
				}
				if req.Type == "window-change" {
					var cols, rows uint32
					if len(req.Payload) >= 8 { //nolint:mnd // magic number from color/terminal protocol spec
						// RFC 4254 §6.7: window-change payload is cols(4) rows(4) px-w(4) px-h(4)
						//nolint:mnd // bit offsets are part of the SSH wire format
						cols = uint32(req.Payload[0])<<24 | uint32(req.Payload[1])<<16 |
							uint32(req.Payload[2])<<8 | uint32(req.Payload[3])
						rows = uint32(req.Payload[4])<<24 | uint32(req.Payload[5])<<16 |
							uint32(req.Payload[6])<<8 | uint32(req.Payload[7])
						prog.Send(tea.WindowSizeMsg{Width: int(cols), Height: int(rows)})
					}
				}
				if req.WantReply {
					_ = req.Reply(req.Type == "window-change", nil)
				}
			}
		}
	}()

	finalModel, err := prog.Run()
	close(stopFwd)
	if err != nil {
		return nil, "", fmt.Errorf("picker: %w", err)
	}

	final, ok := finalModel.(*pickerModel)
	if !ok || final.selected == nil {
		return nil, "", nil
	}
	return final.selected.guest, final.selected.instName, nil
}
