package tui

import (
	"fmt"
	"io"
	"strings"

	"proxpass/internal/models"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ----------------------------------------------------------
// Styles
// ----------------------------------------------------------

var (
	styleRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))  // bright green
	styleStopped = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // gray
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	styleHint    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
)

// ----------------------------------------------------------
// list.Item implementation
// ----------------------------------------------------------

// guestItem wraps a Guest for the bubbles/list component.
type guestItem struct {
	guest     *models.Guest
	instName string
}

func (i guestItem) FilterValue() string { return i.guest.Name }

// list.DefaultDelegate calls Title() and Description() on items.
func (i guestItem) Title() string {
	status := i.guest.Status
	name := fmt.Sprintf("%s [%s%d]", i.guest.Name, i.guest.Type, i.guest.ProxmoxID)
	if status == models.StatusRunning {
		return styleRunning.Render(name)
	}
	return styleStopped.Render(name)
}

func (i guestItem) Description() string {
	parts := []string{i.instName}
	if i.guest.Status != models.StatusRunning {
		parts = append(parts, string(i.guest.Status))
	}
	s := strings.Join(parts, " • ")
	if i.guest.Status != models.StatusRunning {
		return styleStopped.Render(s)
	}
	return styleHint.Render(s)
}

// ----------------------------------------------------------
// Messages
// ----------------------------------------------------------

type selectedMsg struct { item guestItem }
type quitMsg struct{}

type stoppedMsg struct { name string }

// ----------------------------------------------------------
// Model
// ----------------------------------------------------------

type pickerModel struct {
	list     list.Model
	selected *guestItem
	hint     string // temporary message for stopped-guest selection
	quit     bool
}

func newPickerModel(
	guests []*models.Guest,
	instMap map[int64]string,
	width, height int,
) pickerModel {
	items := make([]list.Item, 0, len(guests))
	for _, g := range guests {
		items = append(items, guestItem{guest: g, instName: instMap[g.InstanceID]})
	}

	delegate := list.NewDefaultDelegate()

	l := list.New(items, delegate, width, height)
	l.Title = styleTitle.Render("Select a guest to connect to")
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(true)

	return pickerModel{list: l}
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Cancel on q/Esc/Ctrl+C
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
				// Show a hint and do not connect
				m.hint = fmt.Sprintf("%s is stopped — cannot connect.", selected.guest.Name)
				return m, nil
			}
			m.selected = &selected
			return m, tea.Quit
		}
		// Clear hint on any other keypress
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
// Public entry point
// ----------------------------------------------------------

// PickGuest presents an interactive list of guests to the user
// over the provided reader/writer (e.g. an SSH channel).
//
// Returns the selected Guest and the name of its instance,
// or nil, "" if the user cancels without making a selection.
//
// width and height are the initial terminal dimensions (columns/rows).
func PickGuest(
	reader io.Reader,
	writer io.Writer,
	guests []*models.Guest,
	instMap map[int64]string,
	width, height uint32,
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

	m := newPickerModel(guests, instMap, w, h)

	p, err := tea.NewProgram(
		m,
		tea.WithInput(reader),
		tea.WithOutput(writer),
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
