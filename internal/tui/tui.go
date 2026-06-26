package tui

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"proxpass/internal/db"
	"proxpass/internal/models"
	"proxpass/internal/proxmox"
)

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).MarginBottom(1)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("170")).Bold(true)
	normalStyle   = lipgloss.NewStyle()
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ruleTypeClient = "client"
const ruleTypeGroup = "group"

// ---------------------------------------------------------------------------
// View state machine
// ---------------------------------------------------------------------------

type viewState int

const (
	viewMenu viewState = iota
	viewInstances
	viewGuests
	viewClients
	viewGroups
	viewAccessRules
	viewDefaultPolicy
	viewAdminKeys
	// Input sub-states.
	viewAddInstance
	viewAddClient
	viewAddGroup
	viewAddAdminKey
	viewAddAccessRule
	viewAddPolicyEntry
)

// Menu items in the main menu.
var menuItems = []string{
	"Proxmox Instances",
	"Guests",
	"Clients",
	"Groups",
	"Access Rules",
	"Default Policy",
	"Admin Keys",
	"Quit",
}

// ---------------------------------------------------------------------------
// Messages returned from DB commands
// ---------------------------------------------------------------------------

type errMsg struct{ err error }

func (e errMsg) Error() string { return e.err.Error() }

type instancesMsg []*models.ProxmoxInstance
type guestsMsg []*models.Guest
type clientsMsg []*models.Client
type groupsMsg []*models.Group
type adminKeysMsg []string
type accessRulesMsg []*models.AccessRuleRow
type defaultPolicyMsg *models.DefaultAccessPolicy
type doneMsg struct{} // generic "operation succeeded"

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// Model is the top-level Bubble Tea model for the admin TUI.
type Model struct {
	repo              db.Repository
	discovererFactory proxmox.DiscovererFactory
	ctx               context.Context

	// Navigation
	state  viewState
	cursor int

	// Cached list data
	instances     []*models.ProxmoxInstance
	guests        []*models.Guest
	clients       []*models.Client
	groups        []*models.Group
	adminKeys     []string
	accessRules   []*models.AccessRuleRow
	defaultPolicy *models.DefaultAccessPolicy

	// Flattened default policy entries for cursor-based navigation.
	// Each entry is "client:<id>" or "group:<id>".
	policyEntries []string

	// Multi-step text input for add flows
	inputs    []textinput.Model
	inputStep int  // which input field is active
	inputDone bool // all fields collected, ready to submit

	// Set when the admin selects a guest to connect to.
	// The admin handler checks this after the TUI exits.
	SelectedGuest *models.Guest

	// Status / error line
	statusMsg string
}

// NewModel creates a new TUI model backed by the given repository.
func NewModel(repo db.Repository, df proxmox.DiscovererFactory) *Model {
	return &Model{
		repo:              repo,
		discovererFactory: df,
		ctx:               context.Background(),
		state:             viewMenu,
	}
}

// GetSelectedGuest returns the guest selected for connection, or nil.
func (m *Model) GetSelectedGuest() *models.Guest {
	return m.SelectedGuest
}

// Init implements tea.Model.
//
//nolint:gocritic // required by tea.Model interface
func (m Model) Init() tea.Cmd {
	return nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

//nolint:gocritic // required by tea.Model interface
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// --- async data messages ---
	case instancesMsg:
		m.instances = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case guestsMsg:
		m.guests = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case clientsMsg:
		m.clients = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case groupsMsg:
		m.groups = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case adminKeysMsg:
		m.adminKeys = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case accessRulesMsg:
		m.accessRules = msg
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case defaultPolicyMsg:
		m.defaultPolicy = msg
		m.policyEntries = buildPolicyEntries(msg)
		m.cursor = 0
		m.statusMsg = ""
		return m, nil
	case doneMsg:
		m.statusMsg = ""
		return m, tea.Batch(tea.ClearScreen, m.refreshCurrent())
	case errMsg:
		m.statusMsg = "Error: " + msg.Error()
		return m, nil

	// --- keyboard ---
	case tea.KeyMsg:
		// While in an input form, delegate to the input handler.
		if m.isInputState() {
			return m.updateInput(msg)
		}
		return m.updateNav(msg)
	}

	return m, nil
}

func (m *Model) isInputState() bool {
	//nolint:exhaustive // only input sub-states need explicit handling
	switch m.state {
	case viewAddInstance, viewAddClient, viewAddGroup, viewAddAdminKey,
		viewAddAccessRule, viewAddPolicyEntry:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Navigation update (menu + list screens)
// ---------------------------------------------------------------------------

func (m *Model) updateNav(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "ctrl+c", "q":
		if m.state == viewMenu {
			return m, tea.Quit
		}
		m.state = viewMenu
		m.cursor = 0
		m.statusMsg = ""
		return m, tea.ClearScreen

	case "esc", "backspace":
		if m.state != viewMenu {
			m.state = viewMenu
			m.cursor = 0
			m.statusMsg = ""
			return m, tea.ClearScreen
		}

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}

	case "down", "j":
		m.cursor = min(m.cursor+1, m.listLen()-1)

	case "enter":
		if m.state == viewMenu {
			return m.selectMenu()
		}
		if m.state == viewGuests && len(m.guests) > 0 &&
			m.cursor < len(m.guests) {
			m.SelectedGuest = m.guests[m.cursor]
			return m, tea.Quit
		}

	case "a":
		return m.startAdd()

	case "d":
		return m.deleteSelected()
	}

	return m, nil
}

func (m *Model) listLen() int {
	//nolint:exhaustive // input sub-states are not list views
	switch m.state {
	case viewMenu:
		return len(menuItems)
	case viewInstances:
		return len(m.instances)
	case viewGuests:
		return len(m.guests)
	case viewClients:
		return len(m.clients)
	case viewGroups:
		return len(m.groups)
	case viewAccessRules:
		return len(m.accessRules)
	case viewDefaultPolicy:
		return len(m.policyEntries)
	case viewAdminKeys:
		return len(m.adminKeys)
	default:
		return 0
	}
}

func (m *Model) selectMenu() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0:
		m.state = viewInstances
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchInstances())
	case 1:
		m.state = viewGuests
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchGuests())
	case 2:
		m.state = viewClients
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchClients())
	case 3:
		m.state = viewGroups
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchGroups())
	case 4:
		m.state = viewAccessRules
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchAccessRules())
	case 5:
		m.state = viewDefaultPolicy
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchDefaultPolicy())
	case 6:
		m.state = viewAdminKeys
		m.cursor = 0
		return m, tea.Batch(tea.ClearScreen, m.fetchAdminKeys())
	case 7:
		return m, tea.Quit
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Add flows – set up text inputs
// ---------------------------------------------------------------------------

func (m *Model) startAdd() (tea.Model, tea.Cmd) {
	//nolint:exhaustive // only list views support add
	switch m.state {
	case viewInstances:
		m.inputs = makeInputs(
			"Name", "API URL", "API Token ID",
			"API Token Secret",
			"SSH Host", "SSH Port", "SSH User",
			"SSH Key Path",
		)
		m.state = viewAddInstance
	case viewClients:
		m.inputs = makeInputs("Client Name", "Public Key")
		m.state = viewAddClient
	case viewGroups:
		m.inputs = makeInputs("Group Name")
		m.state = viewAddGroup
	case viewAdminKeys:
		m.inputs = makeInputs("Public Key")
		m.state = viewAddAdminKey
	case viewAccessRules:
		m.inputs = makeInputs("Type (client/group)", "Subject ID", "Guest ID")
		m.state = viewAddAccessRule
	case viewDefaultPolicy:
		m.inputs = makeInputs("Type (client/group)", "ID")
		m.state = viewAddPolicyEntry
	default:
		return m, nil
	}
	m.inputStep = 0
	m.inputDone = false
	m.statusMsg = ""
	return m, tea.Batch(tea.ClearScreen, m.inputs[0].Focus())
}

func makeInputs(placeholders ...string) []textinput.Model {
	inputs := make([]textinput.Model, len(placeholders))
	for i, ph := range placeholders {
		ti := textinput.New()
		ti.Placeholder = ph
		ti.CharLimit = 512
		ti.Width = 60
		inputs[i] = ti
	}
	return inputs
}

// ---------------------------------------------------------------------------
// Input update (text input forms)
// ---------------------------------------------------------------------------

func (m *Model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "ctrl+c":
		return m, tea.Quit

	case "esc":
		// Cancel the input and go back to the parent list.
		m.state = m.parentState()
		m.statusMsg = ""
		cmd := m.refreshCurrent()
		return m, cmd

	case "enter":
		// Advance to next field or submit.
		if m.inputStep < len(m.inputs)-1 {
			m.inputs[m.inputStep].Blur()
			m.inputStep++
			return m, m.inputs[m.inputStep].Focus()
		}
		// All fields filled — submit.
		return m.submitAdd()
	}

	// Pass the key to the active text input.
	var cmd tea.Cmd
	m.inputs[m.inputStep], cmd = m.inputs[m.inputStep].Update(msg)
	return m, cmd
}

func (m *Model) parentState() viewState {
	//nolint:exhaustive // only input sub-states have a parent
	switch m.state {
	case viewAddInstance:
		return viewInstances
	case viewAddClient:
		return viewClients
	case viewAddGroup:
		return viewGroups
	case viewAddAdminKey:
		return viewAdminKeys
	case viewAddAccessRule:
		return viewAccessRules
	case viewAddPolicyEntry:
		return viewDefaultPolicy
	default:
		return viewMenu
	}
}

func (m *Model) submitAdd() (tea.Model, tea.Cmd) {
	parent := m.parentState()
	m.state = parent

	//nolint:exhaustive // only list-view parents are valid submit targets
	switch parent {
	case viewInstances:
		name := strings.TrimSpace(m.inputs[0].Value())
		apiURL := strings.TrimSpace(m.inputs[1].Value())
		tokenID := strings.TrimSpace(m.inputs[2].Value())
		tokenSecret := strings.TrimSpace(m.inputs[3].Value())
		sshHost := strings.TrimSpace(m.inputs[4].Value())
		sshPortStr := strings.TrimSpace(m.inputs[5].Value())
		sshUser := strings.TrimSpace(m.inputs[6].Value())
		sshKeyPath := strings.TrimSpace(m.inputs[7].Value())
		sshPort, err := strconv.Atoi(sshPortStr)
		if err != nil {
			m.statusMsg = "Invalid SSH port number"
			return m, nil
		}
		if name == "" || apiURL == "" || tokenID == "" ||
			tokenSecret == "" || sshHost == "" ||
			sshUser == "" || sshKeyPath == "" {
			m.statusMsg = "All fields are required"
			return m, nil
		}
		inst := &models.ProxmoxInstance{
			Name:           name,
			APIURL:         apiURL,
			APITokenID:     tokenID,
			APITokenSecret: tokenSecret,
			SSHHost:        sshHost,
			SSHPort:        sshPort,
			SSHUser:        sshUser,
			SSHKeyPath:     sshKeyPath,
		}
		cmd := m.addInstance(inst)
		return m, cmd

	case viewClients:
		name := strings.TrimSpace(m.inputs[0].Value())
		pubKey := strings.TrimSpace(m.inputs[1].Value())
		if name == "" || pubKey == "" {
			m.statusMsg = "Name and public key are required"
			return m, nil
		}
		cmd := m.addClient(name, pubKey)
		return m, cmd

	case viewGroups:
		name := strings.TrimSpace(m.inputs[0].Value())
		if name == "" {
			m.statusMsg = "Group name is required"
			return m, nil
		}
		cmd := m.addGroup(name)
		return m, cmd

	case viewAdminKeys:
		pubKey := strings.TrimSpace(m.inputs[0].Value())
		if pubKey == "" {
			m.statusMsg = "Public key is required"
			return m, nil
		}
		cmd := m.addAdminKey(pubKey)
		return m, cmd

	case viewAccessRules:
		ruleType := strings.TrimSpace(strings.ToLower(m.inputs[0].Value()))
		subjectStr := strings.TrimSpace(m.inputs[1].Value())
		guestStr := strings.TrimSpace(m.inputs[2].Value())
		if ruleType != ruleTypeClient && ruleType != ruleTypeGroup {
			m.statusMsg = "Type must be 'client' or 'group'"
			return m, nil
		}
		subjectID, err := strconv.ParseInt(subjectStr, 10, 64)
		if err != nil {
			m.statusMsg = "Invalid Subject ID"
			return m, nil
		}
		guestID, err := strconv.ParseInt(guestStr, 10, 64)
		if err != nil {
			m.statusMsg = "Invalid Guest ID"
			return m, nil
		}
		cmd := m.addAccessRule(models.RuleType(ruleType), subjectID, guestID)
		return m, cmd

	case viewDefaultPolicy:
		entryType := strings.TrimSpace(strings.ToLower(m.inputs[0].Value()))
		idStr := strings.TrimSpace(m.inputs[1].Value())
		if entryType != ruleTypeClient && entryType != ruleTypeGroup {
			m.statusMsg = "Type must be 'client' or 'group'"
			return m, nil
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			m.statusMsg = "Invalid ID"
			return m, nil
		}
		cmd := m.addPolicyEntry(entryType, id)
		return m, cmd
	default:
	}

	return m, nil
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

//nolint:gocognit // switch over all view states requires branching
func (m *Model) deleteSelected() (tea.Model, tea.Cmd) {
	//nolint:exhaustive // only list views support delete
	switch m.state {
	case viewInstances:
		if m.cursor >= len(m.instances) {
			return m, nil
		}
		id := m.instances[m.cursor].ID
		return m, func() tea.Msg {
			if err := m.repo.RemoveProxmoxInstance(m.ctx, id); err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}

	case viewClients:
		if m.cursor >= len(m.clients) {
			return m, nil
		}
		id := m.clients[m.cursor].ID
		return m, func() tea.Msg {
			if err := m.repo.RemoveClient(m.ctx, id); err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}

	case viewGroups:
		if m.cursor >= len(m.groups) {
			return m, nil
		}
		id := m.groups[m.cursor].ID
		return m, func() tea.Msg {
			if err := m.repo.RemoveGroup(m.ctx, id); err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}

	case viewAdminKeys:
		if m.cursor >= len(m.adminKeys) {
			return m, nil
		}
		key := m.adminKeys[m.cursor]
		return m, func() tea.Msg {
			if err := m.repo.RemoveAdminKey(m.ctx, key); err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}

	case viewAccessRules:
		if m.cursor >= len(m.accessRules) {
			return m, nil
		}
		rule := m.accessRules[m.cursor]
		return m, func() tea.Msg {
			var err error
			switch rule.Type {
			case models.RuleClient:
				err = m.repo.RevokeClientAccess(m.ctx, rule.SubjectID, rule.GuestID)
			case models.RuleGroup:
				err = m.repo.RevokeGroupAccess(m.ctx, rule.SubjectID, rule.GuestID)
			}
			if err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}

	case viewDefaultPolicy:
		if m.cursor >= len(m.policyEntries) || m.defaultPolicy == nil {
			return m, nil
		}
		entry := m.policyEntries[m.cursor]
		policy := m.defaultPolicy
		return m, func() tea.Msg {
			updated := &models.DefaultAccessPolicy{
				AuthorizedClientIDs: copyInt64Slice(policy.AuthorizedClientIDs),
				AuthorizedGroupIDs:  copyInt64Slice(policy.AuthorizedGroupIDs),
			}
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) != 2 {
				return errMsg{fmt.Errorf("invalid entry: %s", entry)}
			}
			id, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return errMsg{err}
			}
			switch parts[0] {
			case ruleTypeClient:
				updated.AuthorizedClientIDs = removeInt64(updated.AuthorizedClientIDs, id)
			case ruleTypeGroup:
				updated.AuthorizedGroupIDs = removeInt64(updated.AuthorizedGroupIDs, id)
			}
			if err := m.repo.SetDefaultPolicy(m.ctx, updated); err != nil {
				return errMsg{err}
			}
			return doneMsg{}
		}
	default:
	}

	return m, nil
}

// ---------------------------------------------------------------------------
// DB command helpers (return tea.Cmd)
// ---------------------------------------------------------------------------

func (m *Model) fetchInstances() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListProxmoxInstances(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return instancesMsg(list)
	}
}

func (m *Model) fetchGuests() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListGuests(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return guestsMsg(list)
	}
}

func (m *Model) fetchClients() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListClients(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return clientsMsg(list)
	}
}

func (m *Model) fetchGroups() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListGroups(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return groupsMsg(list)
	}
}

func (m *Model) fetchAdminKeys() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListAdminKeys(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return adminKeysMsg(list)
	}
}

func (m *Model) fetchAccessRules() tea.Cmd {
	return func() tea.Msg {
		list, err := m.repo.ListAccessRules(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return accessRulesMsg(list)
	}
}

func (m *Model) fetchDefaultPolicy() tea.Cmd {
	return func() tea.Msg {
		policy, err := m.repo.GetDefaultPolicy(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		return defaultPolicyMsg(policy)
	}
}

func (m *Model) addInstance(inst *models.ProxmoxInstance) tea.Cmd {
	return func() tea.Msg {
		if err := m.repo.AddProxmoxInstance(m.ctx, inst); err != nil {
			return errMsg{err}
		}

		// Re-read instances to get the assigned ID.
		instances, err := m.repo.ListProxmoxInstances(m.ctx)
		if err != nil {
			return errMsg{err}
		}
		var added *models.ProxmoxInstance
		for _, i := range instances {
			if i.Name == inst.Name {
				added = i
			}
		}
		if added == nil {
			return doneMsg{}
		}

		// Run discovery on the new instance so guests appear immediately.
		if m.discovererFactory != nil {
			discoverer := m.discovererFactory(added)
			guests, err := discoverer.DiscoverGuests(m.ctx)
			if err != nil {
				// Non-fatal — instance was added, discovery failed.
				return doneMsg{}
			}
			for _, g := range guests {
				g.InstanceID = added.ID
				_ = m.repo.UpsertGuest(m.ctx, g)
			}
		}

		return doneMsg{}
	}
}

func (m *Model) addClient(name, pubKey string) tea.Cmd {
	return func() tea.Msg {
		c := &models.Client{Name: name, PublicKeys: []string{pubKey}}
		if err := m.repo.AddClient(m.ctx, c); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *Model) addGroup(name string) tea.Cmd {
	return func() tea.Msg {
		g := &models.Group{Name: name}
		if err := m.repo.AddGroup(m.ctx, g); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *Model) addAdminKey(pubKey string) tea.Cmd {
	return func() tea.Msg {
		if err := m.repo.AddAdminKey(m.ctx, pubKey); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *Model) addAccessRule(ruleType models.RuleType, subjectID, guestID int64) tea.Cmd {
	return func() tea.Msg {
		var err error
		switch ruleType {
		case models.RuleClient:
			err = m.repo.GrantClientAccess(m.ctx, subjectID, []int64{guestID})
		case models.RuleGroup:
			err = m.repo.GrantGroupAccess(m.ctx, subjectID, []int64{guestID})
		}
		if err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *Model) addPolicyEntry(entryType string, id int64) tea.Cmd {
	policy := m.defaultPolicy
	return func() tea.Msg {
		updated := &models.DefaultAccessPolicy{}
		if policy != nil {
			updated.AuthorizedClientIDs = copyInt64Slice(policy.AuthorizedClientIDs)
			updated.AuthorizedGroupIDs = copyInt64Slice(policy.AuthorizedGroupIDs)
		}
		switch entryType {
		case ruleTypeClient:
			updated.AuthorizedClientIDs = append(updated.AuthorizedClientIDs, id)
		case ruleTypeGroup:
			updated.AuthorizedGroupIDs = append(updated.AuthorizedGroupIDs, id)
		}
		if err := m.repo.SetDefaultPolicy(m.ctx, updated); err != nil {
			return errMsg{err}
		}
		return doneMsg{}
	}
}

func (m *Model) refreshCurrent() tea.Cmd {
	//nolint:exhaustive // input sub-states don't refresh
	switch m.state {
	case viewInstances:
		return m.fetchInstances()
	case viewGuests:
		return m.fetchGuests()
	case viewClients:
		return m.fetchClients()
	case viewGroups:
		return m.fetchGroups()
	case viewAdminKeys:
		return m.fetchAdminKeys()
	case viewAccessRules:
		return m.fetchAccessRules()
	case viewDefaultPolicy:
		return m.fetchDefaultPolicy()
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

//nolint:gocritic // required by tea.Model interface
func (m Model) View() string {
	var b strings.Builder

	switch m.state {
	case viewMenu:
		m.viewMenu(&b)
	case viewInstances:
		m.viewInstances(&b)
	case viewGuests:
		m.viewGuests(&b)
	case viewClients:
		m.viewClients(&b)
	case viewGroups:
		m.viewGroups(&b)
	case viewAccessRules:
		m.viewAccessRules(&b)
	case viewDefaultPolicy:
		m.viewDefaultPolicy(&b)
	case viewAdminKeys:
		m.viewAdminKeys(&b)
	case viewAddInstance, viewAddClient, viewAddGroup, viewAddAdminKey,
		viewAddAccessRule, viewAddPolicyEntry:
		m.viewInputForm(&b)
	default:
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + errorStyle.Render(m.statusMsg) + "\n")
	}

	return b.String()
}

func (m *Model) viewMenu(b *strings.Builder) {
	b.WriteString(titleStyle.Render("ProxPass Admin Console") + "\n\n")
	for i, item := range menuItems {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		b.WriteString(cursor + style.Render(item) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("j/k or ↑/↓: navigate • enter: select • q: quit") + "\n")
}

func (m *Model) viewInstances(b *strings.Builder) {
	b.WriteString(titleStyle.Render("Proxmox Instances") + "\n\n")
	if len(m.instances) == 0 {
		b.WriteString("  (none)\n")
	}
	for i, inst := range m.instances {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		line := fmt.Sprintf("[%d] %s", inst.ID, inst.Name)
		b.WriteString(cursor + style.Render(line) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("a: add • d: delete • esc: back • q: menu") + "\n")
}

func (m *Model) viewGuests(b *strings.Builder) {
	b.WriteString(titleStyle.Render("Guests (discovered)") + "\n\n")
	if len(m.guests) == 0 {
		b.WriteString("  (none)\n")
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-6s %-6s %-24s %-10s %s", "ID", "Type", "Name", "Status", "VMID")) + "\n")
	for i, g := range m.guests {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		line := fmt.Sprintf("%-6d %-6s %-24s %-10s %d", g.ID, g.Type, g.Name, g.Status, g.ProxmoxID)
		b.WriteString(cursor + style.Render(line) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("enter: connect • esc: back • q: menu") + "\n")
}

// viewEntityList is a shared helper for rendering simple entity lists (clients, groups, etc.).
func (m *Model) viewEntityList(b *strings.Builder, title string, items []string, helpText string) {
	b.WriteString(titleStyle.Render(title) + "\n\n")
	if len(items) == 0 {
		b.WriteString("  (none)\n")
	}
	for i, item := range items {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		b.WriteString(cursor + style.Render(item) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render(helpText) + "\n")
}

func (m *Model) viewClients(b *strings.Builder) {
	items := make([]string, len(m.clients))
	for i, c := range m.clients {
		items[i] = fmt.Sprintf("[%d] %s (%d key(s))", c.ID, c.Name, len(c.PublicKeys))
	}
	m.viewEntityList(b, "Clients", items, "a: add • d: delete • esc: back • q: menu")
}

func (m *Model) viewGroups(b *strings.Builder) {
	items := make([]string, len(m.groups))
	for i, g := range m.groups {
		items[i] = fmt.Sprintf("[%d] %s (%d member(s))", g.ID, g.Name, len(g.ClientIDs))
	}
	m.viewEntityList(b, "Groups", items, "a: add • d: delete • esc: back • q: menu")
}

func (m *Model) viewAccessRules(b *strings.Builder) {
	b.WriteString(titleStyle.Render("Access Rules") + "\n\n")
	if len(m.accessRules) == 0 {
		b.WriteString("  (none)\n")
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-6s %-10s %-12s %s", "ID", "Type", "Subject ID", "Guest ID")) + "\n")
	for i, r := range m.accessRules {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		line := fmt.Sprintf("%-6d %-10s %-12d %d", r.ID, r.Type, r.SubjectID, r.GuestID)
		b.WriteString(cursor + style.Render(line) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("a: add • d: delete • esc: back • q: menu") + "\n")
}

func (m *Model) viewDefaultPolicy(b *strings.Builder) {
	b.WriteString(titleStyle.Render("Default Policy") + "\n\n")
	if len(m.policyEntries) == 0 {
		b.WriteString("  (no entries)\n")
	}
	for i, entry := range m.policyEntries {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		b.WriteString(cursor + style.Render(entry) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("a: add • d: delete • esc: back • q: menu") + "\n")
}

func (m *Model) viewAdminKeys(b *strings.Builder) {
	b.WriteString(titleStyle.Render("Admin Keys") + "\n\n")
	if len(m.adminKeys) == 0 {
		b.WriteString("  (none)\n")
	}
	for i, key := range m.adminKeys {
		cursor := "  "
		style := normalStyle
		if i == m.cursor {
			cursor = "> "
			style = selectedStyle
		}
		display := key
		if len(display) > 60 {
			display = display[:57] + "..."
		}
		b.WriteString(cursor + style.Render(display) + "\n")
	}
	b.WriteString("\n" + helpStyle.Render("a: add • d: delete • esc: back • q: menu") + "\n")
}

func (m *Model) viewInputForm(b *strings.Builder) {
	var title string
	//nolint:exhaustive // only input sub-states are rendered here
	switch m.state {
	case viewAddInstance:
		title = "Add Proxmox Instance"
	case viewAddClient:
		title = "Add Client"
	case viewAddGroup:
		title = "Add Group"
	case viewAddAdminKey:
		title = "Add Admin Key"
	case viewAddAccessRule:
		title = "Add Access Rule"
	case viewAddPolicyEntry:
		title = "Add Policy Entry"
	default:
	}
	b.WriteString(titleStyle.Render(title) + "\n\n")

	for i := range m.inputs {
		label := m.inputs[i].Placeholder
		if i == m.inputStep {
			b.WriteString(selectedStyle.Render(label+": ") + m.inputs[i].View() + "\n")
		} else {
			val := m.inputs[i].Value()
			if val == "" {
				val = "(empty)"
			}
			b.WriteString(normalStyle.Render(label+": "+val) + "\n")
		}
	}

	b.WriteString("\n" + helpStyle.Render("enter: next/submit • esc: cancel") + "\n")
}

// ---------------------------------------------------------------------------
// RunTUI — entry point for SSH sessions
// ---------------------------------------------------------------------------

// RunTUI starts the admin TUI with custom input/output streams.
// This is designed to be called from the SSH server for admin sessions.
func RunTUI(repo db.Repository, input io.Reader, output io.Writer) error {
	m := NewModel(repo, nil)
	p := tea.NewProgram(m, tea.WithInput(input), tea.WithOutput(output), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildPolicyEntries(policy *models.DefaultAccessPolicy) []string {
	if policy == nil {
		return nil
	}
	var entries []string
	for _, id := range policy.AuthorizedClientIDs {
		entries = append(entries, fmt.Sprintf("client:%d", id))
	}
	for _, id := range policy.AuthorizedGroupIDs {
		entries = append(entries, fmt.Sprintf("group:%d", id))
	}
	return entries
}

func copyInt64Slice(src []int64) []int64 {
	if src == nil {
		return nil
	}
	dst := make([]int64, len(src))
	copy(dst, src)
	return dst
}

func removeInt64(slice []int64, val int64) []int64 {
	result := make([]int64, 0, len(slice))
	for _, v := range slice {
		if v != val {
			result = append(result, v)
		}
	}
	return result
}
