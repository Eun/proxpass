package api

import (
	"context"
	"strings"

	"proxpass/internal/models"
)

// The activity-log recorder.
//
// Every audited action calls record() with its EventID, the resolved actor,
// and the structured params the UI needs. Recording is BEST-EFFORT: a failed
// audit write is logged and swallowed, never surfaced to the caller -- auditing
// an action must not be able to fail the action itself. When activity logging
// is disabled (retention == 0), record() is a no-op and nothing is written.
//
// The DB write happens here, in serve, which is the only process that holds the
// database; sessions report what they did over the loopback API and this is
// where those reports (and the admin mutations) become rows.

// maxActivityCommand bounds the command text stored for a command event, so a
// client cannot write an unbounded blob into the log. Mirrors the session's own
// maxLoggedCommand.
const maxActivityCommand = 200

// Activity param keys, named so the same JSON key is not repeated across the
// instrumented handlers (goconst). The UI's formatEvent reads these.
const (
	paramName        = "name"
	paramID          = "id"
	paramKey         = "key"
	paramSubjectID   = "subject_id"
	paramSubjectKind = "subject_kind"
)

// activityEnabled reports whether events should be recorded. Disabled when the
// retention is zero (the "off" setting) -- then record() writes nothing.
func (h *SessionHandler) activityEnabled() bool {
	return h.activityRetention > 0
}

// record appends one activity event, best-effort. A nil/empty params is stored
// as an empty object by the repo. Errors are logged, not returned.
func (h *SessionHandler) record(ctx context.Context, eventID EventID, actor string, params map[string]any) {
	if !h.activityEnabled() {
		return
	}
	event := &models.ActivityEvent{
		EventID:    string(eventID),
		Actor:      actor,
		OccurredAt: h.now(),
		Params:     params,
	}
	if err := h.repo.AddActivityEvent(ctx, event); err != nil {
		h.logger.Printf("activity: recording %s failed: %v", eventID, err)
	}
}

// actorName resolves the caller's identity name for the audit actor, best-effort.
// Admin handlers have already passed gateAdmin, so the caller is authenticated;
// if the lookup somehow fails here it falls back to a non-empty placeholder
// rather than recording an empty actor.
func (h *SessionHandler) actorName(ctx context.Context) string {
	identity, err := h.callerIdentity(ctx)
	if err != nil || identity == nil || identity.IdentityName == "" {
		return "unknown"
	}
	return identity.IdentityName
}

// recordAdmin records an admin-mutation event under the caller's identity.
func (h *SessionHandler) recordAdmin(ctx context.Context, eventID EventID, params map[string]any) {
	h.record(ctx, eventID, h.actorName(ctx), params)
}

// boundedCommand trims and length-caps a client command for the activity log.
func boundedCommand(cmd string) string {
	if len(cmd) > maxActivityCommand {
		return cmd[:maxActivityCommand] + "…"
	}
	return cmd
}

// adminKeySummary renders an admin public key for the activity log without
// storing the whole blob: the comment (if any) plus a short prefix of the key
// material is enough to tell which key an entry refers to. A public key is not
// a secret, but the full line is long and noisy in a log.
func adminKeySummary(pubKey string) string {
	fields := strings.Fields(strings.TrimSpace(pubKey))
	if len(fields) == 0 {
		return ""
	}
	// fields: [type base64 [comment...]]
	summary := fields[0]
	if len(fields) >= 2 {
		material := fields[1]
		if len(material) > 12 {
			material = material[:12] + "…"
		}
		summary += " " + material
	}
	if len(fields) >= 3 {
		summary += " " + strings.Join(fields[2:], " ")
	}
	return summary
}

// ListActivity returns a newest-first page of the activity log.
func (h *SessionHandler) ListActivity(
	ctx context.Context, request ListActivityRequestObject,
) (ListActivityResponseObject, error) {
	if denied, ok, err := gateAdmin(ctx, h,
		func(reason string) ListActivityResponseObject {
			return ListActivity401JSONResponse{UnauthorizedJSONResponse{Error: reason}}
		},
		func() ListActivityResponseObject {
			return ListActivity403JSONResponse{ForbiddenJSONResponse{Error: errNotAdminAPI.Error()}}
		},
	); !ok {
		return denied, err
	}

	limit := 100
	if request.Params.Limit != nil && *request.Params.Limit > 0 {
		limit = *request.Params.Limit
	}
	offset := 0
	if request.Params.Offset != nil && *request.Params.Offset > 0 {
		offset = *request.Params.Offset
	}

	events, err := h.repo.ListActivity(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	total, err := h.repo.CountActivity(ctx)
	if err != nil {
		return nil, err
	}

	entries := make([]ActivityEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, toAPIActivityEntry(e))
	}
	return ListActivity200JSONResponse(ActivityPage{
		Entries: entries,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
	}), nil
}

// toAPIActivityEntry maps a stored event to the API type.
func toAPIActivityEntry(e *models.ActivityEvent) ActivityEntry {
	params := e.Params
	if params == nil {
		params = map[string]any{}
	}
	return ActivityEntry{
		ID:         e.ID,
		EventID:    EventID(e.EventID),
		Actor:      e.Actor,
		OccurredAt: e.OccurredAt,
		Params:     params,
	}
}

// ReportSessionActivity records what a session reported it is doing.
//
// The session cannot write the database, so it reports over the loopback API
// and this handler -- running in serve under the caller's own credential --
// resolves the actor, maps the reported kind to an EventID, and records the
// row. The actor is the resolved identity, NEVER the login name the caller
// picked. Always 204: the report is advisory and must not fail the session.
func (h *SessionHandler) ReportSessionActivity(
	ctx context.Context, request ReportSessionActivityRequestObject,
) (ReportSessionActivityResponseObject, error) {
	identity, err := h.callerIdentity(ctx)
	if err != nil {
		reason := authFailureReason(err)
		if reason == "" {
			return nil, err
		}
		return ReportSessionActivity401JSONResponse{
			UnauthorizedJSONResponse: UnauthorizedJSONResponse{Error: reason},
		}, nil
	}
	if request.Body == nil {
		return ReportSessionActivity204Response{}, nil
	}

	eventID, ok := sessionEventID(request.Body.Kind)
	if !ok {
		// An unknown kind is ignored rather than erroring: a newer session
		// reporting a kind this server does not know must not break.
		return ReportSessionActivity204Response{}, nil
	}

	params := map[string]any{}
	if request.Body.Kind == SessionActivityKindCommand && request.Body.Command != nil {
		params["command"] = boundedCommand(*request.Body.Command)
	}
	h.record(ctx, eventID, identity.IdentityName, params)
	return ReportSessionActivity204Response{}, nil
}

// sessionEventID maps a session-reported kind to its EventID.
func sessionEventID(kind SessionActivityReportKind) (EventID, bool) {
	switch kind {
	case SessionActivityKindConsole:
		return EventSessionConsoleOpened, true
	case SessionActivityKindCommand:
		return EventSessionCommandRun, true
	case SessionActivityKindSftp:
		return EventSessionSftpOpened, true
	default:
		return "", false
	}
}
