package api

import "proxpass/internal/filter"

// Field maps for the admin list endpoints that filter in memory (the two
// access-rule lists push their filter down to SQL instead). Keys are the JSON
// field names the API exposes; only scalar, non-secret fields are filterable.
// The full operator set is allowed on each (empty AllowedOps). The shared
// param* constants spell the repeated field names once.
//
//nolint:gochecknoglobals // static, read-only field allow-lists
var (
	instanceFilterFields = filter.FieldSpecMap{
		paramID:             {Column: paramID},
		paramName:           {Column: paramName},
		"node":              {Column: "node"},
		"api_url":           {Column: "api_url"},
		"console_transport": {Column: "console_transport"},
		"ssh_host":          {Column: "ssh_host"},
		"ssh_user":          {Column: "ssh_user"},
	}
	clientFilterFields = filter.FieldSpecMap{
		paramID:   {Column: paramID},
		paramName: {Column: paramName},
	}
	groupFilterFields = filter.FieldSpecMap{
		paramID:   {Column: paramID},
		paramName: {Column: paramName},
	}
	guestFilterFields = filter.FieldSpecMap{
		paramID:       {Column: paramID},
		"instance_id": {Column: "instance_id"},
		paramName:     {Column: paramName},
		"proxmox_id":  {Column: "proxmox_id"},
		"status":      {Column: "status"},
		"type":        {Column: "type"},
	}
	settingFilterFields = filter.FieldSpecMap{
		paramKey:   {Column: paramKey},
		paramValue: {Column: paramValue},
	}
)
