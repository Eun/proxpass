package cli

const (
	flagFormat          = "format"
	formatJSON          = "json"
	formatPlain         = "plain"
	flagName            = "name"
	flagKey             = "key"
	flagClient          = "client"
	flagGroup           = "group"
	flagGuest           = "guest"
	flagInstance        = "instance"
	cmdAdd              = "add"
	cmdLs               = "ls"
	cmdConnect          = "connect"
	cmdRm               = "rm"
	cmdUpdate           = "update"
	cmdInspect          = "inspect"
	argsNames           = "<name> [<name> ...]"
	usageFormat         = "Output format: plain or json (default: plain)"
	usageClientName     = "Client name"
	usageGroupName      = "Group name"
	usageInstanceTarget = "Proxmox instance name — repeatable; grants a shell on the node itself"
)
