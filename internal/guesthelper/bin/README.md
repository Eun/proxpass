# Embedded helper binaries

`proxpass-helper`, built for each architecture a Proxmox node can be.

The files checked in here are **placeholders**. Real binaries are staged by
`mise run helpers`, which the image build depends on, and by goreleaser's
`before` hook. `Binary` refuses a placeholder at run time by checking for the
ELF magic, so a misconfigured build fails with a clear message here rather
than as "exec format error" on a Proxmox node.

They are not in `.gitignore`: the placeholders must be committed, because
`//go:embed` fails to compile if a named file is missing, and `go test ./...`
has to work in a fresh checkout.
