package api

// The session API's types and server interface are generated from the
// OpenAPI spec so the two cannot drift. Regenerate with `mise run generate`
// after editing api/openapi.yaml; TestGeneratedCodeIsUpToDate fails if the
// checked-in file does not match the spec.
//
// The NSS directory types are deliberately NOT generated -- see types.go.
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config oapi-codegen.yaml ../../api/openapi.yaml
