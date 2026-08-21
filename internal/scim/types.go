// Package scim implements a SCIM 2.0 (RFC 7643 / RFC 7644) server for the
// /v2/Users and /v2/Groups endpoints, backed by internal/store.
package scim

const (
	SchemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResp   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

// Name mirrors the SCIM "name" complex attribute.
type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

// Email mirrors one entry of the SCIM "emails" multi-valued attribute.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Version      string `json:"version,omitempty"`
	Location     string `json:"location,omitempty"`
}

// EnterpriseUser mirrors the widely-deployed enterprise User extension,
// which is where "department" lives — Okta/Entra/Ping all send it here.
type EnterpriseUser struct {
	Department string `json:"department,omitempty"`
	Manager    *struct {
		Value string `json:"value,omitempty"`
	} `json:"manager,omitempty"`
}

// UserResource is the wire representation of a SCIM User.
type UserResource struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	Name        *Name           `json:"name,omitempty"`
	DisplayName string          `json:"displayName,omitempty"`
	Emails      []Email         `json:"emails,omitempty"`
	Active      *bool           `json:"active,omitempty"`
	Enterprise  *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta        *Meta           `json:"meta,omitempty"`
}

type GroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type GroupResource struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id,omitempty"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []GroupMember `json:"members,omitempty"`
	Meta        *Meta         `json:"meta,omitempty"`
}

type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Resources    []any    `json:"Resources"`
}

type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// PatchOp is one operation within a SCIM PATCH request body (RFC 7644 §3.5.2).
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}
