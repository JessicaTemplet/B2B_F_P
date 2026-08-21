package scim

import (
	"b2bfp/internal/store"
)

func userLocation(base, id string) string  { return base + "/v2/Users/" + id }
func groupLocation(base, id string) string { return base + "/v2/Groups/" + id }

func toUserResource(u *store.User, base string) UserResource {
	active := u.Active
	r := UserResource{
		Schemas:     []string{SchemaUser, SchemaEnterprise},
		ID:          u.ID,
		ExternalID:  u.ExternalID,
		UserName:    u.UserName,
		DisplayName: u.DisplayName,
		Active:      &active,
		Meta: &Meta{
			ResourceType: "User",
			Created:      u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastModified: u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Version:      versionETag(u.Version),
			Location:     userLocation(base, u.ID),
		},
	}
	if u.GivenName != "" || u.FamilyName != "" {
		r.Name = &Name{GivenName: u.GivenName, FamilyName: u.FamilyName}
	}
	if u.Email != "" {
		r.Emails = []Email{{Value: u.Email, Primary: true, Type: "work"}}
	}
	if u.Department != "" {
		r.Enterprise = &EnterpriseUser{Department: u.Department}
	}
	return r
}

// applyUserResource maps an inbound SCIM UserResource (POST create, or PUT
// replace) onto a store.User. For PUT, dst should already be the existing
// record so untouched internal fields (ID, tenant) survive; for POST, dst is
// a fresh zero-value record.
func applyUserResource(dst *store.User, in *UserResource) {
	dst.ExternalID = in.ExternalID
	dst.UserName = in.UserName
	dst.DisplayName = in.DisplayName
	if in.Name != nil {
		dst.GivenName = in.Name.GivenName
		dst.FamilyName = in.Name.FamilyName
	}
	if in.Active != nil {
		dst.Active = *in.Active
	} else {
		dst.Active = true // SCIM: absent 'active' defaults to true on create
	}
	for _, e := range in.Emails {
		if e.Primary || dst.Email == "" {
			dst.Email = e.Value
		}
	}
	if in.Enterprise != nil {
		dst.Department = in.Enterprise.Department
	}
	if dst.Attributes == nil {
		dst.Attributes = map[string]any{}
	}
}

func versionETag(v int) string {
	const hex = "0123456789abcdef"
	// Cheap, stable per-version opaque ETag; not cryptographic, just unique-per-version.
	n := v
	if n < 0 {
		n = -n
	}
	buf := []byte{'W', '/', '"'}
	if n == 0 {
		buf = append(buf, '0')
	}
	var digits []byte
	for n > 0 {
		digits = append(digits, hex[n%16])
		n /= 16
	}
	for i := len(digits) - 1; i >= 0; i-- {
		buf = append(buf, digits[i])
	}
	buf = append(buf, '"')
	return string(buf)
}

func toGroupResource(g *store.Group, base string) GroupResource {
	r := GroupResource{
		Schemas:     []string{SchemaGroup},
		ID:          g.ID,
		ExternalID:  g.ExternalID,
		DisplayName: g.DisplayName,
		Meta: &Meta{
			ResourceType: "Group",
			Created:      g.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastModified: g.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			Version:      versionETag(g.Version),
			Location:     groupLocation(base, g.ID),
		},
	}
	for _, m := range g.Members {
		r.Members = append(r.Members, GroupMember{Value: m})
	}
	return r
}

func applyGroupResource(dst *store.Group, in *GroupResource) {
	dst.ExternalID = in.ExternalID
	dst.DisplayName = in.DisplayName
	dst.Members = nil
	for _, m := range in.Members {
		dst.Members = append(dst.Members, m.Value)
	}
}
