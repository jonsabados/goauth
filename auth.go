package goauth

const AnonymousUserID = "anonymous"

type Principal struct {
	UserID string   `json:"userId"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"`
}

func (p Principal) IsAnonymous() bool {
	return p.UserID == AnonymousUserID
}

var Anonymous = Principal{
	UserID: AnonymousUserID,
	Name:   "Anonymous User",
}
