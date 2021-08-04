package goauth

type Principal struct {
	UserID string   `json:"userId"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Roles  []string `json:"roles"`
}

var Anonymous = Principal{
	UserID: "anonymous",
	Name:   "Anonymous User",
}