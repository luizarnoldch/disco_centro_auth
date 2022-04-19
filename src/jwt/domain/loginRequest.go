package domain

type LoginRequest struct {
	Username string `json:"username_user"`
	Password string `json:"password_user"`
}
