package domain

type LoginRequest struct {
	Username string `json:"username_usuario"`
	Password string `json:"password_usuario"`
}
