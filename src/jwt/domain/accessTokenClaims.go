package domain

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type AccessTokenClaims struct {
	Id       uint64 `json:"id_usuario"`
	Username string `json:"username_usuario"`
	Name     string `json:"name_usuario"`
	LastName string `json:"last_name_usuario"`
	Role     string `json:"role_usuario"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsAdminRole() bool {
	return c.Role == "admin"
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType: "refresh_token",
		Id:        c.Id,
		Username:  c.Username,
		Name:      c.Name,
		LastName:  c.LastName,
		Role:      c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	idParams, _ := strconv.ParseUint(urlParams["id_user"], 10, 64)
	if c.Id != idParams {
		return false
	}
	return true
}
