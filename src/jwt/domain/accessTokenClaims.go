package domain

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type AccessTokenClaims struct {
	Id int64 `json:"id_user"`
	Username string `json:"username_user"`
	Role string `json:"role_user"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsAdminRole() bool {
	return c.Role == "admin"
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:  "refresh_token",
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	idParams, _ := strconv.ParseInt(urlParams["id_user"],10,64)
	if c.Id != idParams {
		return false
	}
	return true
}