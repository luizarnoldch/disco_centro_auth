package domain

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type Login struct {
	Id       uint64 `db:"id_usuario"`
	Username string `db:"username_usuario"`
	Password string `db:"password_usuario"`
	Name     string `db:"name_usuario"`
	LastName string `db:"last_name_usuario"`
	Role     string `db:"role_usuario"`
}

func (l Login) ClaimsForAccessToken() AccessTokenClaims {
	return l.claimsForAdmin()
}

func (l Login) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Username: l.Username,
		Role:     l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
