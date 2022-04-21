package domain

import (
	"time"

	"github.com/golang-jwt/jwt"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour

type RefreshTokenClaims struct {
	TokenType string `json:"tokenType_usuario"`
	Id        uint64 `json:"id_usuario"`
	Username  string `json:"username_usuario"`
	Name      string `json:"name_usuario"`
	LastName  string `json:"last_name_usuario"`
	Role      string `json:"role_usuario"`
	jwt.StandardClaims
}

func (r RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		Id:       r.Id,
		Username: r.Username,
		Name:     r.Name,
		LastName: r.LastName,
		Role:     r.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
