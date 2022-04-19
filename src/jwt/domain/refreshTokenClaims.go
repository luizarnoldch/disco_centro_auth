package domain

import (
	"time"

	"github.com/golang-jwt/jwt"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour

type RefreshTokenClaims struct {
	TokenType string `json:"tokenType_user"`
	Username  string `json:"username_user"`
	Role      string `json:"role_user"`
	jwt.StandardClaims
}

func (r RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		Username: r.Username,
		Role:     r.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
