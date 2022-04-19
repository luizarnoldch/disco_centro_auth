package application

import (
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_lib/errs"
)

type AuthService interface{
	ServiceLogin(domain.LoginRequest)(*domain.LoginResponse, *errs.AppError)
	ServiceVerifyToken(map[string]string) *errs.AppError
	ServiceRefreshToken(domain.RefreshTokenRequest)(*domain.LoginResponse, *errs.AppError)
}