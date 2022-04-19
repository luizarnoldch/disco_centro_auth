package infraestructure

import (
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_lib/errs"
)

type AuthRepository interface {
	RepoAuthLogin(string, string) (*domain.Login, *errs.AppError)
	RepoGenerateSaveRefreshToken(domain.AuthToken) (string, *errs.AppError)
	RepoRefreshToken(string) *errs.AppError
}
