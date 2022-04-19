package application

import (
	"fmt"

	"github.com/golang-jwt/jwt"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/infraestructure"
	"github.com/luizarnoldch/disco_centro_lib/errs"
	"github.com/luizarnoldch/disco_centro_lib/logger"
)

type DefaultAuthService struct {
	repo infraestructure.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) ServiceLogin(req domain.LoginRequest)(*domain.LoginResponse, *errs.AppError){
	var appErr *errs.AppError
	var login *domain.Login
	if login, appErr = s.repo.RepoAuthLogin(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}
	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}
	if refreshToken, appErr = s.repo.RepoGenerateSaveRefreshToken(authToken); appErr != nil {
		return nil, appErr
	}
	return &domain.LoginResponse{
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s DefaultAuthService) ServiceVerifyToken(urlParams map[string]string) *errs.AppError{
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			if claims.IsAdminRole(){
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams){
					return errs.NewAuthorizationError("request not verified with the token claims")
				}
			}
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized",claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid Token")
		}
	}
}

func (s DefaultAuthService) ServiceRefreshToken(req domain.RefreshTokenRequest)(*domain.LoginResponse, *errs.AppError){
	if vErr := req.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			var appErr *errs.AppError
			if appErr = s.repo.RepoRefreshToken(req.RefreshToken);
			appErr != nil {
				return nil, appErr
			}
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(req.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &domain.LoginResponse{
				AccessToken: accessToken,
			}, nil
		}
		return nil, errs.NewAuthenticationError("Inavlid Token")
	}
	return nil, errs.NewAuthenticationError("Can't generate a new access Token until the current one expires")
}

func jwtTokenFromString(tokenString string)(*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func (token *jwt.Token)(interface{},error){
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func NewLoginService(repo infraestructure.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}