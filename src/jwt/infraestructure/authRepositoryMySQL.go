package infraestructure

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_lib/errs"
	"github.com/luizarnoldch/disco_centro_lib/logger"
)

type AuthRepositoryMySQL struct {
	client *sqlx.DB
}

func (db AuthRepositoryMySQL) RepoAuthLogin(username string, password string) (*domain.Login, *errs.AppError) {
	var login domain.Login
	sqlVerify := `SELECT username, u.customer_id, role, group_concat(a.								account_id) as account_numbers FROM users u
								LEFT JOIN accounts a ON a.customer_id = u.customer_id
								WHERE username = ? and password = ?
								GROUP BY a.customer_id`
	err := db.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("Invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &login, nil
}

func (db AuthRepositoryMySQL) RepoGenerateSaveRefreshToken(authToken domain.AuthToken) (string, *errs.AppError) {
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken, appErr = authToken.NewRefreshToken(); appErr != nil {
		return "", appErr
	}
	sqlInsert := "INSERT INTO refresh_token_store (refresh_token) values (?)"
	_, err := db.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("Unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected database error")
	}
	return refreshToken, nil
}

func (db AuthRepositoryMySQL) RepoRefreshToken(refreshToken string) *errs.AppError {
	sqlSelect := "SELECT refresh_token FROM refresh_token_store WHERE refresh token = ?"
	var token string
	err := db.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("Refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return nil
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryMySQL {
	return AuthRepositoryMySQL{client}
}
