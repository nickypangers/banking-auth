package domain

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/nickypangers/banking-lib/errs"
	"github.com/nickypangers/banking-lib/logger"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

type AuthRepository interface {
	ById(username, password string) (*Login, *errs.AppError)
}

func (d AuthRepositoryDb) ById(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := "select username, u.customer_id, role, GROUP_CONCAT(a.account_id) as account_numbers from users u left join accounts a on a.customer_id = u.customer_id where username = ? and password = ?;"
	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")

		} else {
			logger.Error("Error while verifying login request rom database: " + err.Error())
			return nil, errs.NewUnexpectedNotFoundError("unexpected database error")
		}
	}
	return &login, nil
}

func NewAuthRepositoryDb(client *sqlx.DB) AuthRepository {
	return AuthRepositoryDb{client: client}
}
