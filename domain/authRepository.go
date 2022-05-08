package domain

import (
	"database/sql"
	"errors"
	"log"

	"github.com/jmoiron/sqlx"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (d AuthRepositoryDb) ById(username, password string) (*Login, error) {
	var login Login
	sqlVerify := "select username, u.customer_id, role, GROUP_CONCAT(a.account_id) as account_numbers from users u left join accounts a on a.customer_id = u.customer_id where username = ? and password = ? group by a.customer_id;"
	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("invalid credentials")

		} else {
			log.Println("Error while verifying login request rom database: " + err.Error())
			return nil, errors.New("unexpected database error")
		}
	}
	return &login, nil
}

func NewAuthRepositoryDb(client *sqlx.DB) AuthRepository {
	return AuthRepositoryDb{client: client}
}
