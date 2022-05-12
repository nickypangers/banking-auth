package service

import (
	"github.com/golang-jwt/jwt"
	"github.com/nickypangers/banking-auth/domain"
	"github.com/nickypangers/banking-auth/dto"
	"github.com/nickypangers/banking-lib/errs"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, *errs.AppError)
	Verify(map[string]string) (bool, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, *errs.AppError) {
	login, err := s.repo.ById(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	token, err := login.GenerateToken()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s DefaultAuthService) Verify(params map[string]string) (bool, *errs.AppError) {
	token, err := jwt.Parse(params["token"], func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		return false, errs.NewUnexpectedNotFoundError(err.Error())
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		role := claims["role"].(string)

		if role == "user" {
			if claims["customer_id"].(string) != params["customer_id"] {
				return false, errs.NewUnexpectedNotFoundError("customer id does not match")
			}
		}

		isAuthorizedFor := s.rolePermissions.IsAuthorizedFor(role, params["routeName"], params["customer_id"])
		if !isAuthorizedFor {
			return false, errs.NewAuthorizationError("unauthorized")
		}

		return isAuthorizedFor, nil
	}

	return false, errs.NewUnexpectedNotFoundError("invalid token")
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
