package service

import (
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/nickypangers/banking-auth/domain"
	"github.com/nickypangers/banking-auth/dto"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, error)
	Verify(string, string) (bool, error)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, error) {
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

func (s DefaultAuthService) Verify(tokenString, routeName string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		role := claims["role"].(string)
		isAuthorizedFor := s.rolePermissions.IsAuthorizedFor(role, routeName)
		if !isAuthorizedFor {
			return false, errors.New("unauthorized")
		}
		return isAuthorizedFor, nil
	}

	return false, errors.New("invalid token")
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
