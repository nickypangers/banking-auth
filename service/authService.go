package service

import (
	"github.com/nickypangers/banking-auth/domain"
	"github.com/nickypangers/banking-auth/dto"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, error)
}

type DefaultAuthService struct {
	repo domain.AuthRepository
	// rolePermission domain.rolePermission
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

func NewLoginService(repo domain.AuthRepository) DefaultAuthService {
	return DefaultAuthService{repo}
}
