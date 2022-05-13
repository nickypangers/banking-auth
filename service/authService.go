package service

import (
	"fmt"

	"github.com/golang-jwt/jwt"
	"github.com/nickypangers/banking-auth/domain"
	"github.com/nickypangers/banking-auth/dto"
	"github.com/nickypangers/banking-lib/errs"
	"github.com/nickypangers/banking-lib/logger"
)

type AuthService interface {
	Login(dto.LoginRequest) (*string, *errs.AppError)
	Verify(map[string]string) *errs.AppError
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

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {

	// token, err := jwt.Parse(params["token"], func(token *jwt.Token) (interface{}, error) {
	// 	return []byte(domain.HMAC_SAMPLE_SECRET), nil
	// })
	// if err != nil {
	// 	return errs.NewUnexpectedNotFoundError(err.Error())
	// }

	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.NewUnexpectedNotFoundError(err.Error())
	}

	if jwtToken.Valid {
		claims := jwtToken.Claims.(*domain.Claims)

		if claims.IsUserRole() {
			if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
				return errs.NewAuthorizationError("request not verified with the token claims")
			}
		}

		isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"], urlParams["customer_id"])
		if !isAuthorized {
			return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
		}
		return nil
	}

	return errs.NewUnexpectedNotFoundError("invalid token")
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}
}
