package tweeterclone

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	UsernameMinLength = 2
	PasswordMinLength = 6
)

var emailRegex = regexp.MustCompile(".*@.*")

type AuthService interface {
	Register(ctx context.Context, input RegisterInput) (AuthResponse, error)
}

type AuthResponse struct {
	AccessToken string
	User User
}

type RegisterInput struct {
	Email string
	Username string
	Password string
	ConfirmPasssword string
}

func (in *RegisterInput) Sanitize() {
	in.Email = strings.TrimSpace(in.Email)
	in.Email = strings.ToLower(in.Email)

	in.Username = strings.TrimSpace(in.Username)
}

func (in RegisterInput) Validate() error {
	if(len(in.Username) < UsernameMinLength) {
		return fmt.Errorf("%w: username length is short. Need %d chars", ErrValidation, UsernameMinLength)
	}

	if !emailRegex.MatchString(in.Email) {
		return fmt.Errorf("%w: email not valid", ErrValidation)
	}

	if len(in.Password) < PasswordMinLength {
		return fmt.Errorf("%w: password length is short. Need %d chars", ErrValidation, PasswordMinLength)
	}

	if in.Password != in.ConfirmPasssword {
		return fmt.Errorf("%w: password and confirmPassword is different", ErrValidation)
	}

	return nil
}