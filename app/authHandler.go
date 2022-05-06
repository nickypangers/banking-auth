package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/nickypangers/banking-auth/dto"
	service "github.com/nickypangers/banking-auth/service"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := h.service.Login(loginRequest)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "%s", err.Error())
		return
	}
	fmt.Fprintf(w, *token)
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	routeName := r.URL.Query().Get("routeName")

	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Token is required")
		return
	}
	if routeName == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Route name is required")
		return
	}
	m := make(map[string]interface{})
	isAuthorized, err := h.service.Verify(token, routeName)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		fmt.Println(err.Error())
	}
	m["isAuthorized"] = isAuthorized
	json.NewEncoder(w).Encode(m)
}
