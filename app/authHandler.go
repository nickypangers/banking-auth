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
	token, appErr := h.service.Login(loginRequest)
	if appErr != nil {
		w.WriteHeader(appErr.Code)
		fmt.Fprintf(w, "%s", appErr.AsMessage().Message)
		return
	}
	fmt.Fprintf(w, *token)
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	// token := r.URL.Query().Get("token")
	// routeName := r.URL.Query().Get("routeName")
	// customerId := r.URL.Query().Get("customer_id")
	urlParams := make(map[string]string)

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		err := h.service.Verify(urlParams)
		if err != nil {
			writeResponse(w, http.StatusForbidden, notAuthroizedResponse(err.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, "token is required")
	}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func notAuthroizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}
