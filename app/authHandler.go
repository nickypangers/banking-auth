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
		isAuthorized, err := h.service.Verify(urlParams)
		if err != nil {
			writeResponse(w, http.StatusForbidden, err.AsMessage())
		} else {
			if isAuthorized {
				m := make(map[string]bool)
				m["isAuthorized"] = true
				writeResponse(w, http.StatusOK, m)
				return
			} else {
				writeResponse(w, http.StatusForbidden, err.AsMessage())
			}

		}
	} else {
		writeResponse(w, http.StatusForbidden, "token is required")
	}

	// if token == "" {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	fmt.Fprintf(w, "Token is required")
	// 	return
	// }
	// if routeName == "" {
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	fmt.Fprintf(w, "Route name is required")
	// 	return
	// }
	// m := make(map[string]interface{})
	// isAuthorized, appErr := h.service.Verify(token, routeName, customerId)
	// w.Header().Set("Content-Type", "application/json")
	// if appErr != nil {
	// 	fmt.Println(appErr.AsMessage())
	// }
	// m["isAuthorized"] = isAuthorized
	// json.NewEncoder(w).Encode(m)
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
