package app

import (
	"encoding/json"
	"net/http"

	"github.com/luizarnoldch/disco_centro_auth/src/jwt/application"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_lib/logger"
)

type AuthHandler struct {
	service application.AuthService
}

func (h AuthHandler) NotImplementedHandler(w http.ResponseWriter, r *http.Request){
	writeResponse(w, http.StatusOK, "Handler not implemented...")
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request){
	var loginRequest domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.ServiceLogin(loginRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code,appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK,*token)
		}
	}
}