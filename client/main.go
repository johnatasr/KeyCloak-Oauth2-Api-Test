package main

import (
	"context"
	"encoding/json"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

var (
	clientId = "app"
	clientSecret = "29827471-6ee5-4e06-af5f-dac926fbc2ea"
)

func main() {
	ctx := context.Background()
	
	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/App")

	if err != nil {
		log.Fatal(err)
	}
	// Padrao do Oauth2
	config := oauth2.Config{
		ClientID: clientId,
		ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/callback",
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	// Validaçao de estado
	state := "magic"

	// Requisicao principal para o login o Keycloack
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	// Validacao de estado e pega o token
	http.HandleFunc("/auth/callback", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(writer, "State did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, request.URL.Query().Get("code"))

		if err != nil {
			http.Error(writer, "Failed to exchange token", http.StatusBadRequest)
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)

		if !ok {
			http.Error(writer, "No id_token", http.StatusBadRequest)
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			RawIDToken string
		}{
			oauth2Token, rawIDToken,
		}

		data, err := json.MarshalIndent(resp, "", "      ")
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		writer.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
