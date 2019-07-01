package main

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"net/http"
	"time"

	"github.com/imkira/gcp-iap-auth/jwt"
)

var (
	authRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_queries_total",
		Help: "The total number of queries",
	})
	authFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_auth_failures_total",
		Help: "The total number of authentication requests that failed",
	})
	authSuccess = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gcp_iap_proxy_auth_successful_total",
		Help: "The total number of authentication requests that were successful",
	})
)

type userIdentity struct {
	Subject string `json:"sub,omitempty"`
	Email   string `json:"email,omitempty"`
}

func authHandler(res http.ResponseWriter, req *http.Request) {
	authRequests.Inc()

	claims, err := jwt.RequestClaims(req, cfg)
	if err != nil {
		if claims == nil || len(claims.Email) == 0 {
			log.Printf("Failed to authenticate (%v)\n", err)
		} else {
			log.Printf("Failed to authenticate %q (%v)\n", claims.Email, err)
		}

		authFailures.Inc()

		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := &userIdentity{
		Subject: claims.Subject,
		Email:   claims.Email,
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	log.Printf("Authenticated %q (token expires at %v)\n", user.Email, expiresAt)
	res.WriteHeader(http.StatusOK)
	json.NewEncoder(res).Encode(user)

	authSuccess.Inc()
}
