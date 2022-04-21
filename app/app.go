package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/application"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/domain"
	"github.com/luizarnoldch/disco_centro_auth/src/jwt/infraestructure"
	"github.com/luizarnoldch/disco_centro_lib/logger"
)

func sanityCheck() {
	envProps := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWD",
		"DB_ADDR",
		"DB_PORT",
		"DB_NAME",
	}
	for _, k := range envProps {
		if os.Getenv(k) == "" {
			logger.Fatal(fmt.Sprintf("Environment variable %s not defined. Terminating application...", k))
		}
	}
}

func Start() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env")
	}

	sanityCheck()

	router := mux.NewRouter()

	//estableciendo DB

	dbClient := getDbClient()

	//infra := infraestructure.NewDiscoRepositoryStub()

	infra := infraestructure.NewAuthRepository(dbClient)
	appli := application.NewLoginService(infra, domain.GetRolePermissions())
	auth := AuthHandler{appli}

	router.
		HandleFunc("/api/auth/login", auth.Login).
		Methods(http.MethodPost).
		Name("LoginUser")

	/*there is no register logic*/
	router.
		HandleFunc("/api/auth/register", auth.NotImplementedHandler).
		Methods(http.MethodPost).
		Name("RegisterUser")

	router.
		HandleFunc("/api/auth/refresh", auth.Refresh).
		Methods(http.MethodPost).
		Name("RefreshToken")
	router.
		HandleFunc("/api/auth/verify", auth.Verify).
		Methods(http.MethodGet).
		Name("VerifyToken")

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	logger.Info(fmt.Sprintf("Starting server on %s:%s ...", address, port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router))
}

func getDbClient() *sqlx.DB {
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPasswd, dbAddr, dbPort, dbName)
	client, err := sqlx.Open("mysql", dataSource)
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}
