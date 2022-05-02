package main

import (
	"fmt"

	"github.com/joho/godotenv"
	"github.com/nickypangers/banking-auth/app"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	app.Start()
}
