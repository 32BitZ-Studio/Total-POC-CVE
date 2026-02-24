package main

import (
    "fmt"
    "time"

    "github.com/dgrijalva/jwt-go"
)

func main() {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "iss": "kiali-login",
        "exp": time.Now().Add(time.Hour * 24).Unix(),
        "sub": "admin",
    })

    tokenString, err := token.SignedString([]byte("kiali"))
    if err != nil {
        fmt.Println(err)
    }
    fmt.Println(tokenString)
}
