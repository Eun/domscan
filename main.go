package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/signal"
	"time"

	"net"

	"os"

	"strconv"
	"strings"

	"path"

	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/asaskevich/govalidator"
)

const APPNAME = "domscan"
const VERSION = "1.0.1"

var host string

var startIPRange = flag.String("start", "0.0.0.0", "")
var endIPRange = flag.String("end", "255.255.255.255", "")
var scanPrivateIPS = flag.Bool("private", false, "")
var stopOnFirst = flag.Bool("stop", true, "")
var parallelTasks = flag.Int("tasks", 10, "")
var useHTTPS = flag.Bool("https", false, "")
var usePath = flag.String("path", "/", "")
var timeOutDuration = flag.String("timeout", "1s", "")
var useOutAddr = flag.String("localaddr", "", "")
var useCompare = flag.String("compare", "title", "")
var useragent = flag.String("useragent", "", "")

var found_addr []string
var mutex sync.RWMutex

var timeout time.Duration
var outAddr net.IP

var logger = log.New(os.Stdout, "", log.LstdFlags)

var currentWorkers = 0
var scannedHosts uint64 = 0

var startTime int64

func isPrivateIP(ip [4]int16) bool {
	if *scanPrivateIPS == false {

		if ip[0] == 10 {
			return true
		} else if ip[0] == 192 && ip[1] == 168 {
			return true
		} else if ip[0] == 172 && ip[1] >= 16 && ip[1] < 32 {
			return true
		}
	}

	return false
}

var sleepDuration, _ = time.ParseDuration("100ms")

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.93 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36",
	"Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2309.372 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1866.237 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/4E423F",
	"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36",
	"Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
	"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
	"Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0",
	"Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:27.0) Gecko/20121011 Firefox/27.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0",
	"Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/22.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0",
	"Mozilla/5.0 (Microsoft Windows NT 6.2.9200.0); rv:22.0) Gecko/20130405 Firefox/22.0",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1",
	"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:21.0.0) Gecko/20121011 Firefox/21.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.2; WOW64; rv:21.0) Gecko/20130514 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.2; rv:21.0) Gecko/20130326 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130331 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130330 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130401 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20130328 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130401 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20130331 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Windows NT 5.0; rv:21.0) Gecko/20100101 Firefox/21.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0",
}

func getUserAgent() string {
	if useragent != nil && len(*useragent) > 0 {
		return *useragent
	}
	return userAgents[rand.Intn(len(userAgents))]
}

func doRequst(addr, host string) (*goquery.Document, error) {
	var err error
	var request *http.Request
	var response *http.Response
	request, err = http.NewRequest("GET", buildURL(addr), nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				LocalAddr: &net.TCPAddr{IP: outAddr},
				Resolver:  net.DefaultResolver,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, ServerName: host},
		},
	}

	request.Host = host
	request.Header.Set("User-Agent", getUserAgent())

	response, err = client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return goquery.NewDocumentFromReader(response.Body)
}

func isHostSite(orgDoc *goquery.Document, doc *goquery.Document) bool {
	if orgDoc.Find(*useCompare).Text() == doc.Find(*useCompare).Text() {
		return true
	}
	return false
}

func checkHost(orgDoc *goquery.Document, addr, host string) (bool, error) {
	doc, err := doRequst(addr, host)
	if err != nil {
		return false, err
	}

	if isHostSite(orgDoc, doc) {
		return true, nil
	}

	return false, nil
}

func buildIP(ip [4]int16) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func buildURL(str string) string {
	if *useHTTPS == true {
		return fmt.Sprintf("https://%s%s", str, *usePath)
	}
	return fmt.Sprintf("http://%s%s", str, *usePath)
}

func worker(ip string, orgDoc *goquery.Document, host string) {
	os.Stdout.WriteString(fmt.Sprintf("\r%s", ip))
	eq, _ := checkHost(orgDoc, ip, host)
	if eq == true {
		logger.Printf("Found Host (%s) on '%s'", host, ip)
		mutex.Lock()
		found_addr = append(found_addr, ip)
		mutex.Unlock()
		if *stopOnFirst == true {
			printResults()
			os.Exit(1)
		}
	}
	mutex.Lock()
	currentWorkers--
	mutex.Unlock()

}

func parseIP(str string) (ip [4]int16, err error) {
	parts := strings.Split(str, ".")
	if len(parts) != 4 {
		return ip, fmt.Errorf("Invalid IP")
	}
	for i := 0; i < 4; i++ {
		s, err := strconv.Atoi(parts[i])
		if err != nil {
			return ip, fmt.Errorf("Invalid IP")
		}
		ip[i] = int16(s)
	}
	return ip, nil
}

func notOwnIP(ip4addrs [][4]int16, ip [4]int16) bool {

	for i := len(ip4addrs) - 1; i >= 0; i-- {
		ownIP := true

		for j := 0; j < 4; j++ {
			if ip4addrs[i][j] != ip[j] {
				ownIP = false
				break
			}
		}
		if ownIP == true {
			return false
		}
	}
	return true
}

func printResults() {
	total := time.Now().Unix() - startTime
	fmt.Printf("Total Time: %02d:%02d:%02d\n", total/3600, total/60%60, total%60)
	fmt.Printf("Scanned %d hosts & found %d addr for %s", scannedHosts, len(found_addr), host)
	if len(found_addr) > 0 {
		fmt.Printf(":")
	}
	fmt.Printf("\n")
	for _, a := range found_addr {
		fmt.Printf("%s\n", a)
	}

}

func addToWorker(ip string, orgDoc *goquery.Document, host string) {
	for {
		mutex.Lock()
		b := currentWorkers >= *parallelTasks
		mutex.Unlock()
		if b {
			time.Sleep(sleepDuration)
		} else {
			break
		}
	}
	mutex.Lock()
	currentWorkers++
	mutex.Unlock()
	scannedHosts++
	go worker(ip, orgDoc, host)
}

func waitForWorkers() {
	for currentWorkers >= *parallelTasks {
		time.Sleep(sleepDuration)
	}
}

func scan(host string, startIP [4]int16, endIP [4]int16) error {

	var orgDoc *goquery.Document
	addrs, err := net.LookupHost(host)
	if err != nil {
		return err
	}

	if len(addrs) == 0 {
		return fmt.Errorf("No addrs for %s", host)
	}

	var ip4addrs [][4]int16

	var ip [4]int16
	for _, a := range addrs {
		if govalidator.IsIPv4(a) {
			ip, err = parseIP(a)
			if err != nil {
				continue
			}
			ip4addrs = append(ip4addrs, ip)
		}
	}
	if len(ip4addrs) == 0 {
		return fmt.Errorf("No IPv4 addrs for %s", host)
	}

	logger.Printf("Performing initial request...\n")
	orgDoc, err = doRequst(buildIP(ip4addrs[0]), host)
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)

	go func() {
		<-sigs
		logger.Println("ABORTING!")
		printResults()
		os.Exit(1)
	}()

	logger.Printf("Scanning...\n")
	startTime = time.Now().Unix()
	for startIP[0] <= endIP[0] {
		for startIP[1] <= endIP[1] {
			for startIP[2] <= endIP[2] {
				for startIP[3] <= endIP[3] {
					if !isPrivateIP(startIP) {
						if notOwnIP(ip4addrs, startIP) {
							addToWorker(buildIP(startIP), orgDoc, host)
						}
					}
					startIP[3]++
				}
				startIP[2]++
				startIP[3] = 0
			}
			startIP[1]++
			startIP[2] = 0
		}
		startIP[0]++
		startIP[1] = 0
	}

	waitForWorkers()
	return nil
}

func main() {
	flag.Parse()

	args := flag.Args()
	var err error
	if len(args) == 0 || len(args[0]) <= 0 {
		fmt.Printf("usage: %s <options> host\n", path.Base(os.Args[0]))
		fmt.Println("    Options:")
		fmt.Println("    start=0.0.0.0              scan from this ip range")
		fmt.Println("    end=255.255.255.255        stop the scan at this ip range")
		fmt.Println("    private=false              scan private ip addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)")
		fmt.Println("    stop=true                  stop on first match")
		fmt.Println("    tasks=10                   parallel tasks to use")
		fmt.Println("    https=false                use https instead of http")
		fmt.Println("    path=/                     path to use for compare")
		fmt.Println("    timeout=1s                 timeout for hosts")
		fmt.Println("    localaddr=                 local address to bind to (leave empty for default)")
		fmt.Println("    compare=title+favicon      Compare method (is a html document equal to another) (possible values: title, favicon; combine with +)")
		fmt.Printf("\n\n%s %s\n", APPNAME, VERSION)
		os.Exit(1)
	}
	var startIP [4]int16
	var endIP [4]int16
	startIP, err = parseIP(*startIPRange)
	if err != nil {
		logger.Fatalln(err)
	}
	endIP, err = parseIP(*endIPRange)
	if err != nil {
		logger.Fatalln(err)
	}

	host = args[0]

	timeout, err = time.ParseDuration(*timeOutDuration)
	if err != nil {
		logger.Fatalln(err)
	}

	if useOutAddr != nil && len(*useOutAddr) > 0 {
		var addrs []net.Addr
		addrs, err = net.InterfaceAddrs()
		if err != nil {
			logger.Fatalln(err)
		}

		for i := len(addrs) - 1; i >= 0; i-- {
			switch t := addrs[i].(type) {
			case *net.IPNet:
				if t.IP.To4() != nil {
					if strings.EqualFold(t.IP.String(), *useOutAddr) {
						outAddr = t.IP
					}
				}

			}
		}
		if outAddr == nil {
			fmt.Printf("No interface found with the IPv4 %s\n" + *useOutAddr)
			os.Exit(1)
		}
	}

	os.Stderr.WriteString(fmt.Sprintf("Scan for %s:\n", host))
	os.Stderr.WriteString(fmt.Sprintf("    start=%s\n", buildIP(startIP)))
	os.Stderr.WriteString(fmt.Sprintf("    end=%s\n", buildIP(endIP)))
	os.Stderr.WriteString(fmt.Sprintf("    private=%t\n", *scanPrivateIPS))
	os.Stderr.WriteString(fmt.Sprintf("    stop=%t\n", *stopOnFirst))
	os.Stderr.WriteString(fmt.Sprintf("    tasks=%d\n", *parallelTasks))
	os.Stderr.WriteString(fmt.Sprintf("    https=%t\n", *useHTTPS))
	os.Stderr.WriteString(fmt.Sprintf("    path=%s\n", *usePath))
	os.Stderr.WriteString(fmt.Sprintf("    timeout=%s\n", *timeOutDuration))
	os.Stderr.WriteString(fmt.Sprintf("    localaddr=%s\n", *useOutAddr))
	os.Stderr.WriteString(fmt.Sprintf("    compare=%s\n", *useCompare))

	err = scan(host, startIP, endIP)
	if err != nil {
		logger.Fatalln(err)
	}
}
