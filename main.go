package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	LogFile        string `yaml:"logfile"`
	Bindto         string `yaml:"bindto"`
	HTTPS          bool   `yaml:"https"`
	CertFile       string `yaml:"certfile"`
	KeyFile        string `yaml:"keyfile"`
	SecretToken    string `yaml:"secret_token"`
	RateLimit      bool   `yaml:"rate_limit"`
	Email_from     string `yaml:"email_from"`
	Email_password string `yaml:"email_password"`
	Email_smtpHost string `yaml:"email_smtpHost"`
	Email_smtpPort string `yaml:"email_smtpPort"`

	Projets []Projet `yaml:"projets"`
}
type Projet struct {
	Route     string `yaml:"route"`
	Name      string `yaml:"name"`
	Command   string `yaml:"command"`
	Log2Email string `yaml:"log_to_email"`
}

// UGLY GLOBALS !!!!!!!!!!!!
// BUT don't know how to pass arguments to HandleFunc
var yamlConfig Config
var H2Clog *log.Logger

func main() {
	// if YAML config file can be loaded into global variable 'yamlConfig' 
	if chargeconfig() == true {
		var err error

		// open log file
		logFile, logerr := os.OpenFile(yamlConfig.LogFile, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if logerr != nil {
			log.Fatal(logerr)
		}
		defer logFile.Close()

		H2Clog = log.New(logFile, "", log.LstdFlags)
		H2Clog.Println("Hook2CMD logging started ...")

		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc)
		go signalcatcher(sigc, logFile)

		go ticker()
		
		// we add a handler for each 'Route' for each 'Projets'
		for _, uneconfig := range yamlConfig.Projets {
			http.HandleFunc(uneconfig.Route, hookHandler)
		}
		// start the server
		if yamlConfig.HTTPS == true {
			err = http.ListenAndServeTLS(yamlConfig.Bindto, yamlConfig.CertFile, yamlConfig.KeyFile, nil)
		} else {
			err = http.ListenAndServe(yamlConfig.Bindto, nil)
		}
		H2Clog.Fatal(err)
	} else {
		log.Fatal("No config file specified on command line; Please provide an existing yaml file by using -f option")
	}
}

// parse the YAML config file given in parameter '-f config_file'
func chargeconfig() bool {

	var fileName string

	flag.StringVar(&fileName, "f", "", "YAML file to parse.")
	flag.Parse()

	if fileName == "" {
		return false
	}
	data, err := os.ReadFile(fileName)
	if err != nil {
		return false
	}
	err1 := yaml.Unmarshal(data, &yamlConfig)
	if err1 != nil {
		log.Println("Format YAML incorrect pour le fichier : ", fileName)
		return false
	}
	//fmt.Println(yamlConfig)
	return true
}

// handle a connection  : can handle multiple connection ; this is called as a 'go routine'
func hookHandler(w http.ResponseWriter, r *http.Request) {

	//fmt.Printf("\n%s\n", r) //r.RequestURI)

	// on traite ici le Rate Limiting
	if yamlConfig.RateLimit == true {
		// check IP format and get IP as net.IP
		ip_str, _, iperr := net.SplitHostPort(r.RemoteAddr)
		if iperr != nil {
			h_error(w, "Error : Incorrect HTTP Request RemoteAddr\n", "ERROR : "+r.RemoteAddr+" : Incorrect HTTP Request RemoteAddr, Split", 429)
			return
		}
		ip_B := net.ParseIP(ip_str)
		if ip_B == nil {
			h_error(w, "Error : Incorrect HTTP Request RemoteAddr\n", "ERROR : "+r.RemoteAddr+" : Incorrect HTTP Request RemoteAddr, Parse", 429)
			return
		}
		if RateLimit(ip_B) == false {
			h_error(w, "Error : You have been Rate Limited\n", "ERROR : "+ip_B.String()+" : You have been Rate Limited", 429)
			//fmt.Printf("---% x---\n", ip)
			return
		}
	}

	// we look for GITLAB signature
	if header_token1 := r.Header.Get("X-Gitlab-Token"); header_token1 != "" { 
		if header_token1 != yamlConfig.SecretToken {
			h_error(w, "Error : GitLab Token Verification Failed\n", "ERROR : Bad Token in Gitlab WebHook request", 490)
			return
		}
	// we look for GITHUB signature
	} else if header_token2 := r.Header.Get("X-Hub-Signature-256"); header_token2 != "" { 
		payload, _ := ioutil.ReadAll(r.Body)
		if SignedBy(header_token2, payload) != true {
			h_error(w, "Error : GitHub Token Verification Failed\n", "ERROR : Bad Token in Github WebHook request", 491)
			return
		}
	// we look for Hook2CMD signature
	// exemple usage : curl -H "X-Hook2CMD-Token: PVAfCf73k2G3XXnDP2qXNjnbh843DE/QVUYivoDzy6w=" -X POST https://www.cresi.fr:3000/test
	} else if header_token3 := r.Header.Get("X-Hook2CMD-Token"); header_token3 != "" { 
		if header_token3 != yamlConfig.SecretToken {
			h_error(w, "Error : Hook2CMD Token Verification Failed\n", "ERROR : Bad Token in Hook2CMD request", 492)
			return
		}
	} else {
		h_error(w, "Error : Unidentified WebHook request\n", "ERROR : Unidentified WebHook request", 497)
		return
	}
	http.Error(w, "ok\n", 200)

	go traite(r.RequestURI)

	return
}

// common Handler error func
func h_error(w http.ResponseWriter, e_http string, e_log string, e_code int) {
	time.Sleep(8 * time.Second)  // wait 8 sec to slow down hacking
	http.Error(w, e_http, e_code)
	H2Clog.Println(e_log)
}

// look for Projet associated with the 'Route' 
func traite(route string) {

	var uneconfig Projet
	ok := false

	for _, uneconfig = range yamlConfig.Projets {
		//if ( uneconfig.Name == pushEvent.Project.Name && uneconfig.Route == route ) {}
		if uneconfig.Route == route {
			ok = true
			break
		}
	}
	if ok != true {
		H2Clog.Println("ERROR : No Projet for this Route in config file: ", route)
		return
	}

	runcommand(uneconfig)
}

func runcommand(lp Projet) {
	flock_cmd := "/usr/bin/flock"
	flock_arg1 := "-n"
	flock_arg11 := "-E 222"
	flock_arg2 := "/tmp/" + lp.Name
	flock_arg3 := "-c"
	flock_arg4 := lp.Command + " " + lp.Name
	cmd := exec.Command(flock_cmd, flock_arg1, flock_arg11, flock_arg2, flock_arg3, flock_arg4)
	out, err := cmd.CombinedOutput()
	if err != nil {
		H2Clog.Println("cmd.CombinedOutput() failed with ", err)
		H2Clog.Println("If exit status 222, a previous task ", lp.Name, " is still running")
		out = append(out, "cmd.CombinedOutput() failed with "...)
		out = append(out, err.Error()...)
		out = append(out, "\r\n"...)
		out = append(out, "If exit status 222, a previous task "...)
		out = append(out, lp.Name...)
		out = append(out, " is still running"...)
	} else {
		H2Clog.Println("OK : ", lp.Route, lp.Command, lp.Name)
	}
	//fmt.Printf("combined out:\n%s\n", string(out))
	envoimail(lp, out)
}

func envoimail(lp Projet, message []byte) {
	// Configuration
	from := yamlConfig.Email_from
	password := yamlConfig.Email_password
	dest := strings.Split(lp.Log2Email, ",")
	smtpHost := yamlConfig.Email_smtpHost
	smtpPort := yamlConfig.Email_smtpPort
	msg := []byte("To: ")
	msg = append(msg, lp.Log2Email...) // ... permit adding string to []byte !?!?!?
	msg = append(msg, "\r\n"...)
	msg = append(msg, "Subject: Output de la Route "...)
	msg = append(msg, lp.Route...)
	msg = append(msg, " du projet "...)
	msg = append(msg, lp.Name...)
	msg = append(msg, "\r\n\r\n"...)
	msg = append(msg, message...)
	msg = append(msg, "\r\n"...)

	// Create authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Send actual message
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, dest, msg)
	if err != nil {
		H2Clog.Println(err)
	}
}

// Copy From https://github.com/arxdsilva/webhook/blob/v0.0.3/webhook.go
// Thanks
// converted to SHA256
func SignBody(secret string, payload []byte) []byte {
	computed := hmac.New(sha256.New, []byte(secret))
	computed.Write(payload)
	return []byte(computed.Sum(nil))
}

// SignedBy checks that the provided secret matches the hook Signature
//
// Implements validation described in github's documentation:
// https://developer.github.com/webhooks/securing/
func SignedBy(signature string, payload []byte) bool {
	const signaturePrefix = "sha256="

	if !strings.HasPrefix(signature, signaturePrefix) {
		fmt.Println("prefix")
		return false
	}
	actual, err := hex.DecodeString(signature[7:])
	if err != nil {
		fmt.Println("decode error")
		return false
	} else {
		calcule := SignBody(yamlConfig.SecretToken, payload)
		return hmac.Equal(calcule, actual)
	}
}

// RATE LIMITING FUNCTIONS

var IPSem = make(map[[net.IPv6len]byte]*Weighted)

func RateLimit(ip_B net.IP) bool {
	ip_B16 := [net.IPv6len]byte(ip_B)
	weight, ok := IPSem[ip_B16]
	if ok != true {  // the element does not exist in map
		weight = NewWeighted(5)
		IPSem[ip_B16] = weight
	}
	// I choose to ignore the fact that this map element could be being deleted
	// no matter if weight is < 0
	return weight.TryAcquire(1)
}

// this function increment all 'Weighted'' elements of a map every 'tick'
func ticker() {
	c := time.Tick(5 * time.Second)
	for {
		<-c
		for k, v := range IPSem {
			v.Release(1)
			if v.cur < 0 {
				delete(IPSem, k)	// delete map element for wich no access since 'size' tick
			}
			//fmt.Printf("key[%s] value[%d]\n", k, v.cur)
		}
	}
}

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package semaphore provides a weighted semaphore implementation.

// mostly modified for Raphaël BORDEL implementation for Semaphore Bucket Style Rate Limiting

// NewWeighted creates a new weighted semaphore with the given
// maximum combined weight for concurrent access.
func NewWeighted(n int64) *Weighted {
	w := &Weighted{size: n}
	return w
}

// Weighted provides a way to bound concurrent access to a resource.
// The callers can request access with a given weight.
type Weighted struct {
	size    int64
	cur     int64
	mu      sync.Mutex
}

// TryAcquire acquires the semaphore with a weight of n without blocking.
// On success, returns true. On failure, returns false and leaves the semaphore unchanged.
func (s *Weighted) TryAcquire(n int64) bool {
	s.mu.Lock()
	result := s.size-s.cur >= n 
	if result {
		s.cur += n
	}
	s.mu.Unlock()
	return result
}

// Release releases the semaphore with a weight of n.
func (s *Weighted) Release(n int64) {
	s.mu.Lock()
	s.cur -= n
	s.mu.Unlock()
}

// this fucntion catch signals received by the process
func signalcatcher(sigc <-chan os.Signal, logFile *os.File) {
	for {
		s := <-sigc
		switch s {
		case syscall.SIGTERM:
			H2Clog.Println("SIGTERM received : terminating")
			logFile.Close()
			os.Exit(3)
		default:
			H2Clog.Println("Ignore Signal:", s)
		}
	}
}
