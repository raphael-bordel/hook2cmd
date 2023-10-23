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
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"strings"
)

type Config struct {
	LogFile        string `yaml:"logfile"`
	Bindto         string `yaml:"bindto"`
	HTTPS          bool   `yaml:"https"`
	CertFile       string `yaml:"certfile"`
	KeyFile        string `yaml:"keyfile"`
	SecretToken    string `yaml:"secret_token"`
	Email_from     string `yaml:"email_from"`
	Email_password string `yaml:"email_password"`
	Email_smtpHost string `yaml:"email_smtpHost"`
	Email_smtpPort string `yaml:"email_smtpPort"`

	Projets []Projet `yaml:"projets"`
}
type Projet struct {
	Route     string `yaml:"route"`
	Name      string `yaml:"nom"`
	Command   string `yaml:"command"`
	Log2Email string `yaml:"log_to_email"`
}

var yamlConfig Config
var H2Clog *log.Logger

func main() {
	if chargeconfig() == true {
		var err error

		// open log file
		logFile, logerr := os.OpenFile(yamlConfig.LogFile, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
		if logerr != nil {
			log.Fatal(logerr)
		}
		defer logFile.Close()

		// set log output
		//H2Clog.SetOutput(logFile)
		H2Clog = log.New(logFile, "", 0)

		// optional: log date-time, filename, and line number
		//H2Clog.SetFlags(H2Clog.Lshortfile | H2Clog.LstdFlags)

		H2Clog.Println("Hook2CMD logging started ...")

		for _, uneconfig := range yamlConfig.Projets {
			http.HandleFunc(uneconfig.Route, hookHandler)
		}
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
		H2Clog.Println("Format YAML incorrect pour le fichier : ", fileName)
		return false
	}
	//fmt.Println(yamlConfig)
	return true
}

func hookHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("\n%s\n", r.Header) //r.RequestURI)
	
	if header_token1 := r.Header.Get("X-Gitlab-Token"); header_token1 != "" { // on cherche la signature de Gitlab
		if header_token1 != yamlConfig.SecretToken {
			http.Error(w, "Error : GitLab Token Verification Failed\n", 490)
			return
		}
		// GitLab Token : OK
	} else if header_token2 := r.Header.Get("X-Hub-Signature-256"); header_token2 != "" { // on cherche la signature de GitHub
		payload, _ := ioutil.ReadAll(r.Body)
		if SignedBy(header_token2, payload) != true {
			http.Error(w, "Error : GitLab Token Verification Failed\n", 491)
			return
		}
		// GitHub Token : OK
	} else if header_token3 := r.Header.Get("X-Hook2CMD-Token"); header_token3 != "" {  // on cherche notre signature
  		// exemple usage : curl -H "X-Hook2CMD-Token: PVAfCf73k2G3XXnDP2qXNjnbh843DE/QVUYivoDzy6w=" -X POST https://www.cresi.fr:3000/test
		if header_token3 != yamlConfig.SecretToken {
			http.Error(w, "Error : Hook2CMD Token Verification Failed\n", 492)
			return
		}
		// Hook2Cmd : POST : OK
	} else {
		http.Error(w, "Error : Unidentified WebHook request\n", 497)
		return
	}
	http.Error(w, "ok\n", 200)

	go traite(r.RequestURI)

	return
}

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
		H2Clog.Println("pas de config/projet correspondant a cette route : ", route)
		return
	}

	runcommand(uneconfig)
}

func runcommand(lp Projet) {
	cmd := exec.Command(lp.Command, lp.Name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		H2Clog.Println("cmd.Run() failed with ", err)
		return
	}
	fmt.Printf("combined out:\n%s\n", string(out))
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
	msg = append(msg, lp.Log2Email...) // les ... permettent d'ajouter un string à un []byte
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
