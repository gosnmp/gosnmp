package main

import (
	"fmt"
	"github.com/gosnmp/gosnmp"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	authProtocolMap = map[string]gosnmp.SnmpV3AuthProtocol{
		"MD5":    gosnmp.MD5,
		"SHA":    gosnmp.SHA,
		"SHA224": gosnmp.SHA224,
		"SHA256": gosnmp.SHA256,
		"SHA384": gosnmp.SHA384,
		"SHA512": gosnmp.SHA512,
	}

	privProtocolMap = map[string]gosnmp.SnmpV3PrivProtocol{
		"DES":     gosnmp.DES,
		"AES":     gosnmp.AES,
		"AES128":  gosnmp.AES,
		"AES192":  gosnmp.AES192,
		"AES256":  gosnmp.AES256,
		"AES192C": gosnmp.AES192C,
		"AES256C": gosnmp.AES256C,
	}

	numberPattern = regexp.MustCompile(`^[0-9]+$`)
)

const (
	defaultSNMPPort = 161
	defaultRetries  = 6
	debugFlag       = " -D"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	inputCommand := strings.Join(os.Args[1:], " ")
	executeSNMPWalk(strings.TrimSpace(inputCommand))
}

func executeSNMPWalk(command string) {
	snmpParams := &gosnmp.GoSNMP{
		Port:    defaultSNMPPort,
		Timeout: time.Duration(2) * time.Second,
		Retries: defaultRetries,
	}

	if strings.Contains(command, debugFlag) {
		snmpParams.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", log.LstdFlags))
		command = strings.ReplaceAll(command, debugFlag, "")
	}

	args := strings.Split(strings.TrimSpace(command), " ")
	argMap := parseArguments(args)

	configureSNMPParameters(args, argMap, snmpParams)
	targetOID := determineOID(command, args, snmpParams)

	err := snmpParams.Connect()
	if err != nil {
		log.Fatalf("Error connecting: %v", err)
	}
	defer snmpParams.Conn.Close()

	if targetOID == "" {
		err := fetchSystemOID(snmpParams)
		if err != nil {
			log.Fatalf("System OID fetch error: %v", err)
		}
	} else {
		err := fetchOID(snmpParams, targetOID)
		if err != nil {
			log.Fatalf("OID fetch error: %v", err)
		}
	}
}

func configureSNMPParameters(args []string, paramsMap map[string]string, snmpParams *gosnmp.GoSNMP) {
	if retryCount, exists := paramsMap["-r"]; exists && numberPattern.MatchString(retryCount) {
		snmpParams.Retries, _ = strconv.Atoi(retryCount)
	}

	switch args[1] {
	case "-v1":
		snmpParams.Version = gosnmp.Version1
		snmpParams.Community = paramsMap["-c"]
	case "-v2c":
		snmpParams.Version = gosnmp.Version2c
		snmpParams.Community = paramsMap["-c"]
	case "-v3":
		configureSNMPv3(paramsMap, snmpParams)
	default:
		log.Fatalf("Invalid SNMP version specified")
	}
}

func fetchSystemOID(snmpParams *gosnmp.GoSNMP) error {
	response, err := snmpParams.Get([]string{".1.3.6.1.2.1.1.2.0"})
	if err != nil {
		return err
	}
	printSNMPResponse(response)
	return nil
}

func printSNMPResponse(response *gosnmp.SnmpPacket) {
	for _, pdu := range response.Variables {
		displayPDU(pdu)
	}
}

func fetchOID(snmpParams *gosnmp.GoSNMP, oid string) error {
	response, err := snmpParams.WalkAll(oid)
	if err != nil {
		return err
	}
	for _, pdu := range response {
		displayPDU(pdu)
	}
	return nil
}

func determineOID(command string, args []string, snmpParams *gosnmp.GoSNMP) string {
	tokens := strings.Split(command, " -")
	lastToken := strings.Split(tokens[len(tokens)-1], " ")
	snmpParams.Target = lastToken[2]

	if len(lastToken) > 3 {
		return lastToken[3]
	}
	return ""
}

func parseArguments(args []string) map[string]string {
	argMap := make(map[string]string)
	for i := 2; i < len(args)-1; i += 2 {
		argMap[args[i]] = args[i+1]
	}
	return argMap
}

func displayPDU(pdu gosnmp.SnmpPDU) {
	switch pdu.Type {
	case gosnmp.Integer:
		fmt.Printf("%v = INTEGER: %v\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))
	case gosnmp.OctetString:
		fmt.Printf("%v = STRING: %v\n", pdu.Name, retrieveOctetString(pdu))
	case gosnmp.ObjectIdentifier:
		fmt.Printf("%v = OID: %v\n", pdu.Name, pdu.Value)
	case gosnmp.IPAddress:
		fmt.Printf("%v = IpAddress: %v\n", pdu.Name, pdu.Value)
	case gosnmp.TimeTicks:
		fmt.Printf("%v = Timeticks: (%v)\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))
	default:
		fmt.Printf("%v = %v\n", pdu.Name, pdu.Value)
	}
}

func retrieveOctetString(pdu gosnmp.SnmpPDU) string {
	switch reflect.TypeOf(pdu.Value).Kind() {
	case reflect.String:
		return pdu.Value.(string)
	case reflect.Slice:
		if isASCII(string(pdu.Value.([]uint8))) {
			return string(pdu.Value.([]uint8))
		}
		return convertToHexAddress(pdu.Value.([]uint8))
	default:
		return string(pdu.Value.([]byte))
	}
}

func isASCII(value string) bool {
	for _, char := range value {
		if char > unicode.MaxASCII || !unicode.IsPrint(char) {
			return false
		}
	}
	return true
}

func convertToHexAddress(bytes []uint8) string {
	var hexAddr string
	for i, b := range bytes {
		hexAddr += fmt.Sprintf("%02X", b)
		if i < len(bytes)-1 {
			hexAddr += " "
		}
	}
	return hexAddr
}

func configureSNMPv3(paramMap map[string]string, snmpParams *gosnmp.GoSNMP) {
	snmpParams.Version = gosnmp.Version3
	snmpParams.SecurityModel = gosnmp.UserSecurityModel

	securityParams := &gosnmp.UsmSecurityParameters{UserName: paramMap["-u"]}
	switch paramMap["-l"] {
	case "authNoPriv":
		snmpParams.MsgFlags = gosnmp.AuthNoPriv
		if authProtocol, ok := getAuthProtocol(paramMap["-a"]); ok {
			securityParams.AuthenticationProtocol = authProtocol
		}
		securityParams.AuthenticationPassphrase = paramMap["-A"]
	case "authPriv":
		snmpParams.MsgFlags = gosnmp.AuthPriv
		if authProtocol, ok := getAuthProtocol(paramMap["-a"]); ok {
			securityParams.AuthenticationProtocol = authProtocol
		}
		securityParams.AuthenticationPassphrase = paramMap["-A"]
		if privProtocol, ok := getPrivProtocol(paramMap["-x"]); ok {
			securityParams.PrivacyProtocol = privProtocol
		}
		securityParams.PrivacyPassphrase = paramMap["-X"]
	default:
		snmpParams.MsgFlags = gosnmp.NoAuthNoPriv
	}
	snmpParams.SecurityParameters = securityParams
}

func getAuthProtocol(protocol string) (gosnmp.SnmpV3AuthProtocol, bool) {
	for k, v := range authProtocolMap {
		if strings.EqualFold(k, protocol) {
			return v, true
		}
	}
	return gosnmp.NoAuth, false
}

func getPrivProtocol(protocol string) (gosnmp.SnmpV3PrivProtocol, bool) {
	for k, v := range privProtocolMap {
		if strings.EqualFold(k, protocol) {
			return v, true
		}
	}
	return gosnmp.NoPriv, false
}
