// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"log"
	"math/big"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
		"MD5":    gosnmp.MD5,
		"SHA":    gosnmp.SHA,
		"SHA224": gosnmp.SHA224,
		"SHA256": gosnmp.SHA256,
		"SHA384": gosnmp.SHA384,
		"SHA512": gosnmp.SHA512}

	privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
		"DES":     gosnmp.DES,
		"AES":     gosnmp.AES,
		"AES128":  gosnmp.AES,
		"AES192":  gosnmp.AES192,
		"AES256":  gosnmp.AES256,
		"AES192C": gosnmp.AES192C,
		"AES256C": gosnmp.AES256C}

	numberRegexPattern = regexp.MustCompile(`^[0-9]+$`)
)

const (
	port = 161

	retryCount = 6

	debugFlag = " -D"

	spaceSeparator = " "

	hyphenSeparator = "-"

	retryCountFlag = "-r"

	snmpVersionV1 = "-v1"

	snmpVersionV2C = "-v2c"

	snmpVersionV3 = "-v3"

	snmpCommunityFlag = "-c"

	snmpSecurityLevelFlag = "-l"

	snmpSecurityLevelAuthNoPrivacy = "authNoPriv"

	snmpSecurityLevelAuthPrivacy = "authPriv"

	snmpSecurityLevelNoAuthNoPrivacy = "noAuthNoPriv"

	snmpUsernameFlag = "-u"

	snmpAuthenticationProtocolFlag = "-a"

	snmpAuthenticationPassphraseFlag = "-A"

	snmpPrivacyProtocolFlag = "-x"

	snmpPrivacyPassphraseFlag = "-X"

	snmpTimeoutFlag = "-t"

	snmpHexValueFlag = " -O x"

	snmpExponentialTimeoutFlag = "-exp"

	loggingPropertiesFlag = 3

	systemOID = ".1.3.6.1.2.1.1.2.0"
)

func main() {

	log.SetOutput(os.Stdout)

	log.SetFlags(0)

	var inputSNMPWalkCommand string

	args := os.Args[1:]

	inputSNMPWalkCommand = ""

	for _, arg := range args {

		inputSNMPWalkCommand += arg + " "
	}

	GoSNMPExec(strings.TrimSpace(inputSNMPWalkCommand))

}

func GoSNMPExec(command string) {

	params := &gosnmp.GoSNMP{
		Port:               port,
		Timeout:            time.Duration(2) * time.Second,
		ExponentialTimeout: false,
		Retries:            retryCount,
	}

	if strings.Contains(command, debugFlag) {

		params.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", loggingPropertiesFlag))

		command = strings.ReplaceAll(command, debugFlag, "")
	}

	if strings.Contains(command, snmpHexValueFlag) {

		command = strings.ReplaceAll(command, snmpHexValueFlag, "")
	}

	inputParams := strings.Split(command, spaceSeparator)

	length := len(inputParams)

	inputParamMap := createParamMap(inputParams, length)

	isOIDPresent := checkOIDPresent(command, params)

	SetParameters(inputParams, inputParamMap, params)

	err := params.Connect()

	defer func(Connection net.Conn) {

		err := Connection.Close()

		if err != nil {

			log.Fatalf("Connection Close error: %v", err)
		}
	}(params.Conn)

	if err != nil {

		log.Fatalf("Connect error: %v", err)
	}

	if isOIDPresent && !strings.HasSuffix(inputParams[length-1], ".0") {

		result, err := params.WalkAll(inputParams[length-1])

		if err != nil {

			log.Fatalf("Go-SNMP WalkAll error: %v", err)
		}

		for _, pdu := range result {

			FormatSNMPValue(pdu)
		}

	} else {

		var oid []string

		if !isOIDPresent {

			oid = append(oid, systemOID)

		} else {

			tokens := strings.Split(command, hyphenSeparator)

			length := len(tokens)

			token := strings.Split(tokens[length-1], spaceSeparator)

			for index := 3; index < len(token); index++ {

				oid = append(oid, token[index])
			}

		}

		snmpGetResponse, err := params.Get(oid)

		if err != nil {

			log.Fatalf("Error getting OID: %v", err)
		}

		if len(snmpGetResponse.Variables) > 0 {

			for _, pdu := range snmpGetResponse.Variables {

				FormatSNMPValue(pdu)
			}

		} else {

			log.Printf("%v", "No response received.")
		}

	}

}

func SetParameters(inputParams []string, inputParamMap map[string]string, params *gosnmp.GoSNMP) {

	_, retryFlagFound := inputParamMap[retryCountFlag]

	if retryFlagFound && numberRegexPattern.MatchString(inputParamMap[retryCountFlag]) {

		params.Retries, _ = strconv.Atoi(inputParamMap[retryCountFlag])

	}

	_, timeoutFlagFound := inputParamMap[snmpTimeoutFlag]

	if timeoutFlagFound && numberRegexPattern.MatchString(inputParamMap[snmpTimeoutFlag]) {

		timeoutValue, _ := strconv.Atoi(inputParamMap[snmpTimeoutFlag])

		params.Timeout = time.Duration(timeoutValue) * time.Second

	}

	_, exponentialTimeoutFlagFound := inputParamMap[snmpExponentialTimeoutFlag]

	if exponentialTimeoutFlagFound {

		if strings.Contains(inputParamMap[snmpExponentialTimeoutFlag], "true") ||
			strings.Contains(inputParamMap[snmpExponentialTimeoutFlag], "false") {

			params.ExponentialTimeout, _ = strconv.ParseBool(inputParamMap[snmpExponentialTimeoutFlag])

		} else {

			log.Fatalf("%v", "Invalid Command : Invalid exponential timeout value")
		}
	}

	var snmpVersion string

	if inputParams[1] == snmpVersionV1 || inputParams[1] == snmpVersionV2C || inputParams[1] == snmpVersionV3 {

		snmpVersion = inputParams[1]

	} else {

		log.Fatalf("%v", "Invalid Command : Invalid SNMP version")
	}

	switch snmpVersion {

	case snmpVersionV2C:

		params.Version = gosnmp.Version2c

		params.Community = inputParamMap[snmpCommunityFlag]

		break

	case snmpVersionV3:

		params.Version = gosnmp.Version3

		params.SecurityModel = gosnmp.UserSecurityModel

		var snmpSecurityLevel string

		if inputParamMap[snmpSecurityLevelFlag] == snmpSecurityLevelAuthNoPrivacy ||
			inputParamMap[snmpSecurityLevelFlag] == snmpSecurityLevelAuthPrivacy ||
			inputParamMap[snmpSecurityLevelFlag] == snmpSecurityLevelNoAuthNoPrivacy {

			snmpSecurityLevel = inputParamMap[snmpSecurityLevelFlag]

		} else {

			log.Fatalf("%v", "Invalid Command : Invalid security level")
		}

		switch snmpSecurityLevel {

		case snmpSecurityLevelAuthNoPrivacy:

			params.MsgFlags = gosnmp.AuthNoPriv

			_, isValidAuthenticationProtocol := authProtocols[strings.ToUpper(inputParamMap[snmpAuthenticationProtocolFlag])]

			if isValidAuthenticationProtocol {

				params.SecurityParameters = &gosnmp.UsmSecurityParameters{

					UserName: inputParamMap[snmpUsernameFlag],

					AuthenticationProtocol: authProtocols[strings.ToUpper(inputParamMap[snmpAuthenticationProtocolFlag])],

					AuthenticationPassphrase: inputParamMap[snmpAuthenticationPassphraseFlag],
				}
			} else {

				log.Fatalf("%v", "Invalid Command : Invalid authentication parameters")
			}

			break

		case snmpSecurityLevelAuthPrivacy:

			params.MsgFlags = gosnmp.AuthPriv

			_, isValidAuthenticationProtocol := authProtocols[strings.ToUpper(inputParamMap[snmpAuthenticationProtocolFlag])]

			_, isValidPrivacyProtocol := privProtocols[strings.ToUpper(inputParamMap[snmpPrivacyProtocolFlag])]

			if isValidAuthenticationProtocol && isValidPrivacyProtocol {

				params.SecurityParameters = &gosnmp.UsmSecurityParameters{

					UserName: inputParamMap[snmpUsernameFlag],

					AuthenticationProtocol: authProtocols[strings.ToUpper(inputParamMap[snmpAuthenticationProtocolFlag])],

					AuthenticationPassphrase: inputParamMap[snmpAuthenticationPassphraseFlag],

					PrivacyProtocol: privProtocols[strings.ToUpper(inputParamMap[snmpPrivacyProtocolFlag])],

					PrivacyPassphrase: inputParamMap[snmpPrivacyPassphraseFlag],
				}
			} else {

				log.Fatalf("%v", "Invalid command : authentication or privacy parameters")
			}
			break

		default:

			params.MsgFlags = gosnmp.NoAuthNoPriv

			params.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: inputParamMap[snmpUsernameFlag]}
		}
		break

	default:

		params.Version = gosnmp.Version1

		params.Community = inputParamMap[snmpCommunityFlag]
	}

}

func checkOIDPresent(command string, params *gosnmp.GoSNMP) (isOIDPresent bool) {

	tokens := strings.Split(command, hyphenSeparator)

	length := len(tokens)

	token := strings.Split(tokens[length-1], spaceSeparator)

	if (len(token) > 3) && token[3] != "" {

		isOIDPresent = true

	} else {

		isOIDPresent = false
	}

	params.Target = token[2]

	return
}

func createParamMap(array []string, length int) map[string]string {

	parameterMap := make(map[string]string)

	for index := 2; index < length-2; index = index + 2 {

		if array[index+1] != "" && !strings.HasPrefix(array[index+1], "-") {

			parameterMap[array[index]] = array[index+1]

		} else {

			log.Fatalf("%v", "Invalid Command : Invalid command line arguments")
		}
	}
	return parameterMap
}

func IsASCII(value string) bool {

	for _, char := range value {

		if char > unicode.MaxASCII || !unicode.IsPrint(char) {

			return false
		}
	}
	return true
}

func GetHexAddress(tokens interface{}) (macAddress string) {

	macAddress = ""

	if tokens != nil {

		for index, token := range tokens.([]uint8) {

			hexValue := fmt.Sprintf("%X", token)

			if len(hexValue) == 1 {

				hexValue = "0" + hexValue
			}

			if index == len(tokens.([]uint8))-1 {

				macAddress = macAddress + hexValue

			} else {

				macAddress = macAddress + hexValue + " "
			}
		}
	}

	return
}

func FormatSNMPValue(pdu gosnmp.SnmpPDU) {

	switch pdu.Type {

	case gosnmp.Integer:

		log.Printf("%v = INTEGER: %v\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))

	case gosnmp.OctetString:

		var value string

		if reflect.ValueOf(pdu.Value).Kind().String() == "string" {

			value = pdu.Value.(string)

		} else if reflect.ValueOf(pdu.Value).Kind().String() == "slice" {

			if IsASCII(string(pdu.Value.([]uint8))) {

				value = string(pdu.Value.([]uint8))

			} else {

				value = GetHexAddress(pdu.Value.([]uint8))
			}

		} else {

			value = string(pdu.Value.([]byte))

		}

		log.Printf("%v = STRING: %v\n",

			pdu.Name,

			value,
		)

	case gosnmp.Null:

		log.Printf("%v = NULL\n", pdu.Name)

	case gosnmp.ObjectIdentifier:

		log.Printf("%v = OID: %v\n", pdu.Name, pdu.Value)

	case gosnmp.Opaque:

		log.Printf("%v = HEX: %v\n", pdu.Name, strings.TrimPrefix(hex.EncodeToString(pdu.Value.([]byte)), ""))

	case gosnmp.Counter32:

		log.Printf("%v = Counter32: %v\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))

	case gosnmp.Counter64:

		log.Printf("%v = Counter64: %v\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))

	case gosnmp.Gauge32:

		log.Printf("%v = Gauge32: %v\n", pdu.Name, gosnmp.ToBigInt(pdu.Value))

	case gosnmp.IPAddress:

		log.Printf("%v = IpAddress: %v\n", pdu.Name, pdu.Value)

	case gosnmp.TimeTicks:

		log.Printf("%v = Timeticks: %v\n", pdu.Name, "("+gosnmp.ToBigInt(pdu.Value).String()+") "+DecodeTimeTicks(pdu))

	case gosnmp.NoSuchInstance:

		log.Printf("%v = No Such Instance currently exists at this OID", pdu.Name)

	default:

		log.Printf("%v = Unknown data type: \n", pdu.Name)
	}

}

func DecodeTimeTicks(pdu gosnmp.SnmpPDU) string {

	val := new(big.Int)

	val.SetString(gosnmp.ToBigInt(pdu.Value).String(), 10)

	divisor := new(big.Int)

	divisor.SetString("8640000", 10)

	days := new(big.Int)

	days.Div(val, divisor)

	val.Mod(val, divisor)

	hours := new(big.Int)

	hours.Div(val, big.NewInt(360000))

	val.Mod(val, big.NewInt(360000))

	minutes := new(big.Int)

	minutes.Div(val, big.NewInt(6000))

	val.Mod(val, big.NewInt(6000))

	seconds := new(big.Int)

	seconds.Div(val, big.NewInt(100))

	val.Mod(val, big.NewInt(100))

	if days.Cmp(big.NewInt(1)) == 0 {

		return fmt.Sprintf("%v day, %v:%02v:%02v.%02v", days.String(), hours.String(), minutes.String(), seconds.String(), val.String())

	} else if days.Cmp(big.NewInt(0)) == 0 {

		return fmt.Sprintf("%v:%02v:%02v.%02v", hours.String(), minutes.String(), seconds.String(), val.String())

	} else {

		return fmt.Sprintf("%v days, %v:%02v:%02v.%02v", days.String(), hours.String(), minutes.String(), seconds.String(), val.String())
	}

}
