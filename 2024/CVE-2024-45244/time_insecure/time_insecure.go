package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-protos-go/peer"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

type TimeStampChaincode struct {
}

func (t *TimeStampChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *TimeStampChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case "subtractTimestamp":
		return t.subtractTimestamp(stub)
	case "getHistory":
		return t.getHistory(stub)
	case "CalcDividents":
		return t.CalcDividents(stub, args)
	case "CheckDividents_insecure":
		return t.CheckDividents_insecure(stub)
	case "Stake_insecure":
		return t.Stake_insecure(stub, args)
	default:
		return shim.Error("Invalid function name.")
	}
}
//deposit
func (t *TimeStampChaincode) Stake_insecure(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	txTimestamp, err := stub.GetTxTimestamp()
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get transaction timestamp: %v", err))
	}

	timestamp := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).Format(time.RFC3339)
	err = stub.PutState("time", []byte(timestamp))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to save timestamp: %v", err))
	}

	err = stub.PutState("amount", []byte(args[0]))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to save amount: %v", err))
	}

	return shim.Success(nil)
}

func (t *TimeStampChaincode) getHistory(stub shim.ChaincodeStubInterface) peer.Response {
	resultsIterator, err := stub.GetHistoryForKey("amount")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	var history []string
	var time_Timestamp []string
	for resultsIterator.HasNext() {
		modification, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		history = append(history, string(modification.Value))
		time_Timestamp = append(time_Timestamp, time.Unix(modification.Timestamp.Seconds, int64(modification.Timestamp.Nanos)).Format(time.RFC3339))
	}

	return shim.Success([]byte(fmt.Sprintf("History for amount: %v, %s", history, time_Timestamp)))
}

func (t *TimeStampChaincode) subtractTimestamp(stub shim.ChaincodeStubInterface) pb.Response {

	savedTimestamp, err := stub.GetState("time")
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read saved timestamp: %v", err))
	}

	if savedTimestamp == nil {
		return shim.Error(fmt.Sprintf("you must first call the Stake_insecure() function"))
	}

	txTimestamp, err := stub.GetTxTimestamp()
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get transaction timestamp: %v", err))
	}

	savedTime, err := time.Parse(time.RFC3339, string(savedTimestamp))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse saved timestamp: %v", err))
	}

	txTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	difference := txTime.Sub(savedTime).String()

	return shim.Success([]byte(difference))
}

func (t *TimeStampChaincode) CheckDividents_insecure(stub shim.ChaincodeStubInterface) pb.Response {

	savedTimestamp, err := stub.GetState("time") //t or time
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read saved timestamp: %v", err))
	}

	if savedTimestamp == nil {
		return shim.Error(fmt.Sprintf("you must first call the Stake_insecure() function"))
	}

	txTimestamp, err := stub.GetTxTimestamp()
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get transaction timestamp: %v", err))
	}

	savedTime, err := time.Parse(time.RFC3339, string(savedTimestamp))
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to parse saved timestamp: %v", err))
	}

	txTime := time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos))

	days := int(txTime.Sub(savedTime).Abs().Hours()) / 24

	amount, err := stub.GetState("amount") //amount
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to read amount: %v", err))
	}

	amount_str := string(amount)
	amount_int, _ := strconv.Atoi(amount_str)

	dividents := amount_int + (days * amount_int * 2 / (365 * 10)) //days/365   amount*0.2

	return shim.Success([]byte(strconv.Itoa(dividents)))
}

func (t *TimeStampChaincode) CalcDividents(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	days, _ := strconv.Atoi(args[0])
	amount, _ := strconv.Atoi(args[1])

	dividents := amount + (days * amount * 2 / (365 * 10)) //days/365   amount*0.2

	return shim.Success([]byte(strconv.Itoa(dividents)))
}

func main() {
	err := shim.Start(new(TimeStampChaincode))
	if err != nil {
		fmt.Printf("Error starting TimeStampChaincode: %v", err)
	}
}
