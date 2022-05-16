package main

import (
	"context"
	"log"
	"os"

	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	godotenv "github.com/joho/godotenv"
	"golang.org/x/crypto/sha3"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Failed to read file: ", err)
	}

	client, err := ethclient.Dial(os.Getenv("URL"))
	if err != nil {
		log.Fatal(err)
	}

	// loading private key
	privateKey, err := crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()                   // returns an interface that contains public key
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey) // type assertion to explictly set the type of our publicKey variable
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// read nonce for the account's transaction.
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	// set the amount of ETH for transferring
	// In case of ERC20, amount of ETH should be 0
	// The value of Tokens to be transferred will be set in the data field
	// big.NewInt(0) convert ETH to wei
	// 18 decimal places, 1ETH = 1000000000000000000(1 + 18 zeros)
	value := big.NewInt(0) // = wei (0 eth)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	toAddress := common.HexToAddress(os.Getenv("TO_ADDRESS"))
	// Token contract address
	tokenAddress := common.HexToAddress(os.Getenv("TOKEN_ADDRESS"))

	transferFnSignature := []byte("transfer(address,uint256)")
	// Get the method ID of the function
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4] // The first 4 bytes of the resulting hash is the methodId
	fmt.Printf("Method ID: %s\n", hexutil.Encode(methodID))

	// zero pad (to the left) the account address. The resulting byte slice must be 32 bytes long.
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Printf("To address: %s\n", hexutil.Encode(paddedAddress))

	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10) // 1 token
	// zero pad (to the left) the amount. The resulting byte slice must be 32 bytes long.
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Printf("Token amount: %s\n", hexutil.Encode(paddedAmount))

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	gasLimit := uint64(99999)
	// Transaction
	tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)
	// sign the transaction with the private key of the sender
	// The SignTx method requires the EIP155 signer.
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// broadcast the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Tokens sent at: %s", signedTx.Hash().Hex())
}
