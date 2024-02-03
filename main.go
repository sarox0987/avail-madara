package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/account"
	"github.com/NethermindEth/starknet.go/curve"
	"github.com/NethermindEth/starknet.go/rpc"
	ethrpc "github.com/ethereum/go-ethereum/rpc"

	"github.com/NethermindEth/starknet.go/utils"
)

var (
	name                  string = "testnet"
	account_addr          string = "0x0000000000000000000000000000000000000000000000000000000000000004"
	account_cairo_version        = 0
	predeployedClassHash         = "0x2794ce20e5f2ff0d40e632cb53845b9f4e526ebd8471983f7dbd355b721d5a"
	privateKey            string = "0x00c0cf1490de1352865301bb8705143f3ef938f96fdf892f1091dcb5ac7bcd1d"
	ethContract           string = "0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
	contractMethod        string = "transfer"
)

type RPC struct {
	Url string
}

func main() {
	file, err := os.Open("rpc.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	r := &RPC{}
	if err := json.Unmarshal(data, r); err != nil {
		panic(err)
	}

	c, err := ethrpc.DialContext(context.Background(), r.Url)
	if err != nil {
		panic(err)
	}
	p := rpc.NewProvider(c)

	account_address, err := utils.HexToFelt(account_addr)
	if err != nil {
		panic(err.Error())
	}

	public_key := pubKey(privateKey)

	ks := account.NewMemKeystore()
	fakePrivKeyBI, ok := new(big.Int).SetString(privateKey, 0)
	if !ok {
		panic(err.Error())
	}
	ks.Put(public_key, fakePrivKeyBI)

	a, err := account.NewAccount(p, account_address, public_key, ks, 2)
	if err != nil {
		panic(err.Error())
	}

	go deployTx(public_key, a)
	go invokeTx(a)
	select {}

}

func deployTx(pub string, a *account.Account) {
	classHash, err := utils.HexToFelt(predeployedClassHash)
	if err != nil {
		panic(err)
	}

	pubKey, _ := utils.HexToFelt(pub)

	tx := rpc.DeployAccountTxn{
		Nonce:               &felt.Zero,
		MaxFee:              new(felt.Felt).SetUint64(4724395326064),
		Type:                rpc.TransactionType_DeployAccount,
		Version:             rpc.TransactionV1,
		Signature:           []*felt.Felt{},
		ClassHash:           classHash,
		ContractAddressSalt: pubKey,
		ConstructorCalldata: []*felt.Felt{pubKey},
	}

	precomputedAddress, _ := a.PrecomputeAddress(&felt.Zero, pubKey, classHash, tx.ConstructorCalldata)

	err = a.SignDeployAccountTransaction(context.Background(), &tx, precomputedAddress)
	if err != nil {
		panic(err)
	}

	for {

		resp, err := a.AddDeployAccountTransaction(context.Background(), rpc.BroadcastDeployAccountTxn{DeployAccountTxn: tx})
		if err != nil {
			fmt.Println(err)
			time.Sleep(41 * time.Second)
			continue
		}
		fmt.Println("deployd: ", resp.ContractAddress)
		time.Sleep(21 * time.Second)

	}

}

func invokeTx(a *account.Account) {
	for {
		nonce, err := a.Nonce(context.Background(), rpc.BlockID{Tag: "latest"}, a.AccountAddress)
		if err != nil {
			panic(err.Error())
		}

		ca, err := utils.HexToFelt(ethContract)
		if err != nil {
			panic(err.Error())
		}
		recipient, err := utils.HexToFelt("0x054649B7bF9e490E7098265895af70E6fB7DD7e6610E605f9eC27C8afE8b343b")
		if err != nil {
			panic(err.Error())
		}

		amount := utils.BigIntToFelt(big.NewInt(1))
		maxfee := utils.BigIntToFelt(big.NewInt(10000))

		InvokeTx := rpc.InvokeTxnV1{
			MaxFee:        maxfee,
			Version:       rpc.TransactionV1,
			Nonce:         nonce,
			Type:          rpc.TransactionType_Invoke,
			SenderAddress: a.AccountAddress,
		}

		FnCall := rpc.FunctionCall{
			ContractAddress:    ca,
			EntryPointSelector: utils.GetSelectorFromNameFelt(contractMethod),
			Calldata:           []*felt.Felt{recipient, amount},
		}

		InvokeTx.Calldata, err = a.FmtCalldata([]rpc.FunctionCall{FnCall})
		if err != nil {
			panic(err.Error())
		}

		err = a.SignInvokeTransaction(context.Background(), &InvokeTx)
		if err != nil {
			panic(err.Error())
		}

		rsp, err := a.AddInvokeTransaction(context.Background(), InvokeTx)
		if err != nil {
			fmt.Println(err)
			time.Sleep(40 * time.Second)
			continue
		}

		fmt.Println("tx: ", rsp.TransactionHash, " nonce: ", nonce)
		time.Sleep(20 * time.Second)
	}
}

func pubKey(prvKey string) string {
	pk, err := utils.HexToFelt(prvKey)
	if err != nil {
		panic(err.Error())
	}

	pubKey, _, err := curve.Curve.PrivateToPoint(utils.FeltToBigInt(pk))
	if err != nil {
		panic(err.Error())
	}

	return pubKey.String()
}
