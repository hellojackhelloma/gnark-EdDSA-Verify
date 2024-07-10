package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	mrand "math/rand"
	"time"
)

func GetEddsaCircuit() *eddsaCircuit {
	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// create a eddsa key pair
	privateKey, err := eddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		fmt.Println("failed to create a key pair. error:", err)
		return nil
	}
	publicKey := privateKey.Public()

	msg := randomMsg()

	fmt.Printf("%v message: %s\n", time.Now(), string(msg))
	// sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		fmt.Println("failed to Sign. error:", err)
		return nil
	}

	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// public key bytes
	_publicKey := publicKey.Bytes()

	// assign public key values
	assignment.PublicKey.Assign(twistededwards.BN254, _publicKey[:32])

	// assign signature values
	assignment.Signature.Assign(twistededwards.BN254, signature)

	return &assignment
}

func GetEddsaCircuitBatch() *eddsaCircuitBatch {
	var assignment eddsaCircuitBatch
	for i := 0; i < BatchSize; i++ {
		cr := GetEddsaCircuit()
		assignment.PublicKey[i] = cr.PublicKey
		assignment.Signature[i] = cr.Signature
		assignment.Message[i] = cr.Message
	}
	return &assignment
}

func Prove() {
	// compiles our circuit into a R1CS
	var circuit eddsaCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("failed to Compile. error:", err)
		return
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("failed to Setup. error:", err)
		return
	}

	witness, err := frontend.NewWitness(GetEddsaCircuit(), ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("failed to NewWitness. error:", err)
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("failed to witness.Public. error:", err)
		return
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("failed to Prove. error:", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Prove get invalid signature")
	} else {
		fmt.Println("Prove get valid signature")
	}
}

func ProveBatch() {
	// compiles our circuit into a R1CS
	var circuit eddsaCircuitBatch
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("failed to Compile. error:", err)
		return
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("failed to Setup. error:", err)
		return
	}

	witness, err := frontend.NewWitness(GetEddsaCircuitBatch(), ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("failed to NewWitness. error:", err)
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("failed to witness.Public. error:", err)
		return
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("failed to Prove. error:", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Prove get invalid signature")
	} else {
		fmt.Println("Prove get valid signature")
	}
}

func main() {
	//GenVerifyProve()
	//Prove()
	ProveBatch()
}

// Define a set of characters to choose from
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate a random string of length n
func randomMsg() []byte {
	// Seed the random number generator
	mrand.Seed(time.Now().UnixNano())

	// Generate a random length between 1 and 31
	n := mrand.Intn(31) + 1

	b := make([]byte, n)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return b
}

func GenVerifyProve() {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New()

	// create a eddsa key pair
	privateKey, err := eddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		fmt.Println("failed to create a key pair. error:", err)
		return
	}
	publicKey := privateKey.Public()

	// note that the message is on 4 bytes
	msg := []byte("privateKeyprivateKeyprivateKe")
	//msg := []byte{0xde, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xf0, 0x0d, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xf0, 0x0d, 0xf0, 0x0d}
	fmt.Printf("message: %s\n", string(msg))
	// sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		fmt.Println("failed to Sign. error:", err)
		return
	}
	// verifies signature
	isValid, err := publicKey.Verify(signature, msg, hFunc)
	if err != nil {
		fmt.Println("failed to Verify. error:", err)
		return
	}

	if !isValid {
		fmt.Println("invalid signature")
		return
	} else {
		fmt.Println("valid signature")
	}

	// compiles our circuit into a R1CS
	var circuit eddsaCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("failed to Compile. error:", err)
		return
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("failed to Setup. error:", err)
		return
	}

	// witness definition
	// declare the witness
	var assignment eddsaCircuit

	// assign message value
	assignment.Message = msg

	// public key bytes
	_publicKey := publicKey.Bytes()

	// assign public key values
	assignment.PublicKey.Assign(twistededwards.BN254, _publicKey[:32])

	// assign signature values
	assignment.Signature.Assign(twistededwards.BN254, signature)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("failed to NewWitness. error:", err)
		return
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("failed to witness.Public. error:", err)
		return
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("failed to Prove. error:", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Prove get invalid signature")
	} else {
		fmt.Println("Prove get valid signature")
	}
}
