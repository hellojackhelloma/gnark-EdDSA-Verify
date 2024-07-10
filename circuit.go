package main

import (
	twistededwards1 "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type eddsaCircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

const BatchSize = 200

type eddsaCircuitBatch struct {
	PublicKey [BatchSize]eddsa.PublicKey   `gnark:",public"`
	Signature [BatchSize]eddsa.Signature   `gnark:",public"`
	Message   [BatchSize]frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, twistededwards1.BN254)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)

}

func (circuit *eddsaCircuitBatch) Define(api frontend.API) error {

	for i := 0; i < BatchSize; i++ {
		curve, err := twistededwards.NewEdCurve(api, twistededwards1.BN254)
		if err != nil {
			return err
		}

		mimc, err := mimc.NewMiMC(api)
		if err != nil {
			return err
		}

		if err := eddsa.Verify(curve, circuit.Signature[i], circuit.Message[i], circuit.PublicKey[i], &mimc); err != nil {
			return err
		}
	}

	return nil
}
