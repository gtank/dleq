package dleq

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

type Point struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

func (p *Point) IsOnCurve() bool {
	return p.Curve.IsOnCurve(p.X, p.Y)
}

func (p *Point) Marshal() []byte {
	return elliptic.Marshal(p.Curve, p.X, p.Y)
}

func (p *Point) Unmarshal(curve elliptic.Curve, data []byte) error {
	p.Curve = curve
	p.X, p.Y = elliptic.Unmarshal(curve, data)
	if p.X == nil {
		return ErrInvalidPoint
	}
	return nil
}

// This is just a bitmask with the number of ones starting at 8 then
// incrementing by index. To account for fields with bitsizes that are not a whole
// number of bytes, we mask off the unnecessary bits. h/t agl
var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

func randScalar(curve elliptic.Curve, rand io.Reader) ([]byte, *big.Int, error) {
	N := curve.Params().N // base point subgroup order
	bitSize := N.BitLen()
	byteSize := (bitSize + 7) / 8
	buf := make([]byte, byteSize)

	// When in doubt, do what agl does in elliptic.go. Presumably
	// new(big.Int).SetBytes(b).Mod(N) would introduce bias, so we're sampling.
	for true {
		_, err := io.ReadFull(rand, buf)
		if err != nil {
			return nil, nil, err
		}
		// Mask to account for field sizes that are not a whole number of bytes.
		buf[0] &= mask[bitSize%8]
		// Check if scalar is in the correct range.
		if new(big.Int).SetBytes(buf).Cmp(N) >= 0 {
			continue
		}
		break
	}

	return buf, new(big.Int).SetBytes(buf), nil
}
