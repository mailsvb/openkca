package pki

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
)

// DH parameter sizes XCA accepts.
const (
	DHMinBits = 1024
	DHMaxBits = 4096
)

var smallPrimes = func() []uint64 {
	var out []uint64
	sieve := make([]bool, 20000)
	for i := 2; i < len(sieve); i++ {
		if !sieve[i] {
			out = append(out, uint64(i))
			for j := i * i; j < len(sieve); j += i {
				sieve[j] = true
			}
		}
	}
	return out
}()

// GenerateDHParams creates Diffie-Hellman parameters like
// DH_generate_parameters_ex(dh, bits, 2): a safe prime p = 2q+1 with
// p ≡ 23 (mod 24), so that the generator 2 has order q. It searches on all
// CPUs; tried is increased per candidate for progress reports. The result
// is the PEM "DH PARAMETERS" block.
func GenerateDHParams(ctx context.Context, bits int, tried *atomic.Int64) ([]byte, error) {
	if bits < DHMinBits || bits > DHMaxBits {
		return nil, errors.New("DH parameters need 1024 to 4096 bits")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := make(chan *big.Int, 1)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p := searchSafePrime(ctx, bits, tried); p != nil {
				select {
				case found <- p:
					cancel()
				default:
				}
			}
		}()
	}
	wg.Wait()
	select {
	case p := <-found:
		der, err := asn1.Marshal(struct{ P, G *big.Int }{p, big.NewInt(2)})
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: der}), nil
	default:
		return nil, ctx.Err()
	}
}

func searchSafePrime(ctx context.Context, bits int, tried *atomic.Int64) *big.Int {
	const window = 1 << 14
	one := big.NewInt(1)
	q, p, m := new(big.Int), new(big.Int), new(big.Int)
	twelve, eleven := big.NewInt(12), big.NewInt(11)
	res := make([]uint64, len(smallPrimes))
	buf := make([]byte, (bits-1+7)/8)
	for ctx.Err() == nil {
		if _, err := rand.Read(buf); err != nil {
			return nil
		}
		q.SetBytes(buf)
		// bits-1 bits with the top two set, so that p has exactly bits
		q.Rsh(q, uint(len(buf)*8-(bits-1)))
		q.SetBit(q, bits-2, 1)
		q.SetBit(q, bits-3, 1)
		// q ≡ 11 (mod 12)  <=>  p = 2q+1 ≡ 23 (mod 24)
		m.Mod(q, twelve)
		q.Sub(q, m).Add(q, eleven)
		for i, sp := range smallPrimes {
			res[i] = m.Mod(q, m.SetUint64(sp)).Uint64()
		}
		// candidates q + 12k: sieve q and 2q+1 by the small primes
		for k := uint64(0); k < window && ctx.Err() == nil; k++ {
			if tried != nil {
				tried.Add(1)
			}
			composite := false
			for i, sp := range smallPrimes {
				rq := (res[i] + 12*k) % sp
				if rq == 0 || (2*rq+1)%sp == 0 {
					composite = true
					break
				}
			}
			if composite {
				continue
			}
			c := new(big.Int).Add(q, new(big.Int).SetUint64(12*k))
			p.Lsh(c, 1).Add(p, one)
			if p.BitLen() == bits && c.ProbablyPrime(1) && p.ProbablyPrime(1) && c.ProbablyPrime(20) && p.ProbablyPrime(20) {
				return new(big.Int).Set(p)
			}
		}
	}
	return nil
}
