package main
import (
	"fmt"
	"flag"
	"math/rand"
	"math"
	"math/big"
)

func encrypt(p, alfa, B, m int, debug_bool bool) (float64, float64) {
	p_ := float64(p)
	alfa_ := float64(alfa)
	B_ := float64(B)
	m_ := float64(m)
	a := rand.Intn(p)
	a = 4
	a_ := float64(a)
	// Ke = (alfa^a)mod(p)
	Ke := math.Mod( math.Pow(alfa_, a_) , p_)
	// K = (B^a)mod(p)
	K := math.Mod( math.Pow(B_, a_) , p_)
	// y = (x*K)mod(p)
	y := math.Mod( (m_*K) , p_)
	if debug_bool == true {
		fmt.Printf("Plaintext message: %v\n", m_)
		fmt.Printf("Public key:        (%v,%v,%v)\n", p_, alfa_, B_)
		fmt.Printf("Shared key (K):    %v\n", K)
		fmt.Printf("Ephemeral key:     %v\n", Ke)
		fmt.Printf("Encrypted message: %v\n", y)
		fmt.Printf("Bob sends (Ke, y): (%v,%v)\n", Ke, y)
	}
	// Return (Ke,y)
	return Ke,y
}


func decrypt(p, alfa, b, m, Ke int, debug_bool bool) *big.Int {
	var Ke_, b_, p_, m_, alfa_ = big.NewInt(int64(Ke)), big.NewInt(int64(b)), big.NewInt(int64(p)), big.NewInt(int64(m)), big.NewInt(int64(alfa))
	// K = (Ke^b)mod(p)
	K := Ke_.Exp(Ke_, b_, p_)
	// x = (y*inverse(K, p)) % p
	K_inverse      := K.ModInverse(K,p_)
	y_mul_inversek := m_.Mul(m_, K_inverse)
	x := m_.Mod(y_mul_inversek, p_)
	if debug_bool == true {
		fmt.Printf("Private key:            (%v,%v,%v)\n", p_, alfa_, b_)
		fmt.Printf("Alice receives (Ke, y): (%v,%v)\n", Ke, m)	
		fmt.Printf("Shared key (K):         %v\n", K)
		fmt.Printf("Decrypted message:      %v\n", x)
	}
	return x
}


func gcd_calc(a, b int) int {
   var bgcd func(a, b, res int) int
   bgcd = func(a, b, res int) int {
      switch {
         case a == b:
            return res * a
         case a % 2 == 0 && b % 2 == 0:
            return bgcd(a/2, b/2, 2*res)
         case a % 2 == 0:
            return bgcd(a/2, b, res)
         case b % 2 == 0:
            return bgcd(a, b/2, res)
         case a > b:
            return bgcd(a-b, b, res)
         default:
            return bgcd(a, b-a, res)
      }
   }
   return bgcd(a, b, 1)
}

func sign(p, alfa, b, m int, debug_bool bool) (*big.Int, *big.Int) {
	//  Ephemeral key is random
	Ke   := rand.Intn(p-2)
	Ke = 31
	//gcd_ := 0
	for gcd_calc(Ke, (p-1)) != 1 {
		Ke = rand.Intn(p-2)
		//fmt.Println(Ke)
		//gcd_ = gcd_calc(Ke, 540)
		//fmt.Println(gcd_)
	}
	// K = (Ke^b)mod(p)
	var Ke_, alfa_, b_, p_, m_ = big.NewInt(int64(Ke)), big.NewInt(int64(alfa)), big.NewInt(int64(b)), big.NewInt(int64(p)), big.NewInt(int64(m))
	// r = pow(alfa, Ke, p)
	r    := alfa_.Exp(alfa_, Ke_, p_)
	// s = ((m-b*r)*Ke^(-1))mod(p-1)
	aux0 := p_.Sub(p_,big.NewInt(int64(1))  )
	Ke_inverse      := Ke_.ModInverse(Ke_, aux0)
	aux2 := m_.Sub(m_, b_.Mul(b_, r) )
	aux3 := aux2.Mul(aux2, Ke_inverse)
	s    := aux3.Mod(aux3, aux0)
	if debug_bool == true {
		fmt.Printf("Message:                %v\n", m)
		fmt.Printf("Private key:            (%v,%v,%v)\n", p, alfa, b)
		fmt.Println("Ephemeral key:         ", Ke)
		fmt.Printf("Signature (r,s):        (%v,%v)\n", r, s)
	}
	return r, s
}


func verify(p, alfa, B, m, r, s int, debug_bool bool) bool {
	var p_, alfa_, B_, m_, r_, s_ = big.NewInt(int64(p)), big.NewInt(int64(alfa)), big.NewInt(int64(B)), big.NewInt(int64(m)), big.NewInt(int64(r)), big.NewInt(int64(s))
	// Parameter t calculation -> t = ((B^r*r^s))mod(p)
	var aux1, _ = new(big.Int).SetString((B_.Exp(B_, r_, p_)).Text(10), 10)
	aux2 := aux1.Uint64()	
	var aux3, _ = new(big.Int).SetString((B_.Exp(r_, s_, p_)).Text(10), 10)
	aux4 := aux3.Uint64()
	aux5 := big.NewInt(int64(aux2*aux4))
	t1    := B_.Mod(aux5, p_)
	// (alfa^m)mod(p)
	t2 := alfa_.Exp(alfa_, m_, p_)
    // Comparison between parameter t and (alfa^m)mod(p)
    verification := ( t1.Cmp(t2) == 0)
	if debug_bool == true {
		fmt.Printf("Plaintext message:       %v\n", m)
		fmt.Printf("Public key:              (%v,%v,%v)\n", p_, alfa_, B_)
		fmt.Printf("Signature (r,s):         (%v,%v)\n", r, s)
		fmt.Printf("Calculated t:            %v\n", t1)
		fmt.Printf("Verification:            %v\n", verification)
		
	}
	return verification 
}


func main() {
    encrypt_bool := flag.Bool("encrypt", false, "Measure unique values of a metric.")
    alfa := flag.Int("alfa", 1234, "help message for flagname")
    p := flag.Int("p", 1234, "help message for flagname")
    B := flag.Int("B", 1234, "help message for flagname")
    
    decrypt_bool := flag.Bool("decrypt", false, "Measure unique values of a metric.")
    b := flag.Int("b", 1234, "help message for flagname")
    Ke := flag.Int("Ke", 1234, "help message for flagname")

    sign_bool := flag.Bool("sign", false, "Measure unique values of a metric.")
    verify_bool := flag.Bool("verify", false, "Measure unique values of a metric.")
    r := flag.Int("r", 1234, "help message for flagname")
    s := flag.Int("s", 1234, "help message for flagname")
    
    m := flag.Int("m", 1234, "help message for flagname")
    debug_bool := flag.Bool("debug", false, "Measure unique values of a metric.")
    flag.Parse()
	
	if *encrypt_bool == true {
		fmt.Println("Encrypting...")
		Ke, y := encrypt(*p, *alfa, *B, *m, *debug_bool)
		fmt.Printf("(Ke, y) = (%v,%v)\n", Ke, y)
	} else if *decrypt_bool == true{
		fmt.Println("Decrypting...")
		x := decrypt(*p, *alfa, *b, *m, *Ke, *debug_bool)
		fmt.Println(x)
	} else if *sign_bool == true{
		fmt.Println("Signing...")
		r, s := sign(*p, *alfa, *b, *m, *debug_bool)
		fmt.Printf("(r, s) = (%v,%v)\n", r, s)
	} else if *verify_bool == true{
		fmt.Println("Verifying...")
		verified := verify(*p, *alfa, *B, *m, *r, *s, *debug_bool)
		fmt.Printf("Verification =  %v\n", verified)
	}

}