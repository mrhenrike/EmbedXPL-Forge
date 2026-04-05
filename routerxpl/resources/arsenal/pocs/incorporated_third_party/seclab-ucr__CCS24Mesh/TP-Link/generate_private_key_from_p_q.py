import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from sympy import mod_inverse

def generate_private_key_pem(p, q, public_exponent=65537):
    """Generate a private key in PEM format from given primes p and q."""
    # Calculate modulus n
    n = p * q
    # Calculate Euler's totient function φ(n)
    phi_n = (p - 1) * (q - 1)
    
    # Calculate private exponent d
    d = mod_inverse(public_exponent, phi_n)
    
    # Convert primes into RSA parameters
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = mod_inverse(q, p)
    
    # Construct the private key
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(public_exponent, n)
    ).private_key(default_backend())
    
    # Serialize the private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

def main():
    parser = argparse.ArgumentParser(description="Generate an RSA private key PEM file using given primes p and q.")
    parser.add_argument("p", type=int, help="First large prime number (p)")
    parser.add_argument("q", type=int, help="Second large prime number (q)")
    parser.add_argument("--output", type=str, default="private_key.pem", help="Output file name for the private key (default: private_key.pem)")

    args = parser.parse_args()
    
    # Generate PEM
    pem = generate_private_key_pem(args.p, args.q)
    
    # Save to file
    with open(args.output, "wb") as pem_file:
        pem_file.write(pem)
    
    print(f"Private key saved to '{args.output}'")

if __name__ == "__main__":
    main()
