from Crypto.PublicKey import RSA
import argparse

def main(filename):
    try:
        with open(filename, "r") as file:
            key = RSA.importKey(file.read())
            print("Modulus (n):", key.n)
            print("Public Exponent (e):", key.e)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    except ValueError:
        print(f"Error: Could not import key from '{filename}'. Ensure it's a valid RSA public key.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Display RSA public key parameters (n and e).")
    parser.add_argument("filename", type=str, help="Path to the RSA public key file.")
    args = parser.parse_args()
    
    main(args.filename)
