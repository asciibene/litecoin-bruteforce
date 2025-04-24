import ecdsa
import hashlib
import base58
import secrets
from tqdm import *
import colorama


def generate_keypair():
    # Generate private key (32 bytes, 256 bits)
    private_key = secrets.token_bytes(32)

    # Generate public key
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = b'\x04' + verifying_key.to_string()

    # Generate address
    hashed_public_key = hashlib.sha256(public_key).digest()
    ripemd160_public_key = hashlib.new('ripemd160', hashed_public_key).digest()

    # Add network byte (0x00 for Bitcoin mainnet)
    extended_ripemd160_public_key = b'\x00' + ripemd160_public_key
    
    # Add checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160_public_key).digest()).digest()[:4]
    
    # Append checksum to the extended RIPEMD-160 hash
    binary_address = extended_ripemd160_public_key + checksum
    
    # Encode to Base58
    address = base58.b58encode(binary_address).decode('utf-8')

    # Encode private key to WIF format
    extended_private_key = b'\x80' + private_key
    checksum_private_key = hashlib.sha256(hashlib.sha256(extended_private_key).digest()).digest()[:4]
    wif_private_key = base58.b58encode(extended_private_key + checksum_private_key).decode('utf-8')

    return wif_private_key, address

if __name__ == "__main__":
    outfh=open("results.txt","a") 
    itnum=0
    with open("wallets.ltc",'r') as fh:
        while True:
            itnum+=1
            private_key, address = generate_keypair()
            for ln in tqdm(fh, total=8225287, color="blue"):
                if address in ln:
                    #Gotcha!
                    outfh.write(private_key)
                    outfh.write("="*80)
                     
                    #Todo save more details
                    print("Balance Found !!!")
                    
            fh.seek(0) #Go back to file start
            print(f"{itnum} Adresses checked...(last {address})")
            # print("Private Key (WIF):", private_key)
            # print("Address:", address)
            
