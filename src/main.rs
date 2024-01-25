use hex::{decode, encode};
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

fn public_key_to_address(public_key_hex: &str) -> String {
    let mut hasher: Keccak256 = Keccak256::new();
    hasher.update(public_key_hex);
    let results: sha3::digest::generic_array::GenericArray<u8, _> = hasher.finalize();
    let last: &str = &encode(results)[24..];
    last.to_string()
}

fn generate_private_key() -> String {
    // Generate a random 256-bit private key
    let private_key: [u8; 32] = rand::thread_rng().gen();

    // Convert the bytes to a hexadecimal string
    let private_key_hex = encode(private_key);

    private_key_hex
}

fn private_key_to_public_key(private_key_hex: &str) -> String {
    // Parse the private key from the hexadecimal string
    let private_key_bytes = decode(private_key_hex).expect("Failed to decode private key");
    // println!("{private_key_bytes:?}");
    let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");

    // Create a secp256k1 context
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

    // Calculate the corresponding public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Serialize the public key to a hexadecimal string
    let public_key_hex = public_key.serialize_uncompressed();

    //convert to hex
    let public_key_hex_str = encode(public_key_hex);

    public_key_hex_str
}

fn main() {
    let private_key = generate_private_key();
    let public_key = private_key_to_public_key(&private_key);
    let address = public_key_to_address(&public_key);
    println!("Private Key: {}", private_key);
    println!("Public Key: {}", public_key);
    println!("Address: {}", address);
}
