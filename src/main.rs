use std::str::FromStr;

use bip39::Mnemonic;
use miniscript::bitcoin::{
	secp256k1::Secp256k1,
	network::constants::Network,
	util::bip32::{
    	ExtendedPrivKey, ExtendedPubKey, DerivationPath
	}
};
use miniscript::{
    DescriptorTrait, DescriptorPublicKey, TranslatePk2
};

fn main() {
	// Bitcoin mainnet
    let net = Network::Bitcoin;
    // bip-39 recovery phrase
    let mnemonic = Mnemonic::parse(
    	"carbon exile split receive diet either hunt lava math amount hover sheriff"
    ).unwrap();
    // mnemonic to seed with empty password
    let seed = mnemonic.to_seed("");
    // context for libsecp256k1
    let secp_ctx = Secp256k1::new();

    // generate root bip-32 key from seed
    let root = ExtendedPrivKey::new_master(net, &seed).unwrap();
    // fingerprint of the root for Core-like key representation
    // 4 first bytes of hash160(sec-pubkey)
    let fingerprint = root.fingerprint(&secp_ctx);

    // default path for bip-84 (native segwit)
    let path = "m/84h/0h/0h";
    let derivation = DerivationPath::from_str(path).unwrap();
    // child private key
    let child = root.derive_priv(&secp_ctx, &derivation).unwrap();
    // corresponding public key
    let xpub = ExtendedPubKey::from_private(&secp_ctx, &child);
    // Core-like xpub string [fingerprint/derivation]xpub
    let key = format!("[{}{}]{}", fingerprint, &path[1..], xpub);
    println!("Child public key at path {}:\n{}\n", path, key);

    // Core recv range descriptor wpkh(xpub/0/*)
    let desc = miniscript::Descriptor::<DescriptorPublicKey>::from_str(
        &format!("wpkh({}/0/*)", key)
    ).unwrap();
    println!("Receiving descriptor:\n{}\n", desc);
    // First 5 addresses corresponding to this descriptor
    println!("First 5 addresses:");
    for idx in 0..5 {
        let addr = desc.derive(idx)
            .translate_pk2(|xpk| xpk.derive_public_key(&secp_ctx)).unwrap()
            .address(net).unwrap();
        println!("{}", addr);
    }
}