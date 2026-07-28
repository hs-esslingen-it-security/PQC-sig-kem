use core::arch::x86_64::_rdtsc;
use std::arch::x86_64::_mm_lfence;

use pqcrypto::kem::{hqc128, hqc192, hqc256, mlkem512, mlkem768, mlkem1024};
use rand_chacha::rand_core::SeedableRng;
use x25519_dalek::SharedSecret;

const ITER: u32 = 100;

unsafe fn run<F: Fn() -> (u64, u64, u64)>(iter: u32, f: F) {
    for _ in 0..iter {
        let (k, s, v) = f();
        println!("{},{},{}", k, s, v);
    }
}

#[inline(always)]
unsafe fn time<F: FnOnce()>(f: F) -> u64 {
    _mm_lfence();
    let start = _rdtsc();
    _mm_lfence();

    f();

    _mm_lfence();
    let end = _rdtsc();
    _mm_lfence();

    end - start
}

pub trait PqKem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret);
    fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret;
}

unsafe fn bench_kem<K: PqKem>() -> (u64, u64, u64) {
    let mut pk: Option<K::PublicKey> = None;
    let mut sk: Option<K::SecretKey> = None;

    let kgen = time(|| {
        let (p, s) = K::keypair();
        pk = Some(p);
        sk = Some(s);
    });

    let mut encap_out: Option<(K::Ciphertext, K::SharedSecret)> = None;
    let encap = time(|| {
        encap_out = Some(K::encapsulate(pk.as_ref().unwrap()));
    });

    let mut decap_out: Option<K::SharedSecret> = None;
    let decap = time(|| {
        let (ct, _) = encap_out.as_ref().unwrap();
        decap_out = Some(K::decapsulate(ct, sk.as_ref().unwrap()));
    });

    (kgen, encap, decap)
}

unsafe fn bench_x25519() -> (u64, u64, u64) {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);

    let (kgen, alice_secret, alice_public, bob_secret, bob_public) = {
        let mut alice_secret = None;
        let mut alice_public = None;
        let mut bob_secret = None;
        let mut bob_public = None;

        let kgen = time(|| {
            let a_sec = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let a_pub = x25519_dalek::PublicKey::from(&a_sec);

            let b_sec = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
            let b_pub = x25519_dalek::PublicKey::from(&b_sec);

            alice_secret = Some(a_sec);
            alice_public = Some(a_pub);
            bob_secret = Some(b_sec);
            bob_public = Some(b_pub);
        });

        (
            kgen,
            alice_secret.unwrap(),
            alice_public.unwrap(),
            bob_secret.unwrap(),
            bob_public.unwrap(),
        )
    };

    let mut alice_shared_secret: Option<SharedSecret> = None;

    let alice = time(|| {
        alice_shared_secret = Some(alice_secret.diffie_hellman(&bob_public));
    });

    let mut bob_shared_secret: Option<SharedSecret> = None;

    let bob = time(|| {
        bob_shared_secret = Some(bob_secret.diffie_hellman(&alice_public));
    });

    (kgen, bob, alice)
}

macro_rules! impl_kem {
    ($name:ident, $module:ident) => {
        pub struct $name;

        impl PqKem for $name {
            type PublicKey = $module::PublicKey;
            type SecretKey = $module::SecretKey;
            type Ciphertext = $module::Ciphertext;
            type SharedSecret = $module::SharedSecret;

            fn keypair() -> (Self::PublicKey, Self::SecretKey) {
                $module::keypair()
            }

            fn encapsulate(pk: &Self::PublicKey) -> (Self::Ciphertext, Self::SharedSecret) {
                let (ss, ct) = $module::encapsulate(pk);
                (ct, ss)
            }

            fn decapsulate(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret {
                $module::decapsulate(ct, sk)
            }
        }
    };
}

impl_kem!(MlKem512, mlkem512);
impl_kem!(MlKem768, mlkem768);
impl_kem!(MlKem1024, mlkem1024);
impl_kem!(Hqc128, hqc128);
impl_kem!(Hqc192, hqc192);
impl_kem!(Hqc256, hqc256);

fn main() {
    unsafe {
        println!("MlKem512");
        run(ITER, || bench_kem::<MlKem512>());

        println!("MlKem768");
        run(ITER, || bench_kem::<MlKem768>());

        println!("MlKem1024");
        run(ITER, || bench_kem::<MlKem1024>());
        //
        // println!("Hqc128");
        // run(ITER, || bench_kem::<Hqc128>());
        //
        // println!("Hqc192");
        // run(ITER, || bench_kem::<Hqc192>());
        //
        // println!("Hqc256");
        // run(ITER, || bench_kem::<Hqc256>());
        //
        // println!("X25519");
        // run(ITER, || bench_x25519());
    }
}
