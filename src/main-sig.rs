use core::arch::x86_64::_rdtsc;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use std::arch::x86_64::_mm_lfence;

use falcon_rust::{falcon1024, falcon512};
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{Keypair, Signer, Verifier};
use slh_dsa::{Shake128f, Shake128s, Shake192f, Shake192s, Shake256f, Shake256s};

const MSG: &[u8] = b"Hello World";
const ITER: u32 = 50;

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

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0u8; 32])
}

unsafe fn run(iter: u32, f: fn() -> (u64, u64, u64)) {
    for _ in 0..iter {
        let (k, s, v) = f();
        println!("{},{},{}", k, s, v);
    }
}

// ml-dsa
unsafe fn bench_mldsa<K: ml_dsa::MlDsaParams>() -> (u64, u64, u64) {
    let mut rng = rng();

    let mut sk: Option<ml_dsa::SigningKey<K>> = None;
    let mut pk: Option<ml_dsa::VerifyingKey<K>> = None;

    let kgen = unsafe {
        time(|| {
            let kp = K::key_gen(&mut rng);
            pk = Some(kp.verifying_key());
            sk = Some(kp);
        })
    };

    let mut sig: Option<ml_dsa::Signature<K>> = None;
    let sign = time(|| {
        sig = Some(sk.unwrap().sign(&MSG));
    });

    let verify = time(|| {
        let _ = pk.unwrap().verify(MSG, &sig.unwrap());
    });

    (kgen, sign, verify)
}

// rsa
unsafe fn bench_rsa() -> (u64, u64, u64) {
    let mut rng = rng();
    let bits = 2048;

    let mut signing_key: Option<rsa::pkcs1v15::SigningKey::<Sha256>> = None;
    let mut verifying_key: Option<rsa::pkcs1v15::VerifyingKey::<Sha256>> = None;

    let kgen = time(|| {
        let sk = RsaPrivateKey::new(&mut rng, bits).unwrap();
        let pk = RsaPublicKey::from(&sk);
        signing_key = Some(rsa::pkcs1v15::SigningKey::<Sha256>::new(sk));
        verifying_key = Some(rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk));
    });

    let mut sig: Option<rsa::pkcs1v15::Signature> = None;
    let sign = time(|| {
        sig = Some(signing_key.unwrap().sign(MSG));
    });

    let verify = time(|| {
        let _ = verifying_key.unwrap().verify(MSG, &sig.unwrap());
    });

    (kgen, sign, verify)
}

// falcon
unsafe fn bench_falcon512() -> (u64, u64, u64) {
    let mut rng = rng();

    let mut sk: Option<falcon512::SecretKey> = None;
    let mut pk: Option<falcon512::PublicKey> = None;

    let kgen = time(|| {
        let (s, p) = falcon512::keygen(rng.get_seed());
        sk = Some(s);
        pk = Some(p);
    });

    let mut sig: Option<falcon512::Signature> = None;
    let sign = time(|| {
        sig = Some(falcon512::sign(MSG, &sk.unwrap()));
    });

    let verify = time(|| {
        let _ = falcon512::verify(MSG, &sig.unwrap(), &pk.unwrap());
    });

    (kgen, sign, verify)
}

unsafe fn bench_falcon1024() -> (u64, u64, u64) {
    let mut rng = rng();

    let mut sk: Option<falcon1024::SecretKey> = None;
    let mut pk: Option<falcon1024::PublicKey> = None;

    let kgen = time(|| {
        let (s, p) = falcon1024::keygen(rng.get_seed());
        sk = Some(s);
        pk = Some(p);
    });

    let sk = sk.unwrap();
    let pk = pk.unwrap();

    let mut sig: Option<falcon1024::Signature> = None;
    let sign = time(|| {
        sig = Some(falcon1024::sign(MSG, &sk));
    });

    let sig = sig.unwrap();

    let verify = time(|| {
        let _ = falcon1024::verify(MSG, &sig, &pk);
    });

    (kgen, sign, verify)
}

// sphincs
unsafe fn bench_slh<K>() -> (u64, u64, u64)
where
    K: slh_dsa::ParameterSet,
{
    let mut rng = rng();

    let mut sk: Option<slh_dsa::SigningKey<K>> = None;
    let mut vk: Option<_> = None;

    let kgen = time(|| {
        let s = slh_dsa::SigningKey::<K>::new(&mut rng);
        let v = s.verifying_key();
        sk = Some(s);
        vk = Some(v);
    });

    let sk = sk.unwrap();
    let vk = vk.unwrap();

    let mut sig: Option<_> = None;
    let sign = time(|| {
        sig = Some(sk.sign(MSG));
    });

    let sig = sig.unwrap();

    let verify = time(|| {
        let _ = vk.verify(MSG, &sig);
    });

    (kgen, sign, verify)
}

// sqisign
unsafe fn bench_sqisign1() -> (u64, u64, u64) {
    let mut kp: Option<_> = None;

    let kgen = time(|| {
        kp = Some(sqisign_lvl1::generate_keypair().unwrap());
    });

    let kp = kp.unwrap();

    let mut sig: Option<_> = None;
    let sign = time(|| {
        sig = Some(kp.sign(MSG).unwrap());
    });

    let sig = sig.unwrap();

    let verify = time(|| {
        let _ = kp.verify(MSG, &sig);
    });

    (kgen, sign, verify)
}

// unsafe fn bench_sqisign3() -> (u64, u64, u64) {
//     let mut kp: Option<_> = None;
//
//     let kgen = time(|| {
//         kp = Some(sqisign_lvl3::generate_keypair().unwrap());
//     });
//
//     let kp = kp.unwrap();
//
//     let mut sig: Option<_> = None;
//     let sign = time(|| {
//         sig = Some(kp.sign(MSG).unwrap());
//     });
//
//     let sig = sig.unwrap();
//
//     let verify = time(|| {
//         let _ = kp.verify(MSG, &sig);
//     });
//
//     (kgen, sign, verify)
// }
//
// unsafe fn bench_sqisign5() -> (u64, u64, u64) {
//     let mut kp: Option<_> = None;
//
//     let kgen = time(|| {
//         kp = Some(sqisign_lvl5::generate_keypair().unwrap());
//     });
//
//     let kp = kp.unwrap();
//
//     let mut sig: Option<_> = None;
//     let sign = time(|| {
//         sig = Some(kp.sign(MSG).unwrap());
//     });
//
//     let sig = sig.unwrap();
//
//     let verify = time(|| {
//         let _ = kp.verify(MSG, &sig);
//     });
//
//     (kgen, sign, verify)
// }

unsafe fn bench_ed25519() -> (u64, u64, u64) {
    let mut rng = rng();

    let mut sk: Option<ed25519_dalek::SigningKey> = None;
    let mut pk: Option<ed25519_dalek::VerifyingKey> = None;

    let kgen = time(|| {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let s = ed25519_dalek::SigningKey::from_bytes(&seed);
        let p = ed25519_dalek::VerifyingKey::from(&s);
        sk = Some(s);
        pk = Some(p);
    });

    let sk = sk.unwrap();
    let pk = pk.unwrap();

    let mut sig: Option<_> = None;
    let sign = time(|| {
        sig = Some(sk.sign(MSG));
    });

    let sig = sig.unwrap();

    let verify = time(|| {
        let _ = pk.verify(MSG, &sig);
    });

    (kgen, sign, verify)
}

fn main() {
    unsafe {
        println!("mldsa44");
        run(ITER, || bench_mldsa::<MlDsa44>());

        println!("mldsa65");
        run(ITER, || bench_mldsa::<MlDsa65>());

        println!("mldsa87");
        run(ITER, || bench_mldsa::<MlDsa87>());

        println!("rsa");
        run(ITER, || bench_rsa());

        println!("falcon512");
        run(ITER, || bench_falcon512());

        // println!("falcon1024");
        // run(ITER, || bench_falcon1024());
        //
        // println!("slhdsashake128f");
        // run(ITER, || bench_slh::<Shake128f>());
        //
        // println!("slhdsashake128s");
        // run(ITER, || bench_slh::<Shake128s>());
        //
        // println!("slhdsashake192f");
        // run(ITER, || bench_slh::<Shake192f>());
        //
        // println!("slhdsashake192s");
        // run(ITER, || bench_slh::<Shake192s>());
        //
        // println!("slhdsashake256f");
        // run(ITER, || bench_slh::<Shake256f>());
        //
        // println!("slhdsashake256s");
        // run(ITER, || bench_slh::<Shake256s>());

        println!("sqisign1");
        run(ITER, || bench_sqisign1());

        // println!("sqisign3");
        // run(ITER, || bench_sqisign3());
        //
        // println!("sqisign5");
        // run(ITER, || bench_sqisign5());

        println!("ed25519");
        run(ITER, || bench_ed25519());
    }
}
