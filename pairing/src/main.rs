use bls12_381::{pairing, G1Affine, G2Affine, Scalar};

/// To demonstrate the basic property of EC pairing which is:
///
/// e(P, Q + R) = e(P, Q) + e(P, R).
#[allow(non_snake_case)]
fn main() {
    let G = G1Affine::generator();
    let H = G2Affine::generator();

    let s = Scalar::from(12);
    let P = G * s;
    let PAffine = G1Affine::from(&P);

    let s = Scalar::from(15);
    let Q = H * s;
    let QAffine = G2Affine::from(&Q);

    let s = Scalar::from(13);
    let R = H * s;
    let RAffine = G2Affine::from(&R);

    let e = pairing(&PAffine, &G2Affine::from(Q + R));
    println!("e(P, Q + R) = {:?}", e);

    let l = pairing(&PAffine, &QAffine);
    let r = pairing(&PAffine, &RAffine);
    let t = l + r;
    println!("e(P, Q) * e(P, R) = {:?}", t);

    assert_eq!(e, t);
}
