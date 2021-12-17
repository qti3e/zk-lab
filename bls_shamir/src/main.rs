use bls12_381::hash_to_curve::*;
use bls12_381::*;
use group::Curve;

/// A threshold sign using a secret polynomial f(x), using f(0) as the private
/// key.
#[allow(non_snake_case)]
fn main() {
    let G = G1Affine::generator();

    // Each node computes a random point and holds it as their secret share.
    // this values were hand chosen from the simple `F(x) = 5x + 3` polynomial.
    let secret_points = vec![(8u64, 43u64), (16, 83)];

    // Now each node emits public points (x, yG).
    let public_points = secret_points
        .iter()
        .cloned()
        .map(|(x, y)| (x, G * Scalar::from(y)))
        .collect::<Vec<_>>();

    // Compute f(0) using secret points, this is used for demo.
    let private_key = mul_zero(&secret_points)
        .into_iter()
        .map(|(m, y)| m * (*y as i64))
        .sum::<i64>() as u64;

    // We should be able to compute `f(0) * G` using the public points.
    let public_key = mul_zero(&public_points)
        .into_iter()
        .map(projective_mul)
        .sum::<G1Projective>()
        .to_affine();

    // Show that we indeed have the right `f(0) * G`.
    let t = (G * Scalar::from(private_key)).to_affine();
    println!("Private key={:#?}", private_key);
    println!("Public key(1)={:#?}", t);
    println!("Public key(2)={:#?}", public_key);
    assert_eq!(t, public_key);

    // Now we want to encrypt a message. From BLS we remember that:
    // Private key = a
    // Public key  = a * G
    // Signature   = a * M
    //
    // And we would use the following identity to verify the signature.
    // e(Public key, M) = e(aG, M) = e(G, aM) = e(G, Signature)
    //
    // Now we want to use f(0) as our private key, so:
    // Private key = f(0)
    // Public key  = f(0) * G
    // Signature   = f(0) * M
    //
    // As we've seen we have been able to produce the value of our public key,
    // the next step is to sign a message M, which is to compute `f(0) * M`.

    // First we hash the message to a point M in the curve.
    let M = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        "Hello world",
        "test DST".as_ref(),
    )
    .to_affine();

    // Now each of the nodes will send their share (x, yM).
    let sign_points = secret_points
        .iter()
        .map(|(x, y)| (*x, M * Scalar::from(*y)))
        .collect::<Vec<_>>();

    // Now having all of the (x, yM) points, we can compute `f(0) * M`.
    let sign = mul_zero(&sign_points)
        .into_iter()
        .map(projective_mul)
        .sum::<G2Projective>()
        .to_affine();

    println!("Sign={:#?}", sign);

    // Now we want to validate this sign.
    let left = pairing(&public_key, &M);
    let right = pairing(&G, &sign);

    println!("L={:#?}", left);
    println!("R={:#?}", right);
    assert_eq!(left, right);

    println!("Signature validated.")
}

fn mul_zero<T: std::fmt::Debug>(points: &Vec<(u64, T)>) -> Vec<(i64, &T)> {
    points
        .iter()
        .map(|(x, y)| {
            let xj = *x as f64;
            let mut r = 1.0;

            for (xm, _) in points {
                if xm != x {
                    let xm = *xm as f64;
                    r *= xm / (xm - xj);
                }
            }

            assert_eq!(r as i64 as f64, r);

            (r as i64, y)
        })
        .collect::<Vec<_>>()
}

fn projective_mul<'a, T: 'a + std::ops::Neg<Output = T>>((m, y): (i64, &'a T)) -> T
where
    &'a T: std::ops::Mul<Scalar, Output = T>,
{
    if m < 0 {
        let m = (-m) as u64;
        -(y * Scalar::from(m))
    } else {
        let m = m as u64;
        y * Scalar::from(m)
    }
}
