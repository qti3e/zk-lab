use bls12_381::hash_to_curve::*;
use bls12_381::*;
use group::Curve;

#[allow(non_snake_case)]
fn main() {
    // We have two dealers f and g, they both come up with a secret polynomial
    // on their own, the coefficients are not shared.
    //
    // f(x) = 3x^2 + 8x + 5;
    // g(x) = 9x^2 + 3x + 19;
    //
    // Notice that both of these polynomials are of the degree 2. Which means
    // at least 3 points are required to represent the same polynomials. We
    // will have have 5 shares, which means any 3 of the shares will be enough
    // for generating a valid signature on behalf of the group.
    //
    // The idea is to use the polynomial `h(x) = f(x) + g(x)` as the final polynomial
    // that we chose the secret points from.
    // So even if only one of the dealers is honest, we can guarantee the secrecy
    // of `h(x)`.

    let f_coefficients: Vec<u64> = vec![5, 8, 3];
    let g_coefficients: Vec<u64> = vec![19, 3, 9];

    // Each dealer computes the points (k, y) for 0<k<6, these are the secrets
    // we will associated each `k` with one of the nodes interested in having a
    // share, and secretly communicate the the value of y to only that specific
    // node.
    let f_points = (1..=5)
        .map(|x| (x, compute_polynomial(&f_coefficients, x)))
        .collect::<Vec<_>>();
    let g_points = (1..=5)
        .map(|x| (x, compute_polynomial(&g_coefficients, x)))
        .collect::<Vec<_>>();

    println!("F points = {:?}", f_points);
    println!("G points = {:?}", g_points);

    // Now it's time to generate the data that can be used for validating the shares
    // publicly.
    let G = G1Affine::generator();

    // Public coefficients.
    let f_public_coefficients = f_coefficients
        .iter()
        .map(|a| G * Scalar::from(*a))
        .collect::<Vec<_>>();
    let g_public_coefficients = g_coefficients
        .iter()
        .map(|a| G * Scalar::from(*a))
        .collect::<Vec<_>>();

    // Public pairs.
    let f_public_points = f_points
        .iter()
        .map(|(x, y)| (*x, G * Scalar::from(*y)))
        .collect::<Vec<_>>();
    let g_public_points = g_points
        .iter()
        .map(|(x, y)| (*x, G * Scalar::from(*y)))
        .collect::<Vec<_>>();

    // Now each node should verify their share:
    // 1. Does the `y` passed to the node actually generates the public yG?
    //    which is to recompute yG for the y that we have, and expect it to
    //    be equal to yG in the f/g_public_points.
    // 2. Does every (x, yG) belongs to `f(x) . G = ∑ (a_i * G) * x^i`?

    // Step 1:
    for node in 0..5 {
        let (_, f) = f_points[node];
        let (_, fG) = f_public_points[node];
        let t = (G * Scalar::from(f)).to_affine();
        assert_eq!(t, fG.to_affine());

        let (_, g) = g_points[node];
        let (_, gG) = g_public_points[node];
        let t = (G * Scalar::from(g)).to_affine();
        assert_eq!(t, gG.to_affine());
    }

    // Step 2:
    let f_p = (1..=5)
        .map(|x| (x, compute_polynomial_g(&f_public_coefficients, x)))
        .collect::<Vec<_>>();
    let g_p = (1..=5)
        .map(|x| (x, compute_polynomial_g(&g_public_coefficients, x)))
        .collect::<Vec<_>>();

    assert_eq!(f_p, f_public_points);
    assert_eq!(g_p, g_public_points);

    println!("Verification finished without any complaints.");
    println!("Each node has their share of f and g.");

    // Now that each node has an (x, y) on both f and g, they can use this
    // information to compute a point on h.

    let h_public_coefficients = f_public_coefficients
        .iter()
        .zip(&g_public_coefficients)
        .map(|(f, g)| f + g)
        .collect::<Vec<_>>();

    let shares = f_points
        .iter()
        .zip(&g_points)
        .map(|((x, f), (_, g))| (*x, f + g))
        .collect::<Vec<_>>();

    println!("H points = {:?}", shares);

    // If we're using `h(0)` as the private key, then `h(0) * G` is gonna be the public
    // key, which can be obtained by aggregating our public information.
    let public_key = compute_polynomial_g(&h_public_coefficients, 0).to_affine();
    println!("Public key = {:#?}", public_key);

    // Now we're gonna sign a message with only 3 nodes.

    // First we hash the message to a point M in the curve.
    let M = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        "Hello world",
        "test DST".as_ref(),
    )
    .to_affine();

    // Each of the participants (we said we're gonna use only 3) sends the value of
    // `(x, yM)`.
    let mut sign_shares = shares[0..3]
        .iter()
        .map(|(x, y)| (*x, M * Scalar::from(*y)))
        .collect::<Vec<_>>();

    // Node 4 returns an invalid signature share. This can mess with the final
    // signature and invalidate it. So we will detect it by the following
    // verifications:
    // 1. (x, yG) is a valid point on H(x) * G
    // 2. e(yG, M) == e(G, yM)

    sign_shares.push((4, M * Scalar::from(29)));

    let nodes = sign_shares.len();
    println!("Using {} nodes to sign the message", sign_shares.len());

    // Disqualify invalid shares.
    let sign_shares = sign_shares
        .into_iter()
        .filter(|(x, yM)| {
            let node = (x - 1) as usize;
            let yG = (f_public_points[node].1 + g_public_points[node].1).to_affine();

            let l = pairing(&yG, &M);
            let r = pairing(&G, &yM.to_affine());

            l == r
        })
        .collect::<Vec<_>>();

    println!(
        "Validated {} shares ({} node(s) sent invalid share.)",
        sign_shares.len(),
        nodes - sign_shares.len()
    );

    // We now have 3 points `(x, yM)` which means we can compute `h(0) * M` which
    // is the signature.
    let sign = aggregate_shares(&sign_shares);

    println!("Sign={:#?}", sign);

    // Now we want to validate this sign.
    let left = pairing(&public_key, &M);
    let right = pairing(&G, &sign);

    println!("L={:#?}", left);
    println!("R={:#?}", right);
    assert_eq!(left, right);

    println!("Signature validated.")
}

/// Given a vector of coefficients `[a_i]` computes `f(x) = ∑ a_i * x^i`
fn compute_polynomial(coefficients: &Vec<u64>, x: u64) -> u64 {
    coefficients
        .iter()
        .enumerate()
        .map(|(i, a)| a * x.pow(i as u32))
        .sum::<u64>()
}

/// Given a vector of coefficients `[a_i * G]` computes `f(x) = ∑ a_i * G * x^i`
fn compute_polynomial_g(coefficients: &Vec<G1Projective>, x: u64) -> G1Projective {
    coefficients
        .iter()
        .enumerate()
        .map(|(i, a)| a * Scalar::from(x.pow(i as u32)))
        .sum::<G1Projective>()
}

/// Given a set of points `(x, yM)` computes `h(0) * M`.
#[allow(non_snake_case)]
fn aggregate_shares(shares: &Vec<(u64, G2Projective)>) -> G2Affine {
    let mut result = G2Projective::generator();

    for (xj, yM) in shares {
        let mut r = 1.0;
        for (xm, _) in shares {
            if xj != xm {
                let xm = *xm as f64;
                let xj = *xj as f64;
                r *= xm / (xm - xj);
            }
        }
        let r = r as i64;

        let t = if r < 0 {
            -(yM * Scalar::from((-r) as u64))
        } else {
            yM * Scalar::from(r as u64)
        };

        result += t;
    }

    result -= G2Projective::generator();

    result.to_affine()
}
