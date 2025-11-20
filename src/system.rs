use crate::protocol::ZKPProtocol;
use num_bigint::BigUint;

/// Builder for configuring and creating a `ZKPSystem`.
///
/// This struct allows for a flexible way to set up the parameters of the ZKP system.
/// All parameters (p, q, alpha, beta) must be set before calling `build`.
pub struct ZKPSystemBuilder {
    p: Option<BigUint>,
    q: Option<BigUint>,
    alpha: Option<BigUint>,
    beta: Option<BigUint>,
}

impl ZKPSystemBuilder {
    /// Creates a new `ZKPSystemBuilder` with no parameters set.
    pub fn new() -> Self {
        Self {
            p: None,
            q: None,
            alpha: None,
            beta: None,
        }
    }

    /// Sets the prime modulus `p`.
    pub fn with_prime(mut self, prime: BigUint) -> Self {
        self.p = Some(prime);
        self
    }

    /// Sets the prime order `q` of the subgroup.
    pub fn with_order(mut self, order: BigUint) -> Self {
        self.q = Some(order);
        self
    }

    /// Sets the first generator `alpha`.
    pub fn with_generator(mut self, generator: BigUint) -> Self {
        self.alpha = Some(generator);
        self
    }

    /// Sets the second generator `beta`.
    pub fn with_second_generator(mut self, generator: BigUint) -> Self {
        self.beta = Some(generator);
        self
    }

    /// Builds the `ZKPSystem` with the configured parameters.
    ///
    /// # Returns
    ///
    /// * `Ok(ZKPSystem)` if all required parameters are set.
    /// * `Err(&'static str)` if any parameter is missing.
    pub fn build(self) -> Result<ZKPSystem, &'static str> {
        let p = self.p.ok_or("Prime p is required")?;
        let q = self.q.ok_or("Order q is required")?;
        let alpha = self.alpha.ok_or("Generator alpha is required")?;
        let beta = self.beta.ok_or("Second generator beta is required")?;

        Ok(ZKPSystem::new(p, q, alpha, beta))
    }
}

/// Represents the Chaum-Pedersen Zero-Knowledge Proof System.
///
/// This struct holds the system parameters and implements the `ZKPProtocol` trait.
pub struct ZKPSystem {
    parameters: ZKPParameters,
}

impl ZKPSystem {
    /// Creates a new `ZKPSystem` with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `p` - The prime modulus.
    /// * `q` - The prime order of the subgroup.
    /// * `alpha` - The first generator.
    /// * `beta` - The second generator.
    pub fn new(p: BigUint, q: BigUint, alpha: BigUint, beta: BigUint) -> Self {
        Self {
            parameters: ZKPParameters { p, q, alpha, beta },
        }
    }

    /// Returns a new `ZKPSystemBuilder` for constructing a `ZKPSystem`.
    pub fn builder() -> ZKPSystemBuilder {
        ZKPSystemBuilder::new()
    }

    /// Returns a reference to the system parameters.
    pub fn parameters(&self) -> &ZKPParameters {
        &self.parameters
    }
}

impl ZKPProtocol for ZKPSystem {
    fn compute_commitments(&self, randomness: &BigUint) -> (BigUint, BigUint) {
        self.parameters.compute_commitments(randomness)
    }

    fn compute_response(
        &self,
        randomness: &BigUint,
        challenge: &BigUint,
        secret: &BigUint,
    ) -> BigUint {
        self.parameters
            .compute_response(randomness, challenge, secret)
    }

    fn verify(
        &self,
        commitments: (&BigUint, &BigUint),
        challenge: &BigUint,
        response: &BigUint,
        public_keys: (&BigUint, &BigUint),
    ) -> bool {
        self.parameters
            .verify(commitments, challenge, response, public_keys)
    }

    fn compute_public_values(&self, secret: &BigUint) -> (BigUint, BigUint) {
        self.parameters.compute_public_keys(secret)
    }

    fn get_order(&self) -> &BigUint {
        &self.parameters.q
    }
}

/// Holds the immutable parameters of the ZKP system.
#[derive(Debug, Clone)]
pub struct ZKPParameters {
    /// The prime modulus.
    pub p: BigUint,
    /// The prime order of the subgroup.
    pub q: BigUint,
    /// The first generator.
    pub alpha: BigUint,
    /// The second generator.
    pub beta: BigUint,
}

impl ZKPParameters {
    /// Computes the public keys corresponding to a secret.
    ///
    /// y1 = alpha^x mod p
    /// y2 = beta^x mod p
    pub fn compute_public_keys(&self, secret: &BigUint) -> (BigUint, BigUint) {
        let y1 = self.alpha.modpow(secret, &self.p);
        let y2 = self.beta.modpow(secret, &self.p);
        (y1, y2)
    }

    /// Computes the commitments for the proof.
    ///
    /// r1 = alpha^k mod p
    /// r2 = beta^k mod p
    pub fn compute_commitments(&self, randomness: &BigUint) -> (BigUint, BigUint) {
        let r1 = self.alpha.modpow(randomness, &self.p);
        let r2 = self.beta.modpow(randomness, &self.p);
        (r1, r2)
    }

    /// Computes the response to the challenge.
    ///
    /// s = k - c * x mod q
    pub fn compute_response(
        &self,
        randomness: &BigUint,
        challenge: &BigUint,
        secret: &BigUint,
    ) -> BigUint {
        if *randomness >= challenge * secret {
            (randomness - challenge * secret).modpow(&BigUint::from(1u32), &self.q)
        } else {
            &self.q - (challenge * secret - randomness).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    /// Verifies the proof.
    ///
    /// Checks if:
    /// r1 == alpha^s * y1^c mod p
    /// r2 == beta^s * y2^c mod p
    pub fn verify(
        &self,
        commitments: (&BigUint, &BigUint),
        challenge: &BigUint,
        response: &BigUint,
        public_keys: (&BigUint, &BigUint),
    ) -> bool {
        let (r1, r2) = commitments;
        let (y1, y2) = public_keys;

        let cond1 = *r1
            == (&self.alpha.modpow(response, &self.p) * y1.modpow(challenge, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        let cond2 = *r2
            == (&self.beta.modpow(response, &self.p) * y2.modpow(challenge, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        cond1 && cond2
    }
}
