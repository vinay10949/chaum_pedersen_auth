use crate::protocol::ZKPProtocol;
use crate::utils::ZKPUtils;
use num_bigint::BigUint;

/// Represents the Prover in the ZKP protocol.
///
/// The Prover holds the secret and interacts with the ZKP system to generate proofs.
pub struct Prover<'a, T: ZKPProtocol> {
    system: &'a T,
    secret: BigUint,
    public_values: (BigUint, BigUint),
}

impl<'a, T: ZKPProtocol> Prover<'a, T> {
    /// Creates a new `Prover`.
    ///
    /// # Arguments
    ///
    /// * `system` - The ZKP system to use.
    /// * `secret` - The secret value `x` to be proven.
    pub fn new(system: &'a T, secret: BigUint) -> Self {
        let public_values = system.compute_public_values(&secret);
        Self {
            system,
            secret,
            public_values,
        }
    }

    /// Generates the commitments for the proof.
    ///
    /// This is the first step of the protocol.
    /// It generates a random value `k` and computes `r1` and `r2`.
    ///
    /// # Returns
    ///
    /// A tuple containing the commitments `((r1, r2), k)`.
    /// The randomness `k` is returned so it can be used in the response step.
    pub fn generate_commitments(&self) -> ((BigUint, BigUint), BigUint) {
        let randomness = ZKPUtils::generate_random_below(self.system.get_order());
        let commitments = self.system.compute_commitments(&randomness);
        (commitments, randomness)
    }

    /// Generates the response to the challenge.
    ///
    /// This is the third step of the Sigma protocol.
    /// It computes `s = k - c * x mod q`.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The challenge `c` received from the verifier.
    /// * `randomness` - The random value `k` used in the commitment step.
    ///
    /// # Returns
    ///
    /// The response value `s`.
    pub fn generate_response(&self, challenge: &BigUint, randomness: &BigUint) -> BigUint {
        self.system
            .compute_response(randomness, challenge, &self.secret)
    }

    /// Returns the public keys associated with the Prover's secret.
    pub fn public_values(&self) -> &(BigUint, BigUint) {
        &self.public_values
    }
}

/// Represents the Verifier in the ZKP protocol.
///
/// The Verifier challenges the Prover and verifies the proof.
pub struct Verifier<'a, T: ZKPProtocol> {
    system: &'a T,
}

impl<'a, T: ZKPProtocol> Verifier<'a, T> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `system` - The ZKP system (or protocol implementation) to use.
    pub fn new(system: &'a T) -> Self {
        Self { system }
    }

    /// Generates a random challenge for the Prover.
    ///
    /// This is the second step of theprotocol.
    ///
    /// # Returns
    ///
    /// A random challenge value `c`.
    pub fn generate_challenge(&self) -> BigUint {
        ZKPUtils::generate_random_below(self.system.get_order())
    }

    /// Verifies the proof provided by the Prover.
    ///
    /// # Arguments
    ///
    /// * `commitments` - The commitments (r1, r2) from the Prover.
    /// * `challenge` - The challenge `c` sent to the Prover.
    /// * `response` - The response `s` from the Prover.
    /// * `public_values` - The public values (y1, y2) claimed by the Prover.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        &self,
        commitments: (&BigUint, &BigUint),
        challenge: &BigUint,
        response: &BigUint,
        public_values: (&BigUint, &BigUint),
    ) -> bool {
        self.system
            .verify(commitments, challenge, response, public_values)
    }
}
