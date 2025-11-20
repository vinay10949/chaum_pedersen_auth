//! # Chaum-Pedersen Zero-Knowledge Proof Authentication Library
//!
//! This library implements the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol for authentication.
//! It allows a prover to demonstrate knowledge of a discrete logarithm without revealing the secret value itself.


pub mod actors;
pub mod protocol;
pub mod system;
pub mod utils;

pub use actors::{Prover, Verifier};
pub use protocol::ZKPProtocol;
pub use system::{ZKPParameters, ZKPSystem, ZKPSystemBuilder};
pub use utils::ZKPUtils;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_with_builder_pattern() {
        let (alpha, beta, p, q) = ZKPUtils::get_1024_bit_constants();

        let system = ZKPSystem::builder()
            .with_prime(p)
            .with_order(q)
            .with_generator(alpha)
            .with_second_generator(beta)
            .build()
            .expect("Failed to build ZKP system");

        let secret = ZKPUtils::generate_random_below(system.get_order());
        let prover = Prover::new(&system, secret);

        let challenge = ZKPUtils::generate_random_below(system.get_order());
        let (commitments, randomness) = prover.generate_commitments();

        let response = prover.generate_response(&challenge, &randomness);

        let verifier = Verifier::new(&system);
        let result = verifier.verify(
            (&commitments.0, &commitments.1),
            &challenge,
            &response,
            (&prover.public_values().0, &prover.public_values().1),
        );

        assert!(result);
    }

    #[test]
    fn test_1024_bits_constants() {
        let (alpha, beta, p, q) = ZKPUtils::get_1024_bit_constants();
        let system = ZKPSystem::new(p, q, alpha, beta);

        let secret = ZKPUtils::generate_random_below(system.get_order());
        let prover = Prover::new(&system, secret);

        let challenge = ZKPUtils::generate_random_below(system.get_order());
        let (commitments, randomness) = prover.generate_commitments();

        let response = prover.generate_response(&challenge, &randomness);

        let verifier = Verifier::new(&system);
        let result = verifier.verify(
            (&commitments.0, &commitments.1),
            &challenge,
            &response,
            (&prover.public_values().0, &prover.public_values().1),
        );

        assert!(result);
    }

    #[test]
    fn test_2048_bits_constants() {
        let (alpha, beta, p, q) = ZKPUtils::get_2048_bit_constants();
        let system = ZKPSystem::new(p, q, alpha, beta);

        let secret = ZKPUtils::generate_random_below(system.get_order());
        let prover = Prover::new(&system, secret);

        let challenge = ZKPUtils::generate_random_below(system.get_order());
        let (commitments, randomness) = prover.generate_commitments();

        let response = prover.generate_response(&challenge, &randomness);

        let verifier = Verifier::new(&system);
        let result = verifier.verify(
            (&commitments.0, &commitments.1),
            &challenge,
            &response,
            (&prover.public_values().0, &prover.public_values().1),
        );

        assert!(result);
    }
}
