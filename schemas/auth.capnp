@0xfe2ec1d45ede10e6;

interface Auth {
  register @0 (request :RegisterRequest) -> (response :RegisterResponse);
  createAuthenticationChallenge @1 (request :AuthenticationChallengeRequest) -> (response :AuthenticationChallengeResponse);
  verifyAuthentication @2 (request :AuthenticationAnswerRequest) -> (response :AuthenticationAnswerResponse);
}

struct RegisterRequest {
  user @0 :Text;
  y1 @1 :Data;
  y2 @2 :Data;
}

struct RegisterResponse {}

struct AuthenticationChallengeRequest {
  user @0 :Text;
  r1 @1 :Data;
  r2 @2 :Data;
}

struct AuthenticationChallengeResponse {
  authId @0 :Text;
  c @1 :Data;
}

struct AuthenticationAnswerRequest {
  authId @0 :Text;
  s @1 :Data;
}

struct AuthenticationAnswerResponse {
  sessionId @0 :Text;
}
