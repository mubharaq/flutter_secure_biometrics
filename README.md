# Secure Biometrics

A Flutter package that implements secure biometric operations with cryptographic key pairs. This package enables biometric authentication without storing raw biometric data, instead using the device's secure hardware and cryptographic operations.

## Core Features

- 🔐 Biometric authentication using device hardware
- 🔑 RSA key pair generation and secure storage
- 📝 Challenge-response based authentication
- 🔒 Private key protection with biometric access
- 📤 Public key export in PEM format
- ⚡ Failed attempts tracking and management
- 🔄 Fallback mechanisms for key loss

## How It Works

1. Device generates an RSA key pair during setup
2. Private key is stored securely, protected by biometric authentication
3. Public key can be shared with your server
4. Authentication uses challenge-response with cryptographic signatures
5. All biometric operations use device hardware - no biometric data is stored

## Getting Started

### Prerequisites

This package uses `local_auth` for biometric operations and `pointycastle` for the cryptographic operations. Follow platform-specific setup:

See [local_auth documentation](https://pub.dev/packages/local_auth) for detailed setup instructions.

see [pointycastle documentation](https://pub.dev/packages/pointycastle)

### Installation

```yaml
dependencies:
  secure_biometrics: ^0.0.1
```

## Usage

### Initial Setup

```dart
import 'package:secure_biometrics/secure_biometrics.dart';

// Get instance
final secureBiometrics = SecureBiometrics.instance;

// Generate key pair
await secureBiometrics.generateKeyPair();
```

### Authentication Flow

```dart
try {
  // Server sends challenge
  const challenge = "random_challenge_from_server";

  // Sign challenge (requires biometric authentication)
  final signature = await secureBiometrics.signData(challenge);

  // Send signature back to server
  // Server verifies using stored public key
} on BiometricAuthenticationException catch (e) {
  // Handle authentication failure
} on MaxAttemptsExceededException {
  // Handle too many failed attempts
}
```

### Key Management

```dart
// Export public key for server storage
final publicKeyPEM = await secureBiometrics.exportPublicKeyPEM();
```

### RSA Signature Scheme

This package uses RSA signatures with the following specifications:

- Key Size: 2048 bits
- Hash Algorithm: SHA-256
- Padding Scheme: PKCS#1 v1.5
- Public Exponent: 65537 (0x10001)

## Use Cases

### Secure Sign-In

- User attempts to sign in
- App requests challenge from server
- User authenticates with biometrics
- App signs challenge with private key
- Server verifies signature with stored public key

### Key Loss Recovery

- User resets device or uninstalls app
- User signs in with fallback method (password/OTP)
- Generate new key pair
- Update server with new public key
- Re-enable biometric authentication

### Unauthorized Access Prevention

- Another person attempts biometric authentication
- Device denies access to private key
- Failed attempt is tracked
- User is notified of failed attempt

## Security Best Practices

1. Always use device secure storage for private keys
2. Implement robust fallback authentication
3. Never expose private keys - use only for signing
4. Monitor and limit failed authentication attempts
5. Notify users of security-related events

## Error Handling

```dart
try {
  await secureBiometrics.signData(challenge);
} on BiometricAuthenticationException catch (e) {
  // Failed biometric authentication
} on MaxAttemptsExceededException {
  // Too many failed attempts
} on BiometricNotAvailableException {
  // Biometrics not available
} on KeyNotFoundException catch (e) {
  // Key not found
} on KeyOperationException catch (e) {
  // Key operation failed
}
```

## Example

Check the [example](example) folder for a complete demonstration app.

## Tests

Check the [test](test) folder for complete test including signature verification.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
