import '../crypto_keys.dart';

import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:quiver/core.dart';

class RsaPublicKeyImpl extends Object
    with AsymmetricKeyBase
    implements RsaPublicKey {
  @override
  final BigInt exponent;

  @override
  final BigInt modulus;

  RsaPublicKeyImpl({required this.modulus, required this.exponent});

  @override
  int get hashCode => hash2(exponent, modulus);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is RsaPublicKey &&
          other.exponent == exponent &&
          other.modulus == modulus);
}

class RsaPrivateKeyImpl extends Object
    with AsymmetricKeyBase
    implements RsaPrivateKey {
  @override
  final BigInt privateExponent;

  @override
  final BigInt firstPrimeFactor;

  @override
  final BigInt secondPrimeFactor;

  @override
  final BigInt modulus;

  RsaPrivateKeyImpl({
    required this.privateExponent,
    required this.firstPrimeFactor,
    required this.secondPrimeFactor,
    required this.modulus,
  });

  @override
  int get hashCode =>
      hash4(privateExponent, firstPrimeFactor, secondPrimeFactor, modulus);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is RsaPrivateKey &&
          other.privateExponent == privateExponent &&
          other.firstPrimeFactor == firstPrimeFactor &&
          other.secondPrimeFactor == secondPrimeFactor &&
          other.modulus == modulus);
}

class EcPublicKeyImpl extends Object
    with AsymmetricKeyBase
    implements EcPublicKey {
  @override
  final BigInt xCoordinate;

  @override
  final BigInt yCoordinate;

  @override
  final Identifier curve;

  EcPublicKeyImpl({
    required this.xCoordinate,
    required this.yCoordinate,
    required this.curve,
  });

  @override
  int get hashCode => hash3(xCoordinate, yCoordinate, curve);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EcPublicKey &&
          other.xCoordinate == xCoordinate &&
          other.yCoordinate == yCoordinate &&
          other.curve == curve);
}

class EcPrivateKeyImpl extends Object
    with AsymmetricKeyBase
    implements EcPrivateKey {
  @override
  final BigInt eccPrivateKey;

  @override
  final Identifier curve;

  EcPrivateKeyImpl({required this.eccPrivateKey, required this.curve});

  @override
  int get hashCode => hash2(eccPrivateKey, curve);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is EcPrivateKey &&
          other.eccPrivateKey == eccPrivateKey &&
          other.curve == curve);
}

class SymmetricKeyImpl extends Object
    with SymmetricKeyBase
    implements SymmetricKey {
  @override
  final Uint8List keyValue;

  SymmetricKeyImpl({required this.keyValue});

  @override
  int get hashCode => const ListEquality().hash(keyValue);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is SymmetricKey &&
          const ListEquality().equals(other.keyValue, keyValue));
}

class SignatureImpl implements Signature {
  @override
  final Uint8List data;

  SignatureImpl(this.data);

  @override
  int get hashCode => const ListEquality().hash(data);

  @override
  bool operator ==(other) =>
      other is Signature && const ListEquality().equals(other.data, data);
}

class EncryptionResultImpl implements EncryptionResult {
  @override
  final Uint8List data;

  @override
  final Uint8List? initializationVector;

  @override
  final Uint8List? authenticationTag;

  @override
  final Uint8List? additionalAuthenticatedData;

  EncryptionResultImpl(this.data,
      {this.initializationVector,
      this.authenticationTag,
      this.additionalAuthenticatedData});

  @override
  int get hashCode => hash4(
      const ListEquality().hash(data),
      const ListEquality().hash(initializationVector),
      const ListEquality().hash(authenticationTag),
      const ListEquality().hash(additionalAuthenticatedData));

  @override
  bool operator ==(other) =>
      other is EncryptionResult &&
      const ListEquality().equals(other.data, data) &&
      const ListEquality()
          .equals(other.initializationVector, initializationVector) &&
      const ListEquality().equals(other.authenticationTag, authenticationTag) &&
      const ListEquality().equals(
          other.additionalAuthenticatedData, additionalAuthenticatedData);
}
