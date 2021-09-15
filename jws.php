<?php
require_once __DIR__ . '/vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;

use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;

use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;

// The algorithm manager with the HS256 algorithm.
$algorithmManager = new AlgorithmManager([
    new HS256(),
]);


$jwkSIG = JWKFactory::createFromSecret(
    str_pad("mednetsecretrecipe2021", 32, "\00")
);

// We instantiate our JWS Builder.
$jwsBuilder = new JWSBuilder($algorithmManager);

// The payload we want to sign. The payload MUST be a string hence we use our JSON Converter.
$payload = json_encode([
    "name" => "Test test",
    "dob"=> "13/10/1967",
    "email"=> "test@test.com",
    "gender"=> "Male",
    "mobilenumber"=> "971448474646",
    "fg_payment"=> 1,
    "memberIDsender"=> 1322,
    "memberIDAppointment"=> 1322,
    "nationalID"=> "123456888999",
    "networkID"=> 119,
    "latitude"=> 25.291228369481704,
    "longitude"=> 55.384015291929245,
    "identity_type_id"=> 1,
    "identity_id"=> "ABC-12312312323",
    "expired"=> "2022-09-15T17:22:08+05:30"
]);

$jws = $jwsBuilder
    ->create()                               // We want to create a new JWS
    ->withPayload($payload)                  // We set the payload
    ->addSignature($jwkSIG, ['alg' => 'HS256','cty' => 'JWT']) // We add a signature with a simple protected header
    ->build();

$serializer = new JWSCompactSerializer(); // The serializer

$JWStoken = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).


echo "JWSToken:\n" . $JWStoken . "\n";

// The key encryption algorithm manager with the A256KW algorithm.
$keyEncryptionAlgorithmManager = new AlgorithmManager([
    new Dir(),
]);

// The content encryption algorithm manager with the A256CBC-HS256 algorithm.
$contentEncryptionAlgorithmManager = new AlgorithmManager([
    new A128GCM(),
]);

// The compression method manager with the DEF (Deflate) method.
$compressionMethodManager = new CompressionMethodManager([
    new Deflate(0),
]);

// We instantiate our JWE Builder.
$jweBuilder = new JWEBuilder(
    $keyEncryptionAlgorithmManager,
    $contentEncryptionAlgorithmManager,
    $compressionMethodManager
);


$jwkENC = JWKFactory::createFromSecret(
    'MKyKFfaVc7LUonGB'
);

$jwe = $jweBuilder
    ->create()              // We want to create a new JWE
    ->withPayload($JWStoken) // We set the payload
    ->withSharedProtectedHeader([
        'alg' => 'dir',        // Key Encryption Algorithm
        'enc' => 'A128GCM', // Content Encryption Algorithm
        'cty' => 'JWT'
    ])
    ->addRecipient($jwkENC)    // We add a recipient (a shared key or public key).
    ->build();      

    $JWEserializer = new JWECompactSerializer(); // The serializer

    $JWEtoken = $JWEserializer->serialize($jwe, 0); // We serialize the recipient at index 0 (we only have one recipient).

echo "JWEToken:\n". $JWEtoken . "\n";