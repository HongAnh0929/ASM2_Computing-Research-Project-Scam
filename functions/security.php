<?php

define('ENC_METHOD', 'AES-256-CBC');

function encryptData($plaintext){
    $key = $_ENV['DATA_ENCRYPTION_KEY'];
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(ENC_METHOD));
    $ciphertext = openssl_encrypt($plaintext, ENC_METHOD, $key, 0, $iv);
    return base64_encode($iv . $ciphertext);
}

function decryptData($ciphertext_b64){
    $key = $_ENV['DATA_ENCRYPTION_KEY'];
    $data = base64_decode($ciphertext_b64);
    $ivlen = openssl_cipher_iv_length(ENC_METHOD);
    $iv = substr($data, 0, $ivlen);
    $ciphertext = substr($data, $ivlen);
    return openssl_decrypt($ciphertext, ENC_METHOD, $key, 0, $iv);
}

function hashData($data){
    return hash("sha256", $data);
}
?>