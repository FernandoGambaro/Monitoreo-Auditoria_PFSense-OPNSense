<?php

namespace App;

class Encryption
{
    var $skey = '12345671233456212';  // you can change it

    const METHOD = 'AES-256-CBC';

    /*
     * vector
     * @var string
     */
    const IV = '1234567890123412';  // 16 bits

    /**
     * Default secret key
     */
    const KEY = 'TuFavorita2323232399';  // 16 bits

    /**
     * MÉTODOS PARA CONTRASEÑAS (IRREVERSIBLES)
     * Ideales para el login de usuarios.
     */
    public static function hash($password)
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    public static function verify($password, $hash)
    {
        return password_verify($password, $hash);
    }

    /**
     * MÉTODOS PARA DATOS REVERSIBLES (CAPTCHA, TOKENS)
     * Utiliza Base64 para una compatibilidad rápida en sistemas legacy,
     * o puedes usar OpenSSL para cifrado real si tienes una KEY en el .env.
     */
    public function encode($password, $key = self::KEY, $iv = self::IV, $method = self::METHOD)
    {
        if (!$password) {
            return false;
        }
        return base64_encode(openssl_encrypt($password, $method, $key, OPENSSL_RAW_DATA, $iv));
    }

    public function decode($password, $key = self::KEY, $iv = self::IV, $method = self::METHOD)
    {
        if (!$password) {
            return false;
        }

        //        $key = hash('sha256', $password);
        return openssl_decrypt(base64_decode($password), $method, $key, OPENSSL_RAW_DATA, $iv);
    }
}
