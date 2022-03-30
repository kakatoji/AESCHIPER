<?php


class AesCipher
{
    const CIPHER = 'AES-128-CBC';
    const INIT_VECTOR_LENGTH = 16;

    protected $data;

    protected $initVector;
   
    protected $errorMessage;


    public function __construct($initVector, $data = null, $errorMessage = null)
    {
        $this->initVector = $initVector;
        $this->data = $data;
        $this->errorMessage = $errorMessage;
    }


    public static function encrypt($secretKey, $plainText)
    {
        try {
            // Check secret length
            if (!static::isKeyLengthValid($secretKey)) {
                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");
            }

            // Get random initialization vector
            $initVector = bin2hex(openssl_random_pseudo_bytes(static::INIT_VECTOR_LENGTH / 2));

            // Encrypt input text
            $raw = openssl_encrypt(
                $plainText,
                static::CIPHER,
                $secretKey,
                OPENSSL_RAW_DATA,
                $initVector
            );

            // Return base64-encoded string: initVector + encrypted result
            $result = base64_encode($initVector . $raw);

            if ($result === false) {
                // Operation failed
                return new static($initVector, null, openssl_error_string());
            }

            // Return successful encoded object
            return new static($initVector, $result);
        } catch (\Exception $e) {
            // Operation failed
            return new static(isset($initVector), null, $e->getMessage());
        }
    }


    public static function decrypt($secretKey, $cipherText)
    {
        try {
            // Check secret length
            if (!static::isKeyLengthValid($secretKey)) {
                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");
            }

            // Get raw encoded data
            $encoded = base64_decode($cipherText);
            // Slice initialization vector
            $initVector = substr($encoded, 0, static::INIT_VECTOR_LENGTH);
            // Slice encoded data
            $data = substr($encoded, static::INIT_VECTOR_LENGTH);

            // Trying to get decrypted text
            $decoded = openssl_decrypt(
                $data,
                static::CIPHER,
                $secretKey,
                OPENSSL_RAW_DATA,
                $initVector
            );

            if ($decoded === false) {
                // Operation failed
                return new static(isset($initVector), null, openssl_error_string());
            }

            // Return successful decoded object
            return new static($initVector, $decoded);
        } catch (\Exception $e) {
            // Operation failed
            return new static(isset($initVector), null, $e->getMessage());
        }
    }


    public static function isKeyLengthValid($secretKey)
    {
        $length = strlen($secretKey);

        return $length == 16 || $length == 24 || $length == 32;
    }


    public function getData()
    {
        return $this->data;
    }


    public function getInitVector()
    {
        return $this->initVector;
    }


    public function getErrorMessage()
    {
        return $this->errorMessage;
    }


    public function hasError()
    {
        return $this->errorMessage !== null;
    }


    public function __toString()
    {
        return $this->getData();
    }
}
