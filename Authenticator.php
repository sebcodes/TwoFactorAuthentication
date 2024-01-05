<?php
declare(strict_types=1);
namespace Sebcodes;
use \Exception;
/**
 * @package Sebcodes\Authenticator
 * @category Sebcodes Project
 * @author Sebastian Kiefer (sebcodes)
 * @version 1.0
 * @copyright 2024 Sebastian Kiefer
 * @since 2020
 * @link https://sebcodes.de
 * @see https://github.com/sebcodes/TwoFactorAuthentication
 **/

class Authenticator
{
    //Length of auth Key, typically 6
    private int $keyLength = 6;

    //All valid chars
    private array $validChars = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7',
        '=',
    ];

    /**
     * Create a new secret.
     * @param int $length
     * @return string
     * @throws Exception
     */
    public function createSecret(Int $length = 16):string
    {

        // Check valid length
        if ($length < 16 || $length > 128) {
            throw new Exception('Secret length must be between 16 and 128');
        }
        $secret = '';
        $randomCode = false;
        //Check for this function and use it
        if (function_exists('random_bytes')) {
            $randomCode = random_bytes($length);
        }
        elseif (function_exists('openssl_random_pseudo_bytes')) {
            $randomCode = openssl_random_pseudo_bytes($length, $cryptoStrong);
            if (!$cryptoStrong) {
                $randomCode = false;
            }
        }
        //Create secret if $randomCode is true
        if ($randomCode !== false) {
            for ($i = 0; $i < $length; ++$i) {
                //Add secret value with the valid Chars
                $secret .= $this->validChars[ord($randomCode[$i]) & 31];
            }
        } else {
            throw new Exception('No random function exist');
        }

        return (string) $secret;
    }

    /**
     * Calculate code by given secret Key
     * @param string $secret
     * @param Float $timeSlice
     * @return string
     */
    public function getCode(String $secret, Float $timeSlice = null)
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        $secretkey = $this->base32Decode($secret);
        // Pack time into binary string
        $timestamp = "\0\0\0\0" . pack('N*',$timeSlice);
        // Hash it with users secret key
        $hashhmac = hash_hmac("SHA1", $timestamp, $secretkey, true);
        $hashpart = substr($hashhmac, ord(substr($hashhmac, -1)) & 0x0F, 4);
        // Unpack binary value
        $value = unpack('N', $hashpart);
        $value = $value[1] & 0x7FFFFFFF;
        return str_pad(''.($value % pow(10, $this->keyLength)).'', $this->keyLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code by the Google QR Code API.
     * @param string $name
     * @param string $secret
     * @param string $title
     * @param array  $params
     * @return string
     */
    public function createQRCode(String $name,String $secret,String $title = null,Array $params = []):string
    {
        //Add some infos to the query string if they exists
        $width = !empty($params['width']) && (int) $params['width'] > 0 ? (int) $params['width'] : 200;
        $height = !empty($params['height']) && (int) $params['height'] > 0 ? (int) $params['height'] : 200;
        $level = !empty($params['level']) && array_search($params['level'], array('L', 'M', 'Q', 'H')) !== false ? $params['level'] : 'M';
        //Create URL
        $urlencoded = urlencode('otpauth://totp/'.$name.'?secret='.$secret.'');

        isset($title) ? $urlencoded .= urlencode('&issuer='.urlencode($title)): null;
        //Return complete string
        return (string) "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size=${width}x${height}&ecc=$level";
    }

    /**
     * Check that the code is correct.
     * @param string $secret
     * @param string $code
     * @param Float $difference
     * @param Float $currentTimeSlice
     * @return bool
     */
    public function checkCode(String $secret, String $code, Float $difference = 1, Float $currentTimeSlice = null):bool
    {
        //Set time Slice if not set
        if ($currentTimeSlice === null) {
            $currentTimeSlice = floor(time() / 30);
        }
        //If code length not equal 6
        if (strlen($code) != 6) return false;

        //With the difference, check that the code is valid
        for ($i = -$difference; $i <= $difference; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if ($this->equalTiming($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }


    /**
     * Function to decode base32.
     * @param $secret
     * @return bool|string
     */
    protected function base32Decode(String $secret):string
    {
        if (empty($secret)) return '';

        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

        $char = '';

        foreach (str_split($secret) as $c) {
            if (false === ($v = strpos($alphabet, $c))) {
                $v = 0;
            }
            $char .= sprintf('%05b', $v);
        }
        $args = array_map('bindec', str_split($char, 8));
        array_unshift($args, 'C*');

        //use function pack to convert into binary string
        return rtrim(call_user_func_array('pack', $args), "\0");
    }


    /**
     * Check that both codes have the same timing
     * @param String $calculatedCode
     * @param String $userCode
     * @return bool True if booth Strings are equal
     */
    private function equalTiming(String $calculatedCode,String $userCode):bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($calculatedCode, $userCode);
        }
        //Get length of both codes
        $safeLen = (int) strlen($calculatedCode);
        $userLen = (int) strlen($userCode);

        //if not equal return false
        if ($userLen != $safeLen) return (bool) false;

        $result = 0;
        //bitwise checking of codes
        for ($i = 0; $i < $userLen; ++$i) $result |= (ord($calculatedCode[$i]) ^ ord($userCode[$i]));

        //Return if result equal 0
        return (bool) $result === 0;
    }
}
