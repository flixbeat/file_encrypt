<?php    
/**
 * This class uses the Tiny Encryption Algorithm (TEA) to provide a fast,
 * simple method to encrypt/decrypt data.
 * 
 * Usage:
 * <?php
 * require_once('xtea.php');
 * // The salt is usually created when a user logs in.
 * $salt = md5(gmdate('Y-m-d H:i:s')); // Generate a better random salt than this!
 *  $_SESSION['salt'] = $salt;
 * // Then we create the xtea object with the previously created $_SESSION['salt'].
 * $xtea = new xtea($_SESSION['salt']);
 * $encrypted_data = $xtea->encrypt('Whatever data you want to encrypt');
 * $decrypted_data = trim($xtea->decrypt($encrypted_data));
 * ?>
 *
 * @see http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 */
class xtea{
    //Private members.
    /**
     * The salt to be used in encrypting/decrypting data.
     * @var string
     */
    private $key;

    /**
     * Flag indicating whether to use CBC or ECB mode. Normally CBC mode would be the right choice so this member defaults to TRUE.
     * @var boolean
     */
    private $cbc = TRUE;

    /**
     * Constructor.
     * @param string $key A string of characters to be used as a salt.
     */
    function __construct($key){
        $this->key_setup($key);
    }

    /**
     * Verify the implementation of the Blowfish algorithm.
     *
     * @return boolean TRUE if the implementation is correct, FALSE otherwise.
     */
    public function check_implementation(){
        $xtea = new xtea("");
        $vectors = array(
            array(array(0x00000000,0x00000000,0x00000000,0x00000000), array(0x41414141,0x41414141), array(0xed23375a,0x821a8c2d)),
            array(array(0x00010203,0x04050607,0x08090a0b,0x0c0d0e0f), array(0x41424344,0x45464748), array(0x497df3d0,0x72612cb5)),
        );

        //Correct implementation?
        $correct = true;

        //Test vectors, see http://www.schneier.com/code/vectors.txt
        foreach($vectors AS $vector){
            $key = $vector[0];
            $plain = $vector[1];
            $cipher = $vector[2];

            $xtea->key_setup($key);
            $return = $xtea->block_encrypt($vector[1][0],$vector[1][1]);

            if((int)$return[0] != (int)$cipher[0] || (int)$return[1] != (int)$cipher[1]){
                $correct = false;
            }
        }
        return $correct;
    }

    /**
     * Decrypt data. Note: all trailing spaces that might have been added in the encrypt method are trimmed.
     *
     * @param string $text The data to be decrypted.
     * @return string The decrypted data.
     */
    public function decrypt($text){
        $plain = array();
        $cipher = $this->_str2long(base64_decode($text));

        if($this->cbc){
            $i = 2; //Message start at second block
        }else{
            $i = 0; //Message start at first block
        }

        for($i; $i<count($cipher); $i+=2){
            $return = $this->block_decrypt($cipher[$i],$cipher[$i+1]);

            //XORed $return with the previous ciphertext
            if($this->cbc){
                $plain[] = array($return[0]^$cipher[$i-2],$return[1]^$cipher[$i-1]);
            }else{
                //EBC Mode
                $plain[] = $return;
            }
        }

        $output = '';
        for($i = 0; $i<count($plain); $i++){
            $output .= $this->_long2str($plain[$i][0]);
            $output .= $this->_long2str($plain[$i][1]);
        }
        return rtrim($output);
    }

    /**
     * Encrypt some data and return it base64 encoded.
     *
     * @param string $text The data to be encrypted.
     * @return string The encrypted data
     * @see base64_encode
     */
    public function encrypt($text){
        $n = strlen($text);
        if($n%8 != 0){
            $lng = ($n+(8-($n%8)));
        }else{
            $lng = 0;
        }

        $text = str_pad($text, $lng, ' ');
        $text = $this->_str2long($text);

        //Initialization vector: IV
        if($this->cbc){
            $cipher[0][0] = time();
            $cipher[0][1] = (double)microtime()*1000000;
        }

        $a = 1;
        for($i = 0; $i<count($text); $i+=2){
            if($this->cbc){
                //$text is XORed with the previous ciphertext
                $text[$i] ^= $cipher[$a-1][0];
                $text[$i+1] ^= $cipher[$a-1][1];
            }
            $cipher[] = $this->block_encrypt($text[$i],$text[$i+1]);
            $a++;
        }

        $output = "";
        for($i = 0; $i<count($cipher); $i++){
            $output .= $this->_long2str($cipher[$i][0]);
            $output .= $this->_long2str($cipher[$i][1]);
        }
        return base64_encode($output);
    }

    /**
     * Decrypt a block of data.
     *
     * @param integer $y
     * @param integer $z
     * @return array The decrypted block of data.
     */
    private function block_decrypt($y, $z){
        $delta=0x9e3779b9;
        $sum=0xC6EF3720;
        $n=32;

        /* start cycle */
        for ($i=0; $i<32; $i++){
            $z      = $this->_add($z, -($this->_add($y << 4 ^ $this->_rshift($y, 5), $y) ^ $this->_add($sum, $this->key[$this->_rshift($sum, 11) & 3])));
            $sum    = $this->_add($sum, -$delta);
            $y      = $this->_add($y, -($this->_add($z << 4 ^ $this->_rshift($z, 5), $z) ^ $this->_add($sum, $this->key[$sum & 3])));
        }
        /* end cycle */
        return array($y,$z);
    }

    /**
     * Encrypt a block of data.
     *
     * @param integer $y
     * @param integer $z
     * @return array The encrypted block of data.
     */
    private function block_encrypt($y, $z){
        $sum=0;
        $delta=0x9e3779b9;

        /* start cycle */
        for ($i=0; $i<32; $i++){
            $y      = $this->_add($y, $this->_add($z << 4 ^ $this->_rshift($z, 5), $z) ^ $this->_add($sum, $this->key[$sum & 3]));
            $sum    = $this->_add($sum, $delta);
            $z      = $this->_add($z, $this->_add($y << 4 ^ $this->_rshift($y, 5), $y) ^ $this->_add($sum, $this->key[$this->_rshift($sum, 11) & 3]));
        }

        /* end cycle */
        $v[0]=$y;
        $v[1]=$z;

        return array($y,$z);
    }

    /**
     * Set up the salt.
     *
     * @param string $key The salt to be used in encrypting/decrypting data.
     */
    private function key_setup($key){
        if(is_array($key)){
            $this->key = $key;
        }else if(isset($key) && !empty($key)){
            $this->key = $this->_str2long(str_pad($key, 16, $key));
        }else{
            $this->key = array(0,0,0,0);
        }
    }

    /**
     * I have no idea what this function actually does. :-)
     *
     * @param integer $i1
     * @param integer $i2
     * @return integer The manipulated data.
     */
    private function _add($i1, $i2){
        $result = 0.0;

        foreach (func_get_args() as $value){
            // remove sign if necessary
            if (0.0 > $value){
                $value -= 1.0 + 0xffffffff;
            }
            $result += $value;
        }

        // convert to 32 bits
        if (0xffffffff < $result || -0xffffffff > $result){
            $result = fmod($result, 0xffffffff + 1);
        }

        // convert to signed integer
        if (0x7fffffff < $result){
            $result -= 0xffffffff + 1.0;
        }elseif (-0x80000000 > $result){
            $result += 0xffffffff + 1.0;
        }
        return $result;
    }

    //Convert a longinteger into a string
    /**
     * Convert a long integer into a string.
     *
     * @param integer $l The long integer to be converted.
     * @return string The converted integer.
     */
    private function _long2str($l){
        return pack('N', $l);
    }

    /**
     * Right shift some data.
     *
     * @param integer $integer
     * @param integer $n
     * @return integer The shifted data.
     */
    private function _rshift($integer, $n){
        // convert to 32 bits
        if (0xffffffff < $integer || -0xffffffff > $integer){
            $integer = fmod($integer, 0xffffffff + 1);
        }

        // convert to unsigned integer
        if (0x7fffffff < $integer){
            $integer -= 0xffffffff + 1.0;
        }elseif (-0x80000000 > $integer){
            $integer += 0xffffffff + 1.0;
        }

        // do right shift
            if (0 > $integer){
                $integer &= 0x7fffffff;         // remove sign bit before shift
                $integer >>= $n;                    // right shift
                $integer |= 1 << (31 - $n); // set shifted sign bit
            }else{
                $integer >>= $n;                    // use normal right shift
            }
        return $integer;
    }

    /**
     * Convert a string into a long integer
     *
     * @param string The string to be converted to a long integer.
     * @return integer The converted string.
     */
    private function _str2long($data){
        $n = strlen($data);
        $tmp = unpack('N*', $data);
        $data_long = array();
        $j = 0;

        foreach ($tmp as $value){
            $data_long[$j++] = $value;
        }
        return $data_long;
    }
}
?>
