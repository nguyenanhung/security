<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 2018-12-03
 * Time: 16:23
 */

namespace nguyenanhung\MySecurity\Encryption;

/**
 * Class AES
 *
 * @package   nguyenanhung\MySecurity\Encryption
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class AES implements DriverInterface
{
    /** @var int Key Length */
    private $keyLength = 128;
    /** @var string Private Key */
    private $key = '1234567890qwerty';

    /**
     * AES constructor.
     */
    public function __construct()
    {
    }

    /**
     * Function setKeyLength
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:25
     *
     * @param int $keyLength
     *
     * @return $this
     */
    public function setKeyLength($keyLength = 128)
    {
        $this->keyLength = $keyLength;

        return $this;
    }

    /**
     * Function getKeyLength
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:25
     *
     * @return int
     */
    public function getKeyLength()
    {
        return $this->keyLength;
    }

    /**
     * Function setKey
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:26
     *
     * @param string $key
     *
     * @return $this
     */
    public function setKey($key = '')
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Function getKey
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:26
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Function encrypt
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:36
     *
     * @param string $plainText
     *
     * @return string
     */
    public function encrypt($plainText = '')
    {
        $cipher = new \phpseclib\Crypt\AES();
        // could use AES::MODE_CBC
        // keys are null-padded to the closest valid size
        // longer than the longest key and it's truncated
        $cipher->setKeyLength($this->keyLength);
        $cipher->setKey($this->key);
//        $cipher->setPassword($this->key, 'pbkdf2', 'sha1', 'phpseclib/salt', 1000, 256 / 8);
        // the IV defaults to all-NULLs if not explicitly defined
        //$cipher->setIV('7014a0eb6d1611151a286c0ff4f2238f92c120d6');

        return base64_encode($cipher->encrypt($plainText));
    }

    /**
     * Function decrypt
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:35
     *
     * @param string $cipherText
     *
     * @return string
     */
    public function decrypt($cipherText = '')
    {
        $cipher = new \phpseclib\Crypt\AES();
        // could use AES::MODE_CBC
        // keys are null-padded to the closest valid size
        // longer than the longest key and it's truncated
        $cipher->setKeyLength($this->keyLength);
        $cipher->setKey($this->key);
//        $cipher->setPassword($this->key, 'pbkdf2', 'sha1', 'phpseclib/salt', 1000, 256 / 8);
        // the IV defaults to all-NULLs if not explicitly defined
        //$cipher->setIV('7014a0eb6d1611151a286c0ff4f2238f92c120d6');

        return $cipher->decrypt(base64_decode($cipherText));
    }
}
