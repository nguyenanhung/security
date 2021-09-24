<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 2018-12-03
 * Time: 16:23
 */

namespace nguyenanhung\MySecurity\Encryption;

use phpseclib3\Crypt\AES as CryptAES;

/**
 * Class AES
 *
 * @package   nguyenanhung\MySecurity\Encryption
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class AES
{
    /** @var int Key Length */
    private $keyLength = 128;

    /** @var string Private Key */
    private $key = '1234567890qwerty';

    /** @var string $iv */
    private $iv;

    /**
     * AES constructor.
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct()
    {
    }

    /**
     * Function setKeyLength
     *
     * @param int $keyLength
     *
     * @return $this
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 04:06
     */
    public function setKeyLength($keyLength = 128)
    {
        $this->keyLength = $keyLength;

        return $this;
    }

    /**
     * Function getKeyLength
     *
     * @return int
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:52
     */
    public function getKeyLength()
    {
        return $this->keyLength;
    }

    /**
     * Function setKey
     *
     * @param string $key
     *
     * @return $this
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:57
     */
    public function setKey($key = '')
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Function getKey
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 03:21
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Function setIv
     *
     * @param $iv
     *
     * @return $this
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 45:16
     */
    public function setIv($iv)
    {
        $this->iv = $iv;

        return $this;
    }

    /**
     * Function getIv
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/24/2021 03:26
     */
    public function getIv()
    {
        return $this->iv;
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
        $cipher = new CryptAES('ctr');
        // could use AES::MODE_CBC
        // keys are null-padded to the closest valid size
        // longer than the longest key and it's truncated
        $cipher->setKeyLength($this->keyLength);
        $cipher->setKey($this->key);
        // $cipher->setPassword($this->key, 'pbkdf2', 'sha1', 'phpseclib/salt', 1000, 256 / 8);
        // the IV defaults to all-NULLs if not explicitly defined
        $cipher->setIV($this->iv);

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
        $cipher = new CryptAES('ctr');
        // could use AES::MODE_CBC
        // keys are null-padded to the closest valid size
        // longer than the longest key and it's truncated
        $cipher->setKeyLength($this->keyLength);
        $cipher->setKey($this->key);
        // $cipher->setPassword($this->key, 'pbkdf2', 'sha1', 'phpseclib/salt', 1000, 256 / 8);
        // the IV defaults to all-NULLs if not explicitly defined
        $cipher->setIV($this->iv);

        return $cipher->decrypt(base64_decode($cipherText));
    }
}

