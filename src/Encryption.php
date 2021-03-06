<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 2018-12-03
 * Time: 16:12
 */

namespace nguyenanhung\MySecurity;

use Exception;

/**
 * Class Encryption
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class Encryption implements ProjectInterface, EncryptionInterface
{
    use VersionTrait;

    /**
     * Encryption constructor.
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct()
    {
    }

    /**
     * Function createKey
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:20
     *
     * @param int $length
     *
     * @return bool|string
     */
    public function createKey($length = 16)
    {
        if (function_exists('random_bytes')) {
            try {
                return random_bytes((int) $length);
            }
            catch (Exception $e) {
                return FALSE;
            }
        } elseif (defined('MCRYPT_DEV_URANDOM')) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        $isSecure = NULL;
        $key      = openssl_random_pseudo_bytes($length, $isSecure);

        return ($isSecure === TRUE) ? $key : FALSE;
    }
}
