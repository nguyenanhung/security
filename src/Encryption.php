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
class Encryption implements ProjectInterface
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
     * @param int $length
     *
     * @return false|string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/24/2021 04:19
     */
    public function createKey($length = 32)
    {
        if (function_exists('random_bytes')) {
            try {
                return random_bytes((int) $length);
            } catch (Exception $e) {
                if (function_exists('log_message')) {
                    log_message('error', $e->getMessage());
                    log_message('error', $e->getTraceAsString());
                }

                return false;
            }
        } elseif (function_exists('mcrypt_create_iv') && defined('MCRYPT_DEV_URANDOM')) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        $isSecure = null;
        $key = openssl_random_pseudo_bytes($length, $isSecure);

        return ($isSecure === true) ? $key : false;
    }
}
