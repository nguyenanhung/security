<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 2018-12-03
 * Time: 16:00
 */

namespace nguyenanhung\MySecurity;


/**
 * Class Password
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class Password implements ProjectInterface, PasswordInterface
{
    const ALGORITHM_DEFAULT = PASSWORD_DEFAULT;

    /**
     * Password constructor.
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct()
    {
    }

    /**
     * Function getVersion
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:02
     *
     * @return mixed|string
     */
    public function getVersion()
    {
        return self::VERSION;
    }

    /**
     * Function createPassword
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:04
     *
     * @param string $password
     *
     * @return bool|false|string
     */
    public static function createPassword($password = '')
    {
        return password_hash($password, self::ALGORITHM_DEFAULT);
    }

    /**
     * Function verifyPassword
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:05
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     */
    public static function verifyPassword($password = '', $hash = '')
    {
        if (password_verify($password, $hash)) {
            return TRUE;
        }

        return FALSE;
    }

    /**
     * Function passwordGetInfo
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:05
     *
     * @param string $hash
     *
     * @return array
     */
    public static function passwordGetInfo($hash = '')
    {
        return password_get_info($hash);
    }

    /**
     * Function passwordReHash
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:09
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool|false|string|null
     */
    public static function passwordReHash($password = '', $hash = '')
    {
        if (self::verifyPassword($password, $hash)) {
            if (password_needs_rehash($hash, self::ALGORITHM_DEFAULT)) {
                return self::createPassword($password);
            }
        }

        return NULL;
    }
}
