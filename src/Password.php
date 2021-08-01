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

    use VersionTrait;

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
     * Function createPassword
     *
     * @param string $password
     *
     * @return bool|string|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 00:45
     */
    public static function createPassword($password = '')
    {
        return password_hash($password, self::ALGORITHM_DEFAULT);
    }

    /**
     * Function verifyPassword
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 00:23
     */
    public static function verifyPassword($password = '', $hash = ''): bool
    {
        if (password_verify($password, $hash)) {
            return TRUE;
        }

        return FALSE;
    }

    /**
     * Function passwordGetInfo
     *
     * @param string $hash
     *
     * @return array|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 00:39
     */
    public static function passwordGetInfo($hash = '')
    {
        return password_get_info($hash);
    }

    /**
     * Function passwordReHash
     *
     * @param string $password
     * @param string $hash
     *
     * @return bool|string|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 08/01/2021 00:35
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
