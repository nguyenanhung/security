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
class Password implements ProjectInterface
{
    use VersionTrait;

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
    public static function createPassword(string $password = '')
    {
        return password_hash($password, PASSWORD_DEFAULT);
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
    public static function verifyPassword(string $password = '', string $hash = ''): bool
    {
        if (password_verify($password, $hash)) {
            return true;
        }
        return false;
    }

    /**
     * Function passwordGetInfo
     *
     * @param string $hash
     *
     * @return array|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/21/2021 19:32
     */
    public static function passwordGetInfo(string $hash = '')
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
    public static function passwordReHash(string $password = '', string $hash = '')
    {
        if (self::verifyPassword($password, $hash) && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            return self::createPassword($password);
        }
        return null;
    }
}
