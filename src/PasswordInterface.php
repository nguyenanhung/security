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
 * Interface PasswordInterface
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface PasswordInterface
{
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
    public static function createPassword($password = '');

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
    public static function verifyPassword($password = '', $hash = '');

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
    public static function passwordGetInfo($hash = '');

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
    public static function passwordReHash($password = '', $hash = '');
}
