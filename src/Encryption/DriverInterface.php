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
 * Interface DriverInterface
 *
 * @package   nguyenanhung\MySecurity\Encryption
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface DriverInterface
{
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
    public function setKey($key = '');

    /**
     * Function getKey
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-03 16:26
     *
     * @return string
     */
    public function getKey();

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
    public function encrypt($plainText = '');

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
    public function decrypt($cipherText = '');
}
