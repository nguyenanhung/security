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
     * @param string $key
     *
     * @return mixed
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:26
     */
    public function setKey(string $key = '');

    /**
     * Function getKey
     *
     * @return mixed
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:25
     */
    public function getKey();

    /**
     * Function encrypt
     *
     * @param string $plainText
     *
     * @return mixed
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:20
     */
    public function encrypt(string $plainText = '');

    /**
     * Function decrypt
     *
     * @param string $cipherText
     *
     * @return mixed
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 04/20/2021 21:22
     */
    public function decrypt(string $cipherText = '');
}
