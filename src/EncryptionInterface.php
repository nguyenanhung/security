<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 2018-12-03
 * Time: 16:13
 */

namespace nguyenanhung\MySecurity;

/**
 * Interface EncryptionInterface
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface EncryptionInterface
{
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
    public function createKey($length = 16);
}
