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
     * Function createKey
     *
     * @param int $length
     *
     * @return string|bool
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/24/2021 04:19
     */
    public function createKey(int $length = 32)
    {
        try {
            return random_bytes($length);
        } catch (Exception $e) {
            if (function_exists('log_message')) {
                log_message('error', 'Error File: ' . $e->getFile() . ' - Line: ' . $e->getLine() . ' - Message: ' . $e->getMessage());
                log_message('error', $e->getTraceAsString());
            }
            return false;
        }
    }
}
