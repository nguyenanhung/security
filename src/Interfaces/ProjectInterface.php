<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/4/18
 * Time: 14:55
 */

namespace nguyenanhung\MySecurity\Interfaces;

/**
 * Interface ProjectInterface
 *
 * @package   nguyenanhung\MySecurity\Interfaces
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface ProjectInterface
{
    const VERSION       = '1.0';
    const USE_BENCHMARK = TRUE;

    /**
     * Hàm lấy thông tin phiên bản Package
     *
     * @author  : 713uk13m <dev@nguyenanhung.com>
     * @time    : 10/13/18 15:12
     *
     * @return mixed|string Current Project Version, VD: 0.1.0
     */
    public function getVersion();
}
