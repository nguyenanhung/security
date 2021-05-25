<?php
/**
 * Project security
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 05/25/2021
 * Time: 10:41
 */

namespace nguyenanhung\MySecurity;

/**
 * Trait VersionTrait
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
trait VersionTrait
{
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
}
