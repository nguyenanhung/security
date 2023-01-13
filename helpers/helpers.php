<?php
/**
 * Project security
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 09/24/2021
 * Time: 12:38
 */
if (!function_exists('xssValidation')) {
    /**
     * Function xssValidation
     *
     * @param $value
     *
     * @return bool
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 30/07/2022 57:32
     */
    function xssValidation($value)
    {
        return \nguyenanhung\MySecurity\Helper\Xss::xssValidation($value);
    }
}
