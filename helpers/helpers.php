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
    function xssValidation($value): bool
    {
        return \nguyenanhung\MySecurity\Helper\Xss::xssValidation($value);
    }
}
if (!function_exists('xss_validation')) {
    /**
     * Function xss_validation
     *
     * @param $value
     *
     * @return bool
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 12/02/2023 08:05
     */
    function xss_validation($value): bool
    {
        return \nguyenanhung\MySecurity\Helper\Xss::xss_validation($value);
    }
}
if (!function_exists('_force_xss_clean_')) {
    /**
     * Function _force_xss_clean_
     *
     * @param $value
     *
     * @return mixed|string|string[]
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 13/02/2023 11:23
     */
    function _force_xss_clean_($value)
    {
        $antiXSS = new \voku\helper\AntiXSS();

        return $antiXSS->xss_clean($value);
    }
}
if (!function_exists('_forceXssClean_')) {
    /**
     * Function _forceXssClean_
     *
     * @param $value
     *
     * @return mixed|string|string[]
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 13/02/2023 12:06
     */
    function _forceXssClean_($value)
    {
        $antiXSS = new \voku\helper\AntiXSS();

        return $antiXSS->xss_clean($value);
    }
}
if (!function_exists('_xss_clean_')) {
    /**
     * Function _xss_clean_
     *
     * @param $value
     * @param $is_image
     *
     * @return array|bool|string
     * @throws \Exception
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 13/02/2023 15:32
     */
    function _xss_clean_($value, $is_image = false)
    {
        return \nguyenanhung\MySecurity\Helper\Xss::xss_clean($value, $is_image);
    }
}
if (!function_exists('_forceXssClean_')) {
    /**
     * Function _xssClean_
     *
     * @param $value
     * @param $is_image
     *
     * @return array|bool|string
     * @throws \Exception
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 13/02/2023 15:22
     */
    function _xssClean_($value, $is_image = false)
    {
        return \nguyenanhung\MySecurity\Helper\Xss::xss_clean($value, $is_image);
    }
}
