<?php
/**
 * Project security
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 05/25/2021
 * Time: 10:56
 */
if (!function_exists('escape_html')) {
    /**
     * Function escape_html
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 58:03
     */
    function escape_html($string)
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeHtml($string);
    }
}
if (!function_exists('escape_html_attribute')) {
    /**
     * Function escape_html_attribute
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 58:41
     */
    function escape_html_attribute($string)
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeHtmlAttr($string);
    }
}
if (!function_exists('escape_js')) {
    /**
     * Function escape_js
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:04
     */
    function escape_js($string)
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeJs($string);
    }
}
if (!function_exists('escape_css')) {
    /**
     * Function escape_css
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:24
     */
    function escape_css($string)
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeCss($string);
    }
}
if (!function_exists('escape_url')) {
    /**
     * Function escape_url
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:40
     */
    function escape_url($string)
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeUrl($string);
    }
}
