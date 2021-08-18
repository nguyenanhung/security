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
    function escape_html($string): string
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
    function escape_html_attribute($string): string
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
    function escape_js($string): string
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
    function escape_css($string): string
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
    function escape_url($string): string
    {
        $escape = new Laminas\Escaper\Escaper();

        return $escape->escapeUrl($string);
    }
}
if (!function_exists('remove_invisible_characters')) {
    /**
     * Remove Invisible Characters
     *
     * This prevents sandwiching null characters
     * between ascii characters, like Java\0script.
     *
     * @param string
     * @param bool
     *
     * @return    string
     */
    function remove_invisible_characters($str, $url_encoded = TRUE): string
    {
        $nonDisplay = array();
        // every control character except newline (dec 10),
        // carriage return (dec 13) and horizontal tab (dec 09)
        if ($url_encoded) {
            $nonDisplay[] = '/%0[0-8bcef]/i';    // url encoded 00-08, 11, 12, 14, 15
            $nonDisplay[] = '/%1[0-9a-f]/i';    // url encoded 16-31
            $nonDisplay[] = '/%7f/i';    // url encoded 127
        }
        $nonDisplay[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';    // 00-08, 11, 12, 14-31, 127
        do {
            $str = preg_replace($nonDisplay, '', $str, -1, $count);
        }
        while ($count);

        return $str;
    }
}