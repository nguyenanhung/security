<?php
/**
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 9/19/18
 * Time: 13:54
 */
/**
 * Function dump
 *
 * @author: 713uk13m <dev@nguyenanhung.com>
 * @time  : 10/17/18 17:29
 *
 * @param string $str
 */
function dump($str = '')
{
    echo "<pre>";
    var_dump($str);
    echo "</pre>";
}

/**
 * Function testLogPath
 *
 * @author: 713uk13m <dev@nguyenanhung.com>
 * @time  : 10/17/18 17:29
 *
 * @return string
 */
function testLogPath()
{
    return __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR;
}

/**
 * Function testCachePath
 *
 * @author: 713uk13m <dev@nguyenanhung.com>
 * @time  : 10/17/18 17:29
 *
 * @return string
 */
function testCachePath()
{
    return __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR;
}
