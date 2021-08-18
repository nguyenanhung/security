<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/18/18
 * Time: 09:51
 */

namespace nguyenanhung\MySecurity;

/**
 * Interface HtmlSecurityInterface
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface HtmlSecurityInterface
{
    /**
     * Hàm cấu hình thư mục cache cho HTML Purifier
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:44
     *
     * @param null $cachePath
     *
     * @return  $this
     */
    public function setCachePath($cachePath = NULL);

    /**
     * Hàm set cấu hình Config cho HTML Purifier
     *
     * Mảng dữ liệu với key và value
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:51
     *
     * @param array $config Mảng dữ liệu cấu hình
     *
     * @return  $this
     *
     * @see   http://htmlpurifier.org/live/configdoc/plain.html
     */
    public function setConfig(array $config = []);

    /**
     * HTML Escape
     *
     * Hàm clean mã html, loại bỏ mã độc, mã bẩn sử dụng HTML Purifier
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:45
     *
     * @param string $dirtyHtml Chuỗi đầu vào
     *
     * @return string Nội dung đầu ra sau khi đã lọc
     */
    public function escape(string $dirtyHtml = '');
}
