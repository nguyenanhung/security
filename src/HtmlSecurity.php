<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/18/18
 * Time: 09:38
 */

namespace nguyenanhung\MySecurity;

use HTMLPurifier_Config;
use HTMLPurifier;

/**
 * Class HtmlSecurity
 *
 * Class HTML Security sử dụng HTML Purifier để làm bộ lọc
 * được custom lại để cho phù hợp với quá trình sử dụng
 *
 * @see       http://htmlpurifier.org/docs
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class HtmlSecurity implements ProjectInterface, HtmlSecurityInterface
{
    /** @var null|string Thư mục cache cho HTML Purifier */
    private $cachePath = NULL;
    /** @var null|array Mảng dữ liệu cấu hình cho HTML Purifier */
    private $config = NULL;

    use VersionTrait;

    /**
     * HtmlSecurity constructor.
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct()
    {
    }

    /**
     * HtmlSecurity destructor.
     */
    public function __destruct()
    {
        // TODO: Implement __destruct() method.
    }

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
    public function setCachePath($cachePath = NULL)
    {
        $this->cachePath = $cachePath;

        return $this;
    }

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
    public function setConfig($config = [])
    {
        $this->config = $config;

        return $this;
    }

    /**
     * HTML Escape
     *
     * Hàm clean mã html, loại bỏ mã độc, mã bẩn sử dụng HTML Purifier
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:45
     *
     * @param string $str Chuỗi đầu vào
     *
     * @return string Nội dung đầu ra sau khi đã lọc
     */
    public function escape($str = '')
    {
        $config = HTMLPurifier_Config::createDefault();
        $config->set('Cache.SerializerPath', $this->cachePath);
        if (!empty($this->config) && is_array($this->config) && count($this->config) > 0) {
            foreach ($this->config as $key => $value) {
                $config->set($key, $value);
            }
        }
        $purifier = new HTMLPurifier($config);

        return $purifier->purify($str);
    }
}
