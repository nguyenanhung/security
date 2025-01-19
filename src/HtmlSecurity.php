<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/18/18
 * Time: 09:38
 */

namespace nguyenanhung\MySecurity;

use HTMLPurifier;
use HTMLPurifier_Config;

/**
 * Class HtmlSecurity
 *
 * Class HTML Security sử dụng HTML Purifier để làm bộ lọc được custom lại để cho phù hợp với quá trình sử dụng
 *
 * @see       http://htmlpurifier.org/docs
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class HtmlSecurity implements ProjectInterface
{
    use VersionTrait;

    /** @var null|string Thư mục cache cho HTML Purifier */
    protected $cachePath;

    /** @var null|array Mảng dữ liệu cấu hình cho HTML Purifier */
    protected $config;

    /**
     * HtmlSecurity constructor.
     *
     * @param string|null $cachePath
     * @param array|null $config
     *
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     */
    public function __construct(string $cachePath = '', array $config = array())
    {
        if (!empty($cachePath)) {
            $this->cachePath = $cachePath;
        }
        if (!empty($config)) {
            $this->config = $config;
        }
    }

    /**
     * Hàm cấu hình thư mục cache cho HTML Purifier
     *
     * @param string|null $cachePath
     *
     * @return  $this
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:44
     *
     */
    public function setCachePath(?string $cachePath = ''): HtmlSecurity
    {
        $this->cachePath = $cachePath;
        return $this;
    }

    /**
     * Hàm set cấu hình Config cho HTML Purifier
     *
     * Mảng dữ liệu với key và value
     *
     * @param array $config Mảng dữ liệu cấu hình
     *
     * @return  $this
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:51
     *
     * @see   http://htmlpurifier.org/live/configdoc/plain.html
     */
    public function setConfig(array $config = array()): HtmlSecurity
    {
        $this->config = $config;
        return $this;
    }

    /**
     * HTML Escape
     *
     * Hàm clean mã html, loại bỏ mã độc, mã bẩn sử dụng HTML Purifier
     *
     * @param string $dirtyHtml Chuỗi đầu vào
     *
     * @return string Nội dung đầu ra sau khi đã lọc
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 10/18/18 09:45
     *
     */
    public function escape(string $dirtyHtml = ''): string
    {
        // Create Config
        $config = HTMLPurifier_Config::createDefault();

        // Setup Cache.SerializerPath
        $config->set('Cache.SerializerPath', $this->cachePath);

        // Setup External Config
        if (!empty($this->config) && is_array($this->config) && count($this->config) > 0) {
            foreach ($this->config as $key => $value) {
                $config->set($key, $value);
            }
        }

        // Init HTMLPurifier
        $purifier = new HTMLPurifier($config);
        $cleanHtml = $purifier->purify($dirtyHtml);

        return trim($cleanHtml);
    }
}
