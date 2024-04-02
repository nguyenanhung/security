<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 9/28/18
 * Time: 14:47
 */

namespace nguyenanhung\MySecurity\Repository;


use nguyenanhung\MySecurity\ProjectInterface;
use nguyenanhung\MySecurity\VersionTrait;

/**
 * Class DataRepository
 *
 * @package   nguyenanhung\MySecurity\Repository
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
class DataRepository implements ProjectInterface
{
	use VersionTrait;

	const CONFIG_PATH = 'config';
	const CONFIG_EXT = '.php';

	/**
	 * Hàm lấy nội dung config được quy định trong thư mục config
	 *
	 * @param string $configName Tên file config
	 *
	 * @return array|mixed
	 * @author: 713uk13m <dev@nguyenanhung.com>
	 * @time  : 9/28/18 14:47
	 *
	 */
	public static function getData(string $configName)
	{
		$path = __DIR__ . DIRECTORY_SEPARATOR . self::CONFIG_PATH . DIRECTORY_SEPARATOR . $configName . self::CONFIG_EXT;
		if (is_file($path) && file_exists($path)) {
			return require $path;
		}
		return [];
	}

	/**
	 * Hàm lấy nội dung Data từ 1 file bất kỳ trong hệ thống
	 *
	 * @param string $filename Đường dẫn file config
	 *
	 * @return array|mixed
	 * @author: 713uk13m <dev@nguyenanhung.com>
	 * @time  : 10/17/18 09:25
	 *
	 */
	public static function getDataContent(string $filename)
	{
		if (is_file($filename) && file_exists($filename)) {
			return require $filename;
		}
		return [];
	}
}
