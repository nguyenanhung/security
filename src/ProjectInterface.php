<?php
/**
 * Project security.
 * Created by PhpStorm.
 * User: 713uk13m <dev@nguyenanhung.com>
 * Date: 10/4/18
 * Time: 14:55
 */

namespace nguyenanhung\MySecurity;

/**
 * Interface ProjectInterface
 *
 * @package   nguyenanhung\MySecurity
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
interface ProjectInterface
{
	const VERSION = '3.1.3';
	const USE_BENCHMARK = true;

	/**
	 * Hàm lấy thông tin phiên bản Package
	 *
	 * @return string Current Project Version, VD: 0.1.0
	 * @author  : 713uk13m <dev@nguyenanhung.com>
	 * @time    : 10/13/18 15:12
	 *
	 */
	public function getVersion(): string;
}
