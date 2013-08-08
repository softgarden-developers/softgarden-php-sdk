<?php

abstract class ServletUtils {

	public function getHttpHost($trustForwarded) {
		if ($trustForwarded && isset($_SERVER['HTTP_X_FORWARDED_HOST'])) {
			return $_SERVER['HTTP_X_FORWARDED_HOST'];
		}
		return $_SERVER['HTTP_HOST'];
	}

	public static function getHttpProtocol($trustForwarded) {
		if ($trustForwarded && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
			if ($_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
				return 'https';
			}
			return 'http';
		}
		/*apache + variants specific way of checking for https*/
		if (isset($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on' || $_SERVER['HTTPS'] == 1)) {
			return 'https';
		}
		/*nginx way of checking for https*/
		if (isset($_SERVER['SERVER_PORT']) && ($_SERVER['SERVER_PORT'] === '443')) {
			return 'https';
		}
		return 'http';
	}

	public static function isHttps($trustForwarded) {
		return self::getHttpProtocol($trustForwarded) === 'https';
	}
	
}
