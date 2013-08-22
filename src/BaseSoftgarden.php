<?php

if (!function_exists('curl_init')) {
	throw new Exception('softgarden needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
	throw new Exception('softgarden needs the JSON PHP extension.');
}

require_once 'ServletUtils.php';

/**
 * Thrown when an API call returns an exception.
 *
 * @author schueffi <schueffler@softgarden.de>
 */
class SoftgardenApiException extends Exception {
	/**
	 * The result from the API server that represents the exception information.
	 */
	protected $result;

	/**
	 * Make a new API Exception with the given result.
	 *
	 * @param array $result The result from the API server
	 */
	public function __construct($result) {
		$this->result = $result;

		$code = isset($result['error_code']) ? $result['error_code'] : 0;

		if (isset($result['error_description'])) {
			// OAuth 2.0 Draft 10 style
			$msg = $result['error_description'];
		} else if (isset($result['error_msg'])) {
			// Rest server style
			$msg = $result['error_msg'];
		} else {
			$msg = 'Unknown Error. Check getResult()';
		}

		parent::__construct($msg, $code);
	}

	/**
	 * Return the associated result object returned by the API server.
	 *
	 * @return array The result from the API server
	 */
	public function getResult() {
		return $this->result;
	}

	/**
	 * Returns the associated type for the error. This will default to
	 * 'Exception' when a type is not available.
	 *
	 * @return string
	 */
	public function getType() {
		if (isset($this->result['error'])) {
			$error = $this->result['error'];
			if (is_string($error)) {
				// OAuth 2.0 Draft 10 style
				return $error;
			}
		}

		return 'Exception';
	}

	/**
	 * To make debugging easier.
	 *
	 * @return string The string representation of the error
	 */
	public function __toString() {
		$str = $this->getType() . ': ';
		if ($this->code != 0) {
			$str .= $this->code . ': ';
		}
		return $str . $this->message;
	}
}

abstract class BaseSoftgarden {

	/**
	 * Version.
	 */
	const VERSION = '2.0';

	/**
	 * Default options for curl.
	 */
	public static $CURL_OPTS = array(
			CURLOPT_CONNECTTIMEOUT => 10,   // The maximum number of seconds to allow cURL to wait for connection establishement
			CURLOPT_RETURNTRANSFER => true, // Tell curl to write the response to a variable
			CURLOPT_TIMEOUT        => 60,   // The maximum number of seconds to allow cURL functions to execute.
			CURLOPT_USERAGENT      => 'softgarden-php-2.0', // add useragent

			// TODO changeme!!! (SNI problem fix?)
			CURLOPT_SSL_VERIFYHOST	=> 0,
			CURLOPT_SSL_VERIFYPEER	=> 0,

			CURLOPT_FOLLOWLOCATION	=> 0,	// make sure we get the header
			CURLINFO_HEADER_OUT		=> 1, 	// help debugging
				
	);

	/**
	 * List of query parameters that get automatically dropped when rebuilding
	 * the current URL.
	 */
	protected static $DROP_QUERY_PARAMS = array(
			'code',
			'state'
	);
	
	/**
	 * The API base url.
	 *
	 * @var string
	 */
	protected $apiBaseUrl;
	
	/**
	 * The Application ID.
	 *
	 * @var string
	 */
	protected $appId;

	/**
	 * The Application App Secret.
	 *
	 * @var string
	 */
	protected $appSecret;

	/**
	 * The ID of the softgarden user, or 0 if the user is logged out.
	 *
	 * @var integer
	 */
	//protected $user;

	/**
	 * A CSRF state variable to assist in the defense against CSRF attacks.
	 */
	protected $state;

	/**
	 * The OAuth access token received in exchange for a valid authorization
	 * code.  null means the access token has yet to be determined.
	 *
	 * @var string
	 */
	protected $accessToken = NULL;

	/**
	 * Indicates if the CURL based @ syntax for file uploads is enabled.
	 *
	 * @var boolean
	 */
	protected $fileUploadSupport = false;

	/**
	 * Indicates if we trust HTTP_X_FORWARDED_* headers.
	 *
	 * @var boolean
	 */
	protected $trustForwarded = false;
	

	/**
	 * The locale for internationalized api calls.
	 * Defaults to 'en'
	 *
	 * @var string, IETF BCP 47 language tag (optional: list as accepted by Accept-Language http header)
	 */
	protected $locale = 'en';

	/**
	 * Initialize a softgarden Application.
	 *
	 * The configuration:
	 * - appId: the application ID
	 * - secret: the application secret
	 * - apiBaseUrl: (optional) The api base url. Defaults to https://api.softgarden-cloud.com/api/rest
	 * - fileUpload: (optional) boolean indicating if file uploads are enabled
	 * - trustForwarded: (optional) boolean indicating if we trust HTTP_X_FORWARDED_* headers.
	 * - locale: (optional), defaults to 'en'
	 *
	 * @param array $config The application configuration
	 */
	public function __construct($config) {
		$this->setAppId($config['appId']);
		$this->setAppSecret($config['secret']);
		if (isset($config['apiBaseUrl']) && !empty($config['apiBaseUrl'])) {
			$this->setApiBaseUrl($config['apiBaseUrl']);
		} else {
			$this->setApiBaseUrl('https://api.softgarden-cloud.com/api/rest');
		}
		if (isset($config['fileUpload']) && $config['fileUpload']) {
			$this->setFileUploadSupport(true);
		}
		if (isset($config['trustForwarded']) && $config['trustForwarded']) {
			$this->trustForwarded = true;
		}
		if (isset($config['locale'])) {
			$this->locale = $config['locale'];
		}
		
		$state = $this->getPersistentData('state');
		if (!empty($state)) {
			$this->state = $state;
		}
	}

	/**
	 * Set the API base url.
	 *
	 * @param string $appId The API base url
	 * @return BaseSoftgarden
	 */
	public function setApiBaseUrl($apiBaseUrl) {
		$this->apiBaseUrl = $apiBaseUrl;
		return $this;
	}
	
	/**
	 * Get the Application ID.
	 *
	 * @return string the Application ID
	 */
	public function getApiBaseUrl() {
		return $this->apiBaseUrl;
	}
	
	
	/**
	 * Set the Application ID.
	 *
	 * @param string $appId The Application ID
	 * @return BaseSoftgarden
	 */
	public function setAppId($appId) {
		$this->appId = $appId;
		return $this;
	}

	/**
	 * Get the Application ID.
	 *
	 * @return string the Application ID
	 */
	public function getAppId() {
		return $this->appId;
	}

	/**
	 * Set the App Secret.
	 *
	 * @param string $appSecret The App Secret
	 * @return BaseSoftgarden
	 */
	public function setAppSecret($appSecret) {
		$this->appSecret = $appSecret;
		return $this;
	}

	/**
	 * Get the App Secret.
	 *
	 * @return string the App Secret
	 */
	public function getAppSecret() {
		return $this->appSecret;
	}

	/**
	 * Set the locale.
	 *
	 * @param string $locale The locale
	 * @return BaseSoftgarden
	 */
	public function setLocale($locale) {
		$this->locale = $locale;
		return $this;
	}
	
	/**
	 * Get the locale.
	 *
	 * @return string the locale
	 */
	public function getLocale() {
		return $this->locale;
	}
	
	/**
	 * Set the file upload support status.
	 *
	 * @param boolean $fileUploadSupport The file upload support status.
	 * @return BaseSoftgarden
	 */
	public function setFileUploadSupport($fileUploadSupport) {
		$this->fileUploadSupport = $fileUploadSupport;
		return $this;
	}

	/**
	 * Get the file upload support status.
	 *
	 * @return boolean true if and only if the server supports file upload.
	 */
	public function getFileUploadSupport() {
		return $this->fileUploadSupport;
	}

	/**
	 * Sets the access token for api calls.  Use this if you get
	 * your access token by other means and just want the SDK
	 * to use it.
	 *
	 * @param string $access_token an access token.
	 * @return BaseSoftgarden
	 */
	public function setAccessToken($access_token) {
		$this->accessToken = $access_token;
		return $this;
	}

	/**
	 * Determines the access token that should be used for API calls.
	 * The first time this is called, $this->accessToken is set equal
	 * to either a valid user access token, or it's set to the application
	 * access token if a valid user access token wasn't available.  Subsequent
	 * calls return whatever the first call returned.
	 *
	 * @return string The access token
	 */
	public function getAccessToken() {
		if ($this->accessToken !== NULL) {
			// we've done this already and cached it.  Just return.
			return $this->accessToken;
		}

		// first establish access token to be the application
		// access token, in case we navigate to the /oauth/access_token
		// endpoint, where SOME access token is required.
		$this->setAccessToken($this->getApplicationAccessToken());
		$user_access_token = $this->getUserAccessToken();
		if ($user_access_token) {
			$this->setAccessToken($user_access_token);
		}

		return $this->accessToken;
	}

	/**
	 * Determines and returns the user access token, first using
	 * the signed request if present, and then falling back on
	 * the authorization code if present.  The intent is to
	 * return a valid user access token, or false if one is determined
	 * to not be available.
	 *
	 * @return string A valid user access token, or false if one
	 *                could not be determined.
	 */
	protected function getUserAccessToken() {
		$code = $this->getCode();
		if ($code && $code != $this->getPersistentData('code')) {
			$access_token = $this->getAccessTokenFromCode($code);
			if ($access_token) {
				$this->setPersistentData('code', $code);
				$this->setPersistentData('access_token', $access_token);
				return $access_token;
			}

			// code was bogus, so everything based on it should be invalidated.
			$this->clearAllPersistentData();
			return false;
		}

		// as a fallback, just return whatever is in the persistent
		// store, knowing nothing explicit (signed request, authorization
		// code, etc.) was present to shadow it (or we saw a code in $_REQUEST,
		// but it's the same as what's in the persistent store)
		return $this->getPersistentData('access_token');
	}

	/**
	 * Returns the access token that should be used for logged out
	 * users when no authorization code is available.
	 *
	 * @return string The application access token, useful for gathering
	 *                public information about users and applications.
	 */
	protected function getApplicationAccessToken() {
		return NULL; // $this->appId.'|'.$this->appSecret;
	}
	
	/**
	 * Get the authorization code from the query parameters, if it exists,
	 * and otherwise return false to signal no authorization code was
	 * discoverable.
	 *
	 * @return mixed The authorization code, or false if the authorization
	 *               code could not be determined.
	 */
	protected function getCode() {
		if (isset($_REQUEST['code'])) {
			if ($this->state !== NULL &&
			isset($_REQUEST['state']) &&
			$this->state === $_REQUEST['state']) {

				// CSRF state has done its job, so clear it
				$this->state = NULL;
				$this->clearPersistentData('state');
				return $_REQUEST['code'];
			} else {
				self::errorLog('CSRF state token does not match one provided.');
				return false;
			}
		}

		return false;
	}

	/**
	 * Get the UID of the connected user, or 0
	 * if the softgarden user is not connected.
	 *
	 * @return string the UID if available.
	 */
// 	public function getUser() {
// 		if ($this->user !== NULL) {
// 			// we've already determined this and cached the value.
// 			return $this->user;
// 		}
	
// 		return $this->user = $this->getUserFromAvailableData();
// 	}
	
	/**
	 * Determines the connected user by first examining any signed
	 * requests, then considering an authorization code, and then
	 * falling back to any persistent store storing the user.
	 *
	 * @return integer The id of the connected softgarden user,
	 *                 or 0 if no such user exists.
	 */
// 	protected function getUserFromAvailableData() {
// 		// if a signed request is supplied, then it solely determines
// 		// who the user is.
// 		$signed_request = $this->getSignedRequest();
// 		if ($signed_request) {
// 			if (array_key_exists('user_id', $signed_request)) {
// 				$user = $signed_request['user_id'];
	
// 				if($user != $this->getPersistentData('user_id')){
// 					$this->clearAllPersistentData();
// 				}
	
// 				$this->setPersistentData('user_id', $signed_request['user_id']);
// 				return $user;
// 			}
	
// 			// if the signed request didn't present a user id, then invalidate
// 			// all entries in any persistent store.
// 			$this->clearAllPersistentData();
// 			return 0;
// 		}
	
// 		$user = $this->getPersistentData('user_id', $default = 0);
// 		$persisted_access_token = $this->getPersistentData('access_token');
	
// 		// use access_token to fetch user id if we have a user access_token, or if
// 		// the cached access token has changed.
// 		$access_token = $this->getAccessToken();
// 		if ($access_token &&
// 		$access_token != $this->getApplicationAccessToken() &&
// 		!($user && $persisted_access_token == $access_token)) {
// 			$user = $this->getUserFromAccessToken();
// 			if ($user) {
// 				$this->setPersistentData('user_id', $user);
// 			} else {
// 				$this->clearAllPersistentData();
// 			}
// 		}
	
// 		return $user;
// 	}
	
	
	/**
	 * Retrieves the UID with the understanding that
	 * $this->accessToken has already been set and is
	 * seemingly legitimate.  It relies on softgardens API
	 * to retrieve user information and then extract
	 * the user ID.
	 *
	 * @return integer Returns the UID of the softgarden user, or 0
	 *                 if the softgarden user could not be determined.
	 */
// 	protected function getUserFromAccessToken() {
// 		try {
// 			$user_info = $this->api('/me');
// 			return $user_info['id'];
// 		} catch (SoftgardenApiException $e) {
// 			return 0;
// 		}
// 	}
	
	/**
	 * Lays down a CSRF state token for this process.
	 *
	 * @return void
	 */
	protected function establishCSRFTokenState() {
		if ($this->state === NULL) {
			$this->state = md5(uniqid(mt_rand(), true));
			$this->setPersistentData('state', $this->state);
		}
	}

	/**
	 * Retrieves an access token for the given authorization code
	 * (previously generated from softgarden on behalf of
	 * a specific user).  The authorization code is sent to softgarden
	 * and a legitimate access token is generated provided the access token
	 * and the user for which it was generated all match, and the user is
	 * either logged in to softgarden or has granted an offline access permission.
	 *
	 * @param string $code An authorization code.
	 * @return mixed An access token exchanged for the authorization code, or
	 *               false if an access token could not be generated.
	 */
	protected function getAccessTokenFromCode($code, $redirect_uri = NULL) {
		if (empty($code)) {
			return false;
		}

		if ($redirect_uri === NULL) {
			$redirect_uri = $this->getCurrentUrl();
		}

		try {
			// avoid calling the api directly as we do not want to set a fallback accesstoken (instead use the basic auth header explicitely)
			$result = json_decode(
					$this->makeRequest(
							$this->getUrl('/oauth/frontend/token'),
							array(
									//'client_id' 	=> $this->getAppId(),
									//'client_secret' => $this->getAppSecret(),
									'grant_type' 	=> 'authorization_code',
									'code' 			=> $code,
									'redirect_uri' 	=> $redirect_uri,
									'user_ip' 		=> $_SERVER['REMOTE_ADDR']
							),
							'POST'
							
							
					),
					true);
			
			// results are returned, errors are thrown
			if (is_array($result) && isset($result['error'])) {
				$this->throwAPIException($result);
				// @codeCoverageIgnoreStart
			}
				
		} catch (SoftgardenApiException $e) {
			// most likely that user very recently revoked authorization.
			// In any event, we don't have an access token, so say so.
			return false;
		}

		if (empty($result)) {
			return false;
		}

		if (!isset($result['access_token'])) {
			return false;
		}

		return $result['access_token'];
	}

	/**
	 * Build the URL for given domain alias, path and parameters.
	 *
	 * @param $name string The name of the domain
	 * @param $path string Optional path (without a leading slash)
	 * @param $params array Optional query parameters
	 *
	 * @return string The URL for the given parameters
	 */
	protected function getUrl($path='', $params = NULL) {
		$url = $this->getApiBaseUrl() . '/';
		if ($path) {
			if ($path[0] === '/') {
				$path = substr($path, 1);
			}
			$url .= $path;
		}
		if (is_array($params) && !empty($params)) {
			$url .= 
				(strpos($url, '?') === false ? '?' : '&')
				. http_build_query($params, NULL, '&');
		}

		return $url;
	}
	
	/**
	 * Makes an HTTP request. This method can be overridden by subclasses if
	 * developers want to do fancier things or use something other than curl to
	 * make the request.
	 *
	 * @param string $url The URL to make the request to
	 * @param array $params The parameters to use for the POST body
	 * @param CurlHandler $ch Initialized curl handle
	 *
	 * @return string The response text
	 */
	protected function makeRequest($url, $params, $method = 'GET', $accessToken = NULL, $returnHeader = 0, $contentType = null) {
		$ch = curl_init();

		$opts = self::$CURL_OPTS;
		
		// set target url
		$opts[CURLOPT_URL] = $url;

		
		// make sure we get the header if we want them for redirects on client side
		$opts[CURLOPT_HEADER] = $returnHeader;
		
		
		// set additional http headers
		if (isset($opts[CURLOPT_HTTPHEADER])) {
			$headers = $opts[CURLOPT_HTTPHEADER];
		} else {
			$headers = array();
		}
		
		// disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
		// for 2 seconds if the server does not support this header.
		$headers[] = 'Expect:';

		// set the accept header to json, if nothing else is requested
		if (empty ( $contentType )) {
			$contentType = 'application/json';
		}
		$headers[] = "Accept: $contentType";
		
		// set the locale for i18n api calls
		$headers[] = "Accept-Language: " . $this->locale;

		
		if ($method == "POST") {
			$opts[CURLOPT_POST] = true;
			if ($this->getFileUploadSupport()) {
				$opts[CURLOPT_POSTFIELDS] = $params;
			} else {
				$opts[CURLOPT_POSTFIELDS] = http_build_query($params, NULL, '&');
			}
			
		} else if ($method == "JSONPOST") {
			$json = json_encode($params);
			$opts[CURLOPT_POSTFIELDS] = $json;
			$opts[CURLOPT_CUSTOMREQUEST] = "POST";
			$headers[] = "Content-Type: application/json";
			$headers[] = "Content-Length: " . strlen($json);
		
		} else if ($method == "PUT") {
			$json = json_encode($params);
			$opts[CURLOPT_POSTFIELDS] = $json;
			$opts[CURLOPT_CUSTOMREQUEST] = "PUT";
			$headers[] = "Content-Type: application/json";
			$headers[] = "Content-Length: " . strlen($json);
					
		} else if ($method == "DELETE") {
			$opts[CURLOPT_CUSTOMREQUEST] = "DELETE";
		}
		// GET is curl's default
		
		
		if ($accessToken !== NULL) {
			$headers[] = "Authorization: Bearer $accessToken";
		
		} else if ($this->appId !== NULL) {
			curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ;
			curl_setopt($ch, CURLOPT_USERPWD, $this->appId . ($this->appSecret !== NULL ? ':' . $this->appSecret : '') );
		}
		
		// and set all headers to curl
		$opts[CURLOPT_HTTPHEADER] = $headers;
		

		curl_setopt_array($ch, $opts);
		$result = curl_exec($ch);

//   	if (curl_errno($ch) == 60) { // CURLE_SSL_CACERT
//   		self::errorLog('Invalid or no certificate authority found, '.
//   				'using bundled information');
//   		curl_setopt($ch, CURLOPT_CAINFO,
//   		dirname(__FILE__) . '/sg_ca_chain_bundle.crt');
//   		$result = curl_exec($ch);
//   	}

		// With dual stacked DNS responses, it's possible for a server to
		// have IPv6 enabled but not have IPv6 connectivity.  If this is
		// the case, curl will try IPv4 first and if that fails, then it will
		// fall back to IPv6 and the error EHOSTUNREACH is returned by the
		// operating system.
		if ($result === false && empty($opts[CURLOPT_IPRESOLVE])) {
			$matches = array();
			$regex = '/Failed to connect to ([^:].*): Network is unreachable/';
			if (preg_match($regex, curl_error($ch), $matches)) {
				if (strlen(@inet_pton($matches[1])) === 16) {
					self::errorLog('Invalid IPv6 configuration on server, '.
							'Please disable or get native IPv6 on your server.');
					self::$CURL_OPTS[CURLOPT_IPRESOLVE] = CURL_IPRESOLVE_V4;
					curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
					$result = curl_exec($ch);
				}
			}
		}

		if ($result === false) {
			$e = new SoftgardenApiException(array(
					'error_code' => curl_errno($ch),
					'error' => 'CurlException',
					'error_description' => curl_error($ch)
			));
			curl_close($ch);
			throw $e;
		}
		curl_close($ch);
		return $result;
	}

	protected function getHttpHost() {
		return ServletUtils::getHttpHost($this->trustForwarded);
	}
	
	protected function getHttpProtocol() {
		return ServletUtils::getHttpProtocol($this->trustForwarded);
	}
	
	/**
	 * Returns the Current URL, stripping it of known SG parameters that should
	 * not persist.
	 *
	 * @return string The current URL
	 */
	protected function getCurrentUrl() {
		$protocol = $this->getHttpProtocol() . '://';
		$host = $this->getHttpHost();
		$currentUrl = $protocol.$host.$_SERVER['REQUEST_URI'];
		$parts = parse_url($currentUrl);
	
		$query = '';
		if (!empty($parts['query'])) {
			// drop known fb params
			$params = explode('&', $parts['query']);
			$retained_params = array();
			foreach ($params as $param) {
				if ($this->shouldRetainParam($param)) {
					$retained_params[] = $param;
				}
			}
	
			if (!empty($retained_params)) {
				$query = '?'.implode($retained_params, '&');
			}
		}
	
		// use port if non default
		$port =
		isset($parts['port']) &&
		(($protocol === 'http://' && $parts['port'] !== 80) ||
				($protocol === 'https://' && $parts['port'] !== 443))
				? ':' . $parts['port'] : '';
	
		// rebuild
		return $protocol . $parts['host'] . $port . $parts['path'] . $query;
	}
	
	/**
	 * Returns true if and only if the key or key/value pair should
	 * be retained as part of the query string.  This amounts to
	 * a brute-force search of the very small list of softgarden-specific
	 * params that should be stripped out.
	 *
	 * @param string $param A key or key/value pair within a URL's query (e.g.
	 *                     'foo=a', 'foo=', or 'foo'.
	 *
	 * @return boolean
	 */
	protected function shouldRetainParam($param) {
		foreach (self::$DROP_QUERY_PARAMS as $drop_query_param) {
			if (strpos($param, $drop_query_param.'=') === 0) {
				return false;
			}
		}
	
		return true;
	}
	
	public function put($url, $data = NULL, $accessToken = null) {
		return $this->api($url, $data, 'PUT', $accessToken);
	}
	
	public function post($url, $data = NULL, $accessToken = null) {
		return $this->api($url, $data, 'JSONPOST', $accessToken);
	}
	
	public function get($url, $data = NULL, $accessToken = null, $contentType = null) {
		return $this->api($url, $data, 'GET', $accessToken, 0, $contentType);
	}
	
	public function delete($url, $data = NULL, $accessToken = null) {
		return $this->api($url, $data, 'DELETE', $accessToken);
	}
	

	/**
	 * Make an API call.
	 *
	 * @param string $path The path (required)
	 * @param string $method The http method (default 'GET')
	 * @param array $params The query/post data
	 *
	 * @return mixed The decoded response object
	 * @throws SoftgardenApiException
	 */
	public function api($path, $params = NULL, $method = 'GET', $accessToken = null, $returnHeader = 0, $contentType = null) {
		$paramsAsQueryString = $method == 'GET' || $method == 'DELETE';
		$url = $this->getUrl($path, $paramsAsQueryString ? $params : NULL);
		
		$result = $this->makeRequest(
						$url,
						$params,
						$method,
						$accessToken == null ? $this->getAccessToken() : $accessToken,
						$returnHeader,
						$contentType
				);
		
		if ($contentType == null || $contentType == "application/json") {
			$result = $this->jsonDecode($result);
		}
	
		// results are returned, errors are thrown
		if (isset($result->error)) {
			$this->throwAPIException($result);
			// @codeCoverageIgnoreStart
		}
		// @codeCoverageIgnoreEnd
	
		return $result;
	}

	
	public function jsonDecode($response) {
		$ret = json_decode($response);
	
		if (json_last_error() == JSON_ERROR_NONE) {
			return $ret;
		}
	
		return $response;
	}
	
	
	/**
	 * Analyzes the supplied result to see if it was thrown
	 * because the access token is no longer valid.  If that is
	 * the case, then we destroy the session.
	 *
	 * @param $result array A record storing the error message returned
	 *                      by a failed API call.
	 */
	protected function throwAPIException($result) {
		$result = jsond_decode(json_encode($result), true);
		$e = new SoftgardenApiException($result);
		switch ($e->getType()) {
			// OAuth 2.0 Draft 00 style
			case 'OAuthException':
				// OAuth 2.0 Draft 10 style
			case 'invalid_token':
				// REST server errors are just Exceptions
			case 'Exception':
				$message = $e->getMessage();
				if (
				(strpos($message, 'token expired or otherwise invalid') !== false) ||
				(strpos($message, 'Error validating access token') !== false) ||
				(strpos($message, 'Invalid OAuth access token') !== false) ||
				(strpos($message, 'An active access token must be used') !== false)
				) {
					$this->destroySession();
				}
				break;
		}
	
		throw $e;
	}
	
	/**
	 * Prints to the error log if you aren't in command line mode.
	 *
	 * @param string $msg Log message
	 */
	protected static function errorLog($msg) {
		// disable error log if we are running in a CLI environment
		// @codeCoverageIgnoreStart
		if (php_sapi_name() != 'cli') {
			error_log($msg);
		}
		// uncomment this if you want to see the errors on the page
		// print 'error_log: '.$msg."\n";
		// @codeCoverageIgnoreEnd
	}
	
	/**
	 * Destroy the current session
	 */
	public function destroySession() {
		$this->accessToken = NULL;
		//$this->user = NULL;
		$this->clearAllPersistentData();
	}
	
  
	
	
	/**
	 * Each of the following four methods should be overridden in
	 * a concrete subclass, as they are in the provided Softgarden class.
	 * The Softgarden class uses PHP sessions to provide a primitive
	 * persistent store, but another subclass--one that you implement--
	 * might use a database, memcache, or an in-memory cache.
	 *
	 * @see Softgarden
	 */
	
	/**
	 * Stores the given ($key, $value) pair, so that future calls to
	 * getPersistentData($key) return $value. This call may be in another request.
	 *
	 * @param string $key
	 * @param array $value
	 *
	 * @return void
	 */
	abstract protected function setPersistentData($key, $value);
	
	/**
	 * Get the data for $key, persisted by BaseSoftgarden::setPersistentData()
	 *
	 * @param string $key The key of the data to retrieve
	 * @param boolean $default The default value to return if $key is not found
	 *
	 * @return mixed
	 */
	abstract protected function getPersistentData($key, $default = false);
	
	/**
	 * Clear the data with $key from the persistent storage
	 *
	 * @param string $key
	 * @return void
	 */
	abstract protected function clearPersistentData($key);
	
	/**
	 * Clear all data from the persistent storage
	 *
	 * @return void
	 */
	abstract protected function clearAllPersistentData();
	
}
