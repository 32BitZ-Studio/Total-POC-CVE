<?php
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/
/**
 * @package vBulletin
 */

/*
 * 	Note despite only supporting cUrl (and not intending to support anything else for the forseeable
 * 	future) we don't just convert the calling code to cUrl because this class allows us to set
 * 	defaults to vBulletin specific values, simply the interface by hiding options we don't need,
 * 	and adding logic to get around cUrl bugs/problems.  Most notably adding checking to prevent outgoing
 * 	connections to internal urls (including on redirect) which is a security hazard.  It also makes it
 * 	slightly easier to add additional implemenations down the road by providing an interface that we
 * 	can write to.
 */
class vB_Utility_Url
{
	use vB_Utility_Trait_NoSerialize;

	//note that URL/POST/POSTFIELDS/CUSTOMREQUEST are set via the public request functions
	//and will probably not do anything useful if set via setOption.  We should hide these
	//and, if the current functions don't cover a use case then create more.

	//constants for options.
	const URL = 1;
	const TIMEOUT = 2;
	const POST = 4;
	const HEADER = 8;
	const POSTFIELDS = 16;
	const ENCODING = 32;
//	const USERAGENT = 64;
	//const RETURNTRANSFER = 128;
	const HTTPHEADER = 256;

	const CLOSECONNECTION = 1024;
	const FOLLOWLOCATION = 2048;
	const MAXREDIRS = 4096;
	const NOBODY = 8192;
	const CUSTOMREQUEST = 16384;
	const MAXSIZE = 32768;
	const DIEONMAXSIZE = 65536;
	const VALIDSSLONLY = 131072;
	const TEMPFILENAME = 262144;

	//there used to be more, but they weren't used.
	const ERROR_MAXSIZE = 1;
	const ERROR_NOFILE = 2;
	const ERROR_NOLIB = 8;

	//some stuff to keep track of internal state in the callbacks.
	//used to determine if we should log to the file
	//these should be considered private even though PHP doesn't allow that.
	const STATE_HEADERS = 1;
	const STATE_LOCATION = 2;
 	const STATE_BODY = 3;

	//class vars
	private $errror = 0;

	private $bitoptions = 0;
	private $options = array();

	private $allowedports;
	private $allowip;
	private $allowlocal;
	private $allowedsiteroot;

	private $response_text = '';
	private $response_header = '';

	private $string;
	private $ip;
	private $ch;
	private $tempfilepointer;

	private $response_length = 0;
	private $max_limit_reached = false;

	/**
	* Constructor
	*
	* @param vB_Utility_String $string -- the properly configured string object.
	*	@param array|int $allowedports -- ports in addition to 80 and 443 that we allow outgoing connections to.
	*/
	public function __construct($string, $validationOptions)
	{
		$this->string = $string;
		//this doesn't need to be configured for the specific site so we don't
		//need to pass it in.  But keep it as a class variable to avoid constantly
		//instantiated it -- and in case that changes.
		$this->ip = new vB_Utility_Ip();

		$this->allowedports = $validationOptions['allowedports'] ?? array();
		if (!is_array($this->allowedports))
		{
			$this->allowedports = array($this->allowedports);
		}

		$this->allowip = $validationOptions['allowip'] ?? false;
		$this->allowlocal = $validationOptions['allowlocal'] ?? false;
		$this->allowedsiteroot = $validationOptions['allowedsiteroot'] ?? '';

		$this->reset();
	}

	/**
	 * This deals with the case that people forget to either unlink or move the file.
	 */
	//this behavior is copied from the original vurl implementation.  It's a bit
	//problematic because we call might not be aware that the file we return will
	//magically go away if they don't immediately do something with it.  On the other
	//hand, we don't necesarily want to leave the file around either
	//Leaving the way it was.
	public function __destruct()
	{
		$this->deleteTempFile();
	}

	/**
	* Set Error
	*
	* @param int $errorcode
	*/
	private function setError($errorcode)
	{
		$this->error = $errorcode;
	}

	/**
	* Return Error
	*
	* @return	int errorcode
	*/
	public function getError()
	{
		return $this->error;
	}

	/**
	* Callback for handling headers
	*
	* @param	resource	cURL object
	* @param	string		Request
	*
	* @return	integer		length of the request
	*/
	public function curl_callback_header(&$ch, $string)
	{
		if (trim($string) !== '')
		{
			$this->response_header .= $string;
		}
		return strlen($string);
	}


	/**
	* On/Off options
	*
	* @param		integer	one of the option constants
	* @param		mixed		option to set
	*
	*/
	public function setOption($option, $extra)
	{
		switch ($option)
		{
			case self::POST:
			case self::HEADER:
			case self::NOBODY:
			case self::FOLLOWLOCATION:
			case self::CLOSECONNECTION:
			case self::VALIDSSLONLY:
				if ($extra)
				{
					$this->bitoptions |= $option;
				}
				else
				{
					$this->bitoptions &= ~$option;
				}
				break;

			case self::TIMEOUT:
				$timeout = intval($extra);
				if(!$timeout)
				{
					$timeout = 15;
				}
				$this->options[self::TIMEOUT] = $timeout;
				break;

			case self::POSTFIELDS:
				if ($extra)
				{
					$this->options[self::POSTFIELDS] = $extra;
				}
				else
				{
					$this->options[self::POSTFIELDS] = '';
				}
				break;
			case self::ENCODING:
//			case self::USERAGENT:
			case self::URL:
			case self::CUSTOMREQUEST:
			case self::TEMPFILENAME:
				$this->options[$option] = $extra;
				break;

			case self::HTTPHEADER:
				if (is_array($extra))
				{
					$this->options[self::HTTPHEADER] = $extra;
				}
				else
				{
					$this->options[self::HTTPHEADER] = array();
				}
				break;

			case self::MAXSIZE:
			case self::MAXREDIRS:
			case self::DIEONMAXSIZE:
				$this->options[$option] = intval($extra);
				break;
		}
	}

	/**
	* Callback for handling the request body
	*
	* @param	resource	cURL object
	* @param	string		Request
	*
	* @return	integer		length of the request
	*/
	public function curl_callback_response(&$ch, $response)
	{
		$chunk_length = strlen($response);

		/* We receive both headers + body */
		if ($this->bitoptions & self::HEADER)
		{
			if ($this->__finished_headers != self::STATE_BODY)
			{
				if ($this->bitoptions & self::FOLLOWLOCATION AND preg_match('#(?<=\r\n|^)Location:#i', $response))
				{
					$this->__finished_headers = self::STATE_LOCATION;
				}

				if ($response === "\r\n")
				{
					if ($this->__finished_headers == self::STATE_LOCATION)
					{
						// found a location -- still following it; reset the headers so they only match the new request
						$this->response_header = '';
						$this->__finished_headers = self::STATE_HEADERS;
					}
					else
					{
						// no location -- we're done
						$this->__finished_headers = self::STATE_BODY;
					}
				}

				return $chunk_length;
			}
		}

		//if we don't have the temp file yet, open it.
		if(!$this->tempfilepointer AND $this->options[self::TEMPFILENAME])
		{
			$this->tempfilepointer = @fopen($this->options[self::TEMPFILENAME], 'wb');
			if(!$this->tempfilepointer)
			{
				$this->setError(self::ERROR_NOFILE);
				return false;
			}
		}

		if ($this->tempfilepointer)
		{
			fwrite($this->tempfilepointer, $response);
		}
		else
		{
			$this->response_text .= $response;
		}

		$this->response_length += $chunk_length;

		if (!empty($this->options[self::MAXSIZE]) AND $this->response_length > $this->options[self::MAXSIZE])
		{
			$this->max_limit_reached = true;
			$this->setError(self::ERROR_MAXSIZE);
			return false;
		}

		return $chunk_length;
	}

	/**
	 *	Perform a GET request
	 *
	 *	@param string $url
	 *	@return false | array
	 *		-- array headers -- the httpheaders return.  Empty if the HEADER is not set
	 *		-- string body -- the body of the request. Empty if NOBODY is set
	 *		Returns false on error
	 */
	public function get($url)
	{
		$this->setOption(self::URL, $url);
		$this->setOption(self::POST, 0);

		$result = $this->exec(array());
		if ($result)
		{
			return $this->formatResponse();
		}
		return false;
	}

	/**
	 *	Perform a POST request
	 *	@param string $url
	 *	@param array|string $postdata -- the data as either an array or "query param" string
	 *
	 *	@return false | array
	 *		-- array headers -- the httpheaders return.  Empty if the HEADER is not set
	 *		-- string body -- the body of the request. Empty if NOBODY is set
	 *		Returns false on error
	 */
	public function post($url, $postdata)
	{
		$this->setOption(self::URL, $url);
		$this->setOption(self::POST, 1);
		$this->setOption(self::POSTFIELDS, $postdata);

		$result = $this->exec(array());
		if ($result)
		{
			return $this->formatResponse();
		}
		return false;
	}

	/**
	 *	Perform a POST request using a JSON post body
	 *
	 *	This performs as post using a custom JSON request (popular with REST APIs) instead of
	 *	a standard x-www-form-urlencoded format
	 *
	 *	@param string $url
	 *	@param string $postdata -- the JSON encoded request.
	 *
	 *	@return false | array
	 *		-- array headers -- the httpheaders return.  Empty if the HEADER is not set
	 *		-- string body -- the body of the request. Empty if NOBODY is set
	 *		Returns false on error
	 */
	public function postJson($url, $postdata)
	{
		$this->setOption(self::URL, $url);
		$this->setOption(self::CUSTOMREQUEST, 'POST');
		$this->setOption(self::POSTFIELDS, $postdata);

		// Set HTTP Header for POST request
		$result = $this->exec(array('Content-Type: application/json'));
		if ($result)
		{
			return $this->formatResponse();
		}
		return false;
	}

	private function formatResponse()
	{
		$response = array(
			'headers' => array(),
			'body' => '',
		);

		if ($this->bitoptions & self::HEADER)
		{
			$response['headers'] = $this->buildHeaders($this->response_header);
		}

		if ($this->response_length > 0)
		{
			if($this->options[self::TEMPFILENAME])
			{
				$response['body'] = $this->options[self::TEMPFILENAME];
			}
			else
			{
				$response['body'] = $this->response_text;
			}
		}
		else
		{
			//we probably didn't create it, but if we did let's remove it if it's empty
			$this->deleteTempFile();
		}

		return $response;
	}

	private function buildHeaders($data)
	{
		$returnedheaders = explode("\r\n", $data);
		$headers = array();
		foreach ($returnedheaders AS $line)
		{
			@list($header, $value) = explode(': ', $line, 2);
			if (preg_match('#^http/([12](?:\.[012])?) ([12345]\d\d)#i', $header, $httpmatches))
			{
				$headers['http-response']['version'] = $httpmatches[1];
				$headers['http-response']['statuscode'] = $httpmatches[2];
			}
			else if (!empty($header))
			{
				$headers[strtolower($header)] = $value;
			}
		}

		return $headers;
	}

	/**
	* Performs fetching of the file if possible
	*
	* @return	boolean
	*/
	private function exec($extraheaders)
	{
		if (!function_exists('curl_init') OR ($this->ch = curl_init()) === false)
		{
			$this->setError(self::ERROR_NOLIB);
			return false;
		}

		$this->setCurlOptions($this->ch, $extraheaders);

		//we'll roll our own redirect logic for security reasons
		$redirect_tries = 1;
		if ($this->bitoptions & self::FOLLOWLOCATION)
		{
			$redirect_tries = $this->options[self::MAXREDIRS];
		}

		//sanity check to avoid an infinite loop
		if ($redirect_tries < 1)
		{
			$redirect_tries = 1;
		}

		$redirectCodes = array(301, 302, 307, 308);

		$url = $this->options[self::URL];
		for ($i = $redirect_tries; $i > 0; $i--)
		{
			$result = $this->execCurl($url);

			//if we don't have another iteration of the loop to go, skip the effort here.
			if (($i > 1) AND in_array(curl_getinfo($this->ch, CURLINFO_HTTP_CODE), $redirectCodes))
			{
				$url = curl_getinfo($this->ch, CURLINFO_REDIRECT_URL);
			}
			else
			{
				//if we don't have a redirect, skip the loop
				break;
			}
		}

		//if we are following redirects and still have a redirect code, its because we hit our limit without finding a real page
		//we want the fallback code to mimic the behavior of curl in this case
		if (($this->bitoptions & self::FOLLOWLOCATION) && in_array(curl_getinfo($this->ch, CURLINFO_HTTP_CODE), $redirectCodes))
		{
			$result = false;
		}

		//close the connection and clean up the file.
		curl_close($this->ch);
		$this->closeTempFile();

		if ($this->options[self::DIEONMAXSIZE] AND $this->max_limit_reached)
		{
			return false;
		}

		return $result;
	}


	private function setCurlOptions($ch, $extraheaders)
	{
		curl_setopt($ch, CURLOPT_TIMEOUT, $this->options[self::TIMEOUT]);
		if (!empty($this->options[self::CUSTOMREQUEST]))
		{
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $this->options[self::CUSTOMREQUEST]);

			//if we set a post this way, we still need to send the post fields.
			//documentation suggests that this is the correct way to send posts with non
			//standard post bodies (such as JSON or XML)
			if (strcasecmp($this->options[self::CUSTOMREQUEST], 'post') === 0)
			{
				curl_setopt($ch, CURLOPT_POSTFIELDS, $this->options[self::POSTFIELDS]);
			}
		}
		else if ($this->bitoptions & self::POST)
		{
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $this->options[self::POSTFIELDS]);
		}
		else
		{
			curl_setopt($ch, CURLOPT_POST, 0);
		}

		$headers = array_merge($this->options[self::HTTPHEADER], $extraheaders);

		if ($this->bitoptions & self::CLOSECONNECTION)
		{
			$headers[] = 'Connection: close';
		}

		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		if ($this->options[self::ENCODING])
		{
			// this will work on versions of cURL after 7.10, though was broken on PHP 4.3.6/Win32
			@curl_setopt($ch, CURLOPT_ENCODING, $this->options[self::ENCODING]);
		}


		curl_setopt($ch, CURLOPT_HEADER, ($this->bitoptions & self::HEADER) ? 1 : 0);
		if ($this->bitoptions & self::NOBODY)
		{
			curl_setopt($ch, CURLOPT_NOBODY, 1);
		}

		if (!($this->bitoptions & self::VALIDSSLONLY))
		{
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
		}

		//never use CURLOPT_FOLLOWLOCATION -- we need to make sure we are as careful with the
		//urls returned from the server as we are about the urls we initially load.
		//we'll loop internally up to the recommended tries.
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);

		curl_setopt($ch, CURLOPT_WRITEFUNCTION, array(&$this, 'curl_callback_response'));
		curl_setopt($ch, CURLOPT_HEADERFUNCTION, array(&$this, 'curl_callback_header'));
	}


	private function closeTempFile()
	{
		if ($this->tempfilepointer)
		{
			fclose($this->tempfilepointer);
			$this->tempfilepointer = null;
		}
	}

	private function deleteTempFile()
	{
		if (file_exists($this->options[self::TEMPFILENAME]))
		{
			@unlink($this->options[self::TEMPFILENAME]);
		}
	}

	public function reset()
	{
		$this->bitoptions = 0;
		$this->error = 0;

		$this->options = array(
			self::TIMEOUT    => 15,
			self::POSTFIELDS => '',
			self::ENCODING   => '',
			self::URL        => '',
			self::HTTPHEADER => array(),
			self::MAXREDIRS  => 5,
			self::DIEONMAXSIZE => 1,
			self::TEMPFILENAME => '',
		);
	}

	/**
	 * Clears all previous request info
	 */
	private function resetPageLoad()
	{
		$this->response_text = '';
		$this->response_header = '';
		$this->response_length = 0;
		$this->__finished_headers = self::STATE_HEADERS;
		$this->max_limit_reached = false;
		$this->closeTempFile();
	}

	/**
	 *	Actually load the url from the interweb
	 *	@param string $url
	 *	@params boolean $isHttps
	 *
	 *	@return string|false The result of curl_exec
	 */
	private function execCurl($url)
	{
		$this->resetPageLoad();

		$urlinfo = $this->string->parseUrl($url);
		$url = $this->rebuildUrl($urlinfo);

		curl_setopt($this->ch, CURLOPT_URL, $url);


		//if this is a site url (based on the site root) then
		if (!$this->isSiteUrl($urlinfo))
		{
			if (!$this->validateUrl($urlinfo))
			{
				return false;
			}

			//if we don't care about local IPs, don't make a separate exec.
			//testing indicates this *shoudn't* cause two TCP connections but documentation is
			//scanty and it serves no purpose if we aren't going to examine the IP before
			//actually sending the HTTP request.
			if (!$this->allowlocal)
			{
				//connect so that we can inspect the target IP address
				curl_setopt($this->ch, CURLOPT_CONNECT_ONLY, 1);
				$result = curl_exec($this->ch);

				//this violates the "utilites" rule of depending on things outside of the utility directory.
				//However we don't really want this in the PHAR file because this is something an end
				//user might want to edit, we can't hide it.  We need to figure out a proper policy for
				//that sort of dependancy (probably should pass the path into the constructor).
				//Howere the better solution is to remove this logic entirely. It's probably not needed
				//(best understanding is it's due to problems with SSL certs on really old cUrl installs)
				//But it's insufficiently unclear what the consequences are.
				$isHttps = ($urlinfo['scheme'] == 'https');
				if ($isHttps AND $result === false AND curl_errno($this->ch) == '60')
				{
					curl_setopt($this->ch, CURLOPT_CAINFO, DIR . '/includes/cacert.pem');
					$result = curl_exec($this->ch);
				}

				//in some cases "success" from curl_exec can be an empty string.  It probably doesn't apply since we
				//aren't using RETURNTRANSER, but let's be clear and do a strict check.  We can also get a
				//"server returned no data" error here.  I'm not sure *why* we get that error because we wouldn't
				//expect it with connect only, but it doesn't seem to affect anything aside from getting a false return.
				//so check for it and treat it as a valid return when it does.
				if ($result === false AND curl_errno($this->ch) != 52)
				{
					return false;
				}

				$targetAddress = curl_getinfo($this->ch, CURLINFO_PRIMARY_IP);
				if (!$this->ip->isPublic($targetAddress))
				{
					return false;
				}
			}
		}

		//actually process the request.
		curl_setopt($this->ch, CURLOPT_CONNECT_ONLY, 0);
		$result = curl_exec($this->ch);

		return $result;
	}

	/**
	 *	Rebuild the a url from the info components
	 *
	 *	This ensures that we know for certain that the url we validated
	 *	is the the one that we are fetching.  Due to bugs in parse_url
	 *	it's possible to slip something through the validation function
	 *	because it appears in the wrong component.  So we validate the
	 *	hostname that appears in the array but the actual url will be
	 *	interpreted differently by curl -- for example:
	 *
	 *	http://127.0.0.1:11211#@orange.tw/xxx
	 *
	 *	The host name is '127.0.0.1' and port is 11211 but parse_url will return
	 *	host orange.tw and no port value.
	 *
	 *	the expectation is that the values passed to this function passed validateUrl
	 *
	 *	@param $urlinfo -- The parsed url info from vB_Utility_String::parseUrl -- scheme, port, host
	 */
	private function rebuildUrl($urlinfo)
	{
		$url = '';

		$url .= $urlinfo['scheme'];
		$url .= '://';

		$url .= $urlinfo['host'];

		//note that we intentionally skip the port here.  We *only* want to use
		//the default port for the scheme ever.  There is no point is setting it
		//explicitly.  We also deliberately strip username/password data if passed.
		//That's far more likely to be an attempt to hack than it is a legitimate
		//url to fetch.
		if (!empty($urlinfo['path']))
		{
			$url .= $urlinfo['path'];
		}

		if (!empty($urlinfo['query']))
		{
			$url .= '?';
			$url .= $urlinfo['query'];
		}

		//not sure if this is needed since it shouldn't get passed to the
		//server.  But it's harmless and it feels like we should attempt
		//to preserve the original as much as is possible.
		if (!empty($urlinfo['fragement']))
		{
			$url .= '#';
			$url .= $urlinfo['fragement'];
		}

		return $url;
	}

	private function isSiteUrl($urlinfo)
	{
		//we haven't configured a site root, so we don't pass anything.
		if(!$this->allowedsiteroot)
		{
			return false;
		}

		$siteinfo = $this->string->parseUrl($this->allowedsiteroot);
		if ($urlinfo['host'] != $siteinfo['host'])
		{
			return false;
		}

		$normurlpath = $this->normalizepath($urlinfo['path']);
		$normsitepath = $this->normalizepath($siteinfo['path']);

		return ($normurlpath AND $normsitepath AND strpos($normurlpath, $normsitepath) === 0);
	}

	//realpath without an actual path
	private function normalizepath($path)
	{
		return $this->string->normalizepath($path, '/');
	}


	/**
	 *	Determine if the url is safe to load
	 *
	 *	@param $urlinfo -- The parsed url info from vB_String::parseUrl -- scheme, port, host
	 * 	@return boolean
	 */
	private function validateUrl($urlinfo)
	{
		// check scheme.  We only allow http as a protocol
		if (!isset($urlinfo['scheme']) OR !in_array(strtolower($urlinfo['scheme']), array('http', 'https')))
		{
			return false;
		}

		// only allow connections to the standard http ports unless we have a specific exception
		// if we don't have defined port then we're using the default by definition
		if (!empty($urlinfo['port']))
		{
			$allowedPorts = array_merge(array(80, 443), $this->allowedports);
			if (!in_array($urlinfo['port'], $allowedPorts))
			{
				return false;
			}
		}

		//check the hostname to avoid some nasty things.
		$host = $urlinfo['host'];

		$hostipcheck = $host;
		if ($hostipcheck[0] == '[' AND $hostipcheck[-1] == ']')
		{
			$hostipcheck = substr($hostipcheck, 1, -1);
		}


		//the hostname is given as an IP addres -- we don't want to allow this unless we have an override.
		//this isn't something normal people do.
		if ($this->ip->isValid($hostipcheck))
		{
			if ($this->allowip)
			{
				return $this->allowlocal OR $this->ip->isPublic($hostipcheck);
			}
			else
			{
				return false;
			}
		}

		//let's check localhost before we send it through the connection.  We know it's local
		if (!$this->allowlocal AND strcasecmp($host, 'localhost') == 0)
		{
			return false;
		}

		return true;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103236 $
|| #######################################################################
\*=========================================================================*/
