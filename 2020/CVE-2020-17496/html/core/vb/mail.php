<?php if (!defined('VB_ENTRY')) die('Access denied.');
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

/**
* Mail class.
* May use either the SMTP or Queue implementations to send the mail, depending on
* the options.
*
* @package 		vBulletin
* @version		$Revision: 102426 $
* @date 		$Date: 2010-05-29 02:50:59 +0800
*/
class vB_Mail
{
	use vB_Trait_NoSerialize;

	/**
	* Destination address
	*
	* @var	string
	*/
	protected $toemail = '';

	/**
	* Subject
	*
	* @var	string
	*/
	protected $subject = '';

	/**
	* Message
	*
	* @var	string
	*/
	protected $message = '';

	/**
	* All headers to be sent with the message
	*
	* @var	string
	*/
	protected $headers = '';

	/**
	* Sender email
	*
	* @var	string
	*/
	protected $fromemail = '';

	/**
	* Line delimiter
	*
	* @var	string
	*/
	protected $delimiter = "\r\n";
	//if you change the delimiter you need to change the regex.  Look for $vboptions['extra_smtp_headers']

	/**
	* Switch to enable/disable debugging. When enabled, warnings are not suppressed
	*
	* @var	boolean
	*/
	protected $debug = false;

	/**
	* Message to log if logging is enabled
	*
	* @var	string
	*/
	protected $log = '';

	/**
	 *	Used for unit tests. fetchLibrary() will return the test stub if this is set to true.
	 *
	 *	@var	boolean
	 */
	protected static $enableTestCapture = false;

	/**
	 * Array of phrase shortcode replacements
	 *
	 * @var array
	 */
	protected $shortcode_replace_map = array();

	/**
	 * Starts the process of sending an email - either immediately or by adding it to the mail queue.
	 *
	 * @param string $toemail Destination email address
	 * @param string $subject Email message subject
	 * @param string $message Email message body
	 * @param boolean $sendnow If true, do not use the mail queue and send immediately
	 * @param string $from Optional name/email to use in 'From' header
	 * @param string $uheaders Additional headers
	 * @param string $username Username of person sending the email
	 * @param bool $skipFloodCheck If true, the flood check will be skipped
	 * @param string $contentType Content type for email.
	 * @return bool
	 */
	public static function vbmail($toemail, $subject, $message, $sendnow = false, $from = '', $uheaders = '', $username = '', $skipFloodCheck = false, $contentType = 'text/plain')
	{
		if (empty($toemail))
		{
			return false;
		}

		if (!($mail = self::fetchLibrary(!$sendnow AND vB::getDatastore()->getOption('usemailqueue'))))
		{
			return false;
		}

		if (!$mail->start($toemail, $subject, $message, $from, $uheaders, $username, $contentType))
		{
			return false;
		}

		$floodReturn['valid'] = true;
		if(!empty($from) AND !$skipFloodCheck)
		{
			$floodReturn = self::emailFloodCheck();
		}

		if ($floodReturn['valid'])
		{
			return $mail->send();
		}
		else
		{
			return $floodReturn['error'];
		}
	}

	/**
	* Begin adding email to the mail queue
	*/
	public static function vbmailStart()
	{
		$mail = vB_Mail_Queue::fetchInstance();
		$mail->setBulk(true);
	}

	/**
	* Stop adding mail to the mail queue and insert the mailqueue data for sending later
	*/
	public static function vbmailEnd()
	{
		$mail = vB_Mail_Queue::fetchInstance();
		$mail->setBulk(false);
	}

	/**
	* Reads the email message queue and delivers a number of pending emails to the message sender
	*/
	public static function execMailQueue()
	{
		$vboptions = vB::getDatastore()->getValue('options');
		$mailqueue = vB::getDatastore()->getValue('mailqueue');

		if ($mailqueue !== null AND $mailqueue > 0 AND $vboptions['usemailqueue'])
		{
			// mailqueue template holds number of emails awaiting sending

			$mail = vB_Mail_Queue::fetchInstance();
			$mail->execQueue();
		}
	}

	/**
	 * Constructor
	 */
	protected function __construct()
	{
		$sendmail_path = @ini_get('sendmail_path');
		if (!$sendmail_path OR vB::getDatastore()->getOption('use_smtp') OR defined('FORCE_MAIL_CRLF'))
		{
			// no sendmail, so we're using SMTP or a server that lines CRLF to send mail // the use_smtp part is for the MailQueue extension
			$this->delimiter = "\r\n";
		}
		else
		{
			$this->delimiter = "\n";
		}
	}

	/**
	 * Factory method for mail.
	 *
	 * @param	bool	$deferred	Whether mail sending can be deferred
	 *
	 * @return	vB_Mail
	 */
	public static function fetchLibrary($deferred = false)
	{
		if (self::$enableTestCapture AND class_exists('vB_Mail_Test'))
		{
			return new vB_Mail_Test($deferred);
		}

		if ($deferred)
		{
			return vB_Mail_Queue::fetchInstance();
		}

		if (vB::getDatastore()->getOption('use_smtp'))
		{
			return new vB_Mail_Smtp();
		}

		return new vB_Mail();
	}

	/**
	 * Starts the process of sending an email - preps it so it's fully ready to send.
	 * Call send() to actually send it.
	 *
	 * @param string $toemail Destination email address
	 * @param string $subject Email message subject
	 * @param string $message Email message body
	 * @param string $from Optional name/email to use in 'From' header
	 * @param string $uheaders Additional headers
	 * @param string $username Username of person sending the email
	 * @param string $contentType Encoding for mail.
	 * @return bool True on success, false on failure
	 */
	public function start($toemail, $subject, $message, $from = '', $uheaders = '', $username = '', $contentType = 'text/plain')
	{
		$toemail = $this->fetchFirstLine($toemail);

		if (empty($toemail))
		{
			return false;
		}

		$delimiter =& $this->delimiter;
		$vboptions = vB::getDatastore()->getValue('options');

		$toemail = vB_String::unHtmlSpecialChars($toemail);
		$subject = $this->fetchFirstLine($subject);
		$message = preg_replace("#(\r\n|\r|\n)#s", $delimiter, trim($message));

		$charset = vB_String::getCharset();
		if ((strtolower($charset) == 'iso-8859-1' OR $charset == '') AND preg_match('/&[a-z0-9#]+;/i', $message))
		{
			$message = utf8_encode($message);
			$subject = utf8_encode($subject);
			$username = utf8_encode($username);

			$encoding = 'UTF-8';
			$unicode_decode = true;
		}
		else if ($vboptions['utf8encode'])
		{
			$message = to_utf8($message, $charset);
			$subject = to_utf8($subject, $charset);
			$username = to_utf8($username, $charset);

			$encoding = 'UTF-8';
			$unicode_decode = true;
		}
		else
		{
			// we know nothing about the message's encoding in relation to UTF-8,
			// so we can't modify the message at all; just set the encoding
			$encoding = $charset;
			$unicode_decode = false;
		}

		$message = vB_String::unHtmlSpecialChars($message, $unicode_decode);
		$subject = $this->encodeEmailHeader(vB_String::unHtmlSpecialChars($subject, $unicode_decode), $encoding, false, false);

		$from = $this->fetchFirstLine($from);
		if (empty($from))
		{
			$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('x_mailer'));
			if (isset($vbphrase['x_mailer']))
			{
				$mailfromname = sprintf($this->fetchFirstLine($vbphrase['x_mailer']), $vboptions['bbtitle']);
			}
			else
			{
				$mailfromname = $vboptions['bbtitle'];
			}

			if ($unicode_decode == true)
			{
				$mailfromname = utf8_encode($mailfromname);
			}
			$mailfromname = $this->encodeEmailHeader(vB_String::unHtmlSpecialChars($mailfromname, $unicode_decode), $encoding);

			$headers = "From: $mailfromname <" . $vboptions['webmasteremail'] . '>' . $delimiter;
			$headers .= 'Auto-Submitted: auto-generated' . $delimiter;

			// Exchange (Oh Microsoft) doesn't respect auto-generated: http://www.vbulletin.com/forum/project.php?issueid=27687
			if ($vboptions['usebulkheader'])
			{
				$headers .= 'Precedence: bulk' . $delimiter;
			}
		}
		else
		{
			if ($username)
			{
				$mailfromname = $username . " - " . $vboptions['bbtitle'];
			}
			else
			{
				$mailfromname = $from;
			}

			if ($unicode_decode == true)
			{
				$mailfromname = utf8_encode($mailfromname);
			}
			$mailfromname = $this->encodeEmailHeader(vB_String::unHtmlSpecialChars($mailfromname, $unicode_decode), $encoding);

			$headers = "From: $mailfromname <$from>" . $delimiter;
			$headers .= "Sender: " . $vboptions['webmasteremail'] . $delimiter;
		}

		$fromemail = empty($vboptions['bounceemail']) ? $vboptions['webmasteremail'] : $vboptions['bounceemail'];
		$headers .= 'Return-Path: ' . $fromemail . $delimiter;

		$http_host = vB::getRequest()->getVbHttpHost();
		if (!$http_host)
		{
			$http_host = substr(md5($message), 12, 18) . '.vb_unknown.unknown';
		}

		$msgid = '<' . gmdate('YmdHis') . '.' . substr(md5($message . microtime()), 0, 12) . '@' . $http_host . '>';
		$headers .= 'Message-ID: ' . $msgid . $delimiter;

		$headers .= preg_replace("#(\r\n|\r|\n)#s", $delimiter, $uheaders);
		unset($uheaders);

		$headers .= 'MIME-Version: 1.0' . $delimiter;
		$headers .= 'Content-Type: ' . $contentType . ($encoding ? "; charset=\"$encoding\"" : '') . $delimiter;
		$headers .= 'Content-Transfer-Encoding: 8bit' . $delimiter;

		if (!empty($vboptions['extra_smtp_headers']))
		{
			$headers .= preg_replace("#\r[^\n]|[^r]\n#", $delimiter, $vboptions['extra_smtp_headers']) . $delimiter;
		}

		$this->toemail = $toemail;
		$this->subject = $subject;
		$this->message = $message;
		$this->headers = $headers;
		$this->fromemail = $fromemail;

		return true;
	}

	/**
	* Set all the necessary variables for sending a message.
	*
	* @param string	$toemail Destination address
	* @param string	$subject Subject
	* @param string	$message Message
	* @param string	$headers All headers to be sent with the message
	* @param string	$fromemail Sender email
	*/
	public function quickSet($toemail, $subject, $message, $headers, $fromemail)
	{
		$this->toemail = $toemail;
		$this->subject = $subject;
		$this->message = $message;
		$this->headers = $headers;
		$this->fromemail = $fromemail;
	}

	/**
	 * Send the mail.
	 * Note: If you define DISABLE_MAIL in config.php as:
	 *	 delimited email addresses	- Only mail for the recipients will be sent
	 *	<filename>.log				- Mail will be logged to the given file if writable
	 *  any other value				- Mail will be disabled
	 *
	 * @param bool $force_send If true, DISABLE_MAIL will be ignored.
	 *
	 * @return boolean True on success, false on failure
	 */
	public function send($force_send = false)
	{
		// No recipient, abort
		if (!$this->toemail)
		{
			return false;
		}

		// Phrase shortcodes
		$this->doShortcodeReplacements();

		// Check debug settings
		if (!$force_send AND defined('DISABLE_MAIL'))
		{
			if (is_string(DISABLE_MAIL))
			{
				// check for a recipient whitelist
				if (strpos(DISABLE_MAIL, '@') !== false)
				{
					// check if the address is allowed
					if (strpos(DISABLE_MAIL, $this->toemail) === false)
					{
						return false;
					}
				}
				else if (strpos(DISABLE_MAIL, '.log') !== false)
				{
					// mail is only logged
					$this->logEmail('DEBUG', DISABLE_MAIL);

					return true;
				}
				else
				{
					// recipient not in the whitelist and not logging
					return false;
				}
			}
			else
			{
				// DISABLE_MAIL defined but isn't a string so just disable
				return false;
			}
		}

		// Send the mail
		if($this->execSend() AND (!defined('VB_AREA') OR (defined('VB_AREA') AND VB_AREA != 'Install' AND VB_AREA != 'Upgrade')))
		{
			vB_Library::instance('user')->updateEmailFloodTime();
		}
		else
		{
			return false;
		}

		return true;

	}

	/**
	* Actually send the message.
	*
	* @return boolean True on success, false on failure
	*/
	protected function execSend()
	{
		if (!$this->toemail)
		{
			return false;
		}

		@ini_set('sendmail_from', $this->fromemail);

		if ($delay = intval(vB::getDatastore()->getOption('mail_delay')))
		{
			@sleep($delay);
		}

		if (vB::getDatastore()->getOption('needfromemail'))
		{
			$result = @mail($this->toemail, $this->subject, $this->message, trim($this->headers), '-f ' . $this->fromemail);
		}
		else
		{
			$result = @mail($this->toemail, $this->subject, $this->message, trim($this->headers));
		}

		$this->logEmail($result);

		return $result;
	}

	/**
	 * Does the phrase shortcode replacements for emails.
	 */
	protected function doShortcodeReplacements()
	{
		$options = vB::getDatastore()->getValue('options');

		// Phrase {shortcode} replacements
		// This replacement happens in several places. Please keep them synchronized.
		// You can search for {shortcode} in php and js files.
		// For email, the replacements happen here in send() since all email gets
		// routed through this function, and doing this elsewhere, such as in
		// fetchEmailPhrases() is problematic, since we don't always call fetchEmailPhrases
		// and we don't know who the recipient is in that function.
		if (empty($this->shortcode_replace_map))
		{
			$this->shortcode_replace_map = array (
				'{sitename}'        => $options['bbtitle'],
				'{musername}'       => '{musername}',
				'{username}'        => '{username}',
				'{userid}'          => '{userid}',
				'{registerurl}'     => vB5_Route::buildUrl('register|fullurl'),
				'{activationurl}'   => vB5_Route::buildUrl('activateuser|fullurl'),
				'{helpurl}'         => vB5_Route::buildUrl('help|fullurl'),
				'{contacturl}'      => vB5_Route::buildUrl('contact-us|fullurl'),
				'{homeurl}'         => $options['frontendurl'],
				'{date}'            => vbdate($options['dateformat']),
				// ** leave deprecated codes in to avoid breaking existing data **
				// deprecated - the previous *_page codes have been replaced with the *url codes
				'{register_page}'   => vB5_Route::buildUrl('register|fullurl'),
				'{activation_page}' => vB5_Route::buildUrl('activateuser|fullurl'),
				'{help_page}'       => vB5_Route::buildUrl('help|fullurl'),
				// deprecated - session url codes are no longer needed
				'{sessionurl}'      => '',
				'{sessionurl_q}'    => '',
			);
		}

		// update user-specific information for each recipient
		$user_replacements = vB_Library::instance('user')->getEmailReplacementValues($this->toemail);
		$this->shortcode_replace_map['{musername}'] = $user_replacements['{musername}'];
		$this->shortcode_replace_map['{username}'] = $user_replacements['{username}'];
		$this->shortcode_replace_map['{userid}'] = $user_replacements['{userid}'];

		// do the replacement
		$shortcode_find = array_keys($this->shortcode_replace_map);
		$this->subject = str_replace($shortcode_find, $this->shortcode_replace_map, $this->subject);
		$this->message = str_replace($shortcode_find, $this->shortcode_replace_map, $this->message);
	}

	/**
	* Returns the first line of a string -- good to prevent errors when sending emails (above)
	*
	* @param string $text String to be trimmed
	*
	* @return string
	*/
	protected function fetchFirstLine($text)
	{
		$text = preg_replace("/(\r\n|\r|\n)/s", "\r\n", trim($text));
		$pos = strpos($text, "\r\n");
		if ($pos !== false)
		{
			return substr($text, 0, $pos);
		}

		return $text;
	}

	/**
	* Encodes a mail header to be RFC 2047 compliant. This allows for support
	* of non-ASCII character sets via the quoted-printable encoding.
	*
	* @param string $text The text to encode
	* @param string $charset The character set of the text
	* @param bool $force_encode Whether to force encoding into quoted-printable even if not necessary
	* @param bool $quoted_string Whether to quote the string; applies only if encoding is not done
	*
	* @return	string	The encoded header
	*/
	protected function encodeEmailHeader($text, $charset = 'utf-8', $force_encode = false, $quoted_string = true)
	{
		$text = trim($text);

		if (!$charset)
		{
			// don't know how to encode, so we can't
			return $text;
		}

		if ($force_encode == true)
		{
			$qp_encode = true;
		}
		else
		{
			$qp_encode = false;

			for ($i = 0; $i < strlen($text); $i++)
			{
				if (ord($text[$i]) > 127)
				{
					// we have a non ascii character
					$qp_encode = true;
					break;
				}
			}
		}

		if ($qp_encode == true)
		{
			// see rfc 2047; not including _ as allowed here, as I'm encoding spaces with it
			$outtext = preg_replace_callback('#([^a-zA-Z0-9!*+\-/ ])#',
				function($matches)
				{
					return '=' . strtoupper(dechex(ord($matches[1])));
				}, $text
			);
			$outtext = str_replace(' ', '_', $outtext);
			$outtext = "=?$charset?q?$outtext?=";

			return $outtext;
		}
		else
		{
			if ($quoted_string)
			{
				$text = str_replace(array('"', '(', ')'), array('\"', '\(', '\)'), $text);

				return "\"$text\"";
			}
			else
			{
				return preg_replace('#(\r\n|\n|\r)+#', ' ', $text);
			}
		}
	}

	/**
	* Sets the debug member
	*
	* @param $debug boolean
	*/
	public function setDebug($debug)
	{
		$this->debug = $debug;
	}

	/**
	 * Logs email to file
	 *
	 * @param bool $status
	 * @param bool $errfile
	 *
	 * @return
	 */
	protected function logEmail($status = true, $errfile = false)
	{
		if ((defined('DEMO_MODE') AND DEMO_MODE == true))
		{
			return;
		}

		$vboptions = vB::getDatastore()->getValue('options');

		// log file is passed or taken from options
		$errfile = $errfile ? $errfile : $vboptions['errorlogemail'];

		// no log file specified
		if (!$errfile)
		{
			return;
		}

		// trim .log from logfile
		$errfile = (substr($errfile, -4) == '.log') ? substr($errfile, 0, -4) : $errfile;

		if ($vboptions['errorlogmaxsize'] != 0 AND $filesize = @filesize("$errfile.log") AND $filesize >= $vboptions['errorlogmaxsize'])
		{
			@copy("$errfile.log", $errfile . vB::getRequest()->getTimeNow() . '.log');
			@unlink("$errfile.log");
		}

		$timenow = date('r', vB::getRequest()->getTimeNow());

		$fp = @fopen("$errfile.log", 'a+b');

		if ($fp)
		{
			if ($status === true)
			{
				$output = "SUCCESS\r\n";
			}
			else
			{
				$output = "FAILED";
				if ($status !== false)
				{
					$output .= ": $status";
				}
				$output .= "\r\n";
			}
			if ($this->delimiter == "\n")
			{
				$append = "$timenow\r\nTo: " . $this->toemail . "\r\nSubject: " . $this->subject . "\r\n" . $this->headers . "\r\n\r\n" . $this->message . "\r\n=====================================================\r\n\r\n";
				@fwrite($fp, $output . $append);
			}
			else
			{
				$append = preg_replace("#(\r\n|\r|\n)#s", "\r\n", "$timenow\r\nTo: " . $this->toemail . "\r\nSubject: " . $this->subject . "\r\n" . $this->headers . "\r\n\r\n" . $this->message . "\r\n=====================================================\r\n\r\n");

				@fwrite($fp, $output . $append);
			}
			fclose($fp);
		}
	}

	public static function emailFloodCheck()
	{
		$session = vB::getCurrentSession();

		if (empty($session))
		{
			return array('valid' => true, 'error' => array());
		}
		$usercontext = $session->fetch_userinfo();
		if (empty($usercontext['userid']))
		{
			$usercontext['emailstamp'] = vB::getCurrentSession()->get('emailstamp');
		}
		$timenow =  vB::getRequest()->getTimeNow();
		$timepassed = $timenow - $usercontext['emailstamp'];
		$vboptions = vB::getDatastore()->getValue('options');

		if($vboptions['emailfloodtime'] > 0 AND $timepassed < $vboptions['emailfloodtime'] AND empty($usercontext['is_admin']))
		{
			return array('valid' => false, 'error' => array("emailfloodcheck", array($vboptions['emailfloodtime'],($vboptions['emailfloodtime'] - $timepassed))));
		}

		return array('valid' => true, 'error' => array());
	}

	public static function setTestMode($enable = false)
	{
		self::$enableTestCapture = $enable;
	}

	public static function getTestMode()
	{
		return self::$enableTestCapture;
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 102426 $
|| #######################################################################
\*=========================================================================*/
