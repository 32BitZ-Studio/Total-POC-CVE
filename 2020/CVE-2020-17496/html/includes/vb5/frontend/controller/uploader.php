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

class vB5_Frontend_Controller_Uploader extends vB5_Frontend_Controller
{
	protected $api;

	protected $upload_handler;

	public function __construct()
	{
		parent::__construct();
		$this->api = Api_InterfaceAbstract::instance();
	}

	public function actionGetUploader()
	{
		$config = vB5_Config::instance();

		$templater = new vB5_Template('attach_uploader');
		$this->outputPage($templater->render());
	}

	/**
	 * Fetches an image from a URL and adds it as an attachment.
	 *
	 * Used by: (not necessarily an exhaustive list)
	 * 	Content entry UI attachments panel, when uploading from a URL
	 * 	Content entry UI "image" button in toolbar, when fetching and saving as a local attachment
	 * 	Uploading a profile image / avatar, when uploading from a URL
	 * 	Uploading a signature pic, when uploading from a URL
	 * 	Uploading a group image, when uploading from a URL
	 * 	Uploading a site logo in sitebuilder, when uploading from a URL
	 */
	public function actionUrl()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (isset($_REQUEST['urlupload']))
		{
			$api = Api_InterfaceAbstract::instance();

			$response = $api->callApi('content_attach', 'uploadUrl',
				array(
					'url' => $_REQUEST['urlupload'],
					'attachment' => (!empty($_REQUEST['attachment']) ? $_REQUEST['attachment'] : ''),
					'uploadfrom' => (isset($_REQUEST['uploadFrom']) ? $_REQUEST['uploadFrom'] : ''),
				)
			);

			// when the api returns an error, there is no filedataid
			$response['filedataid'] = empty($response['filedataid']) ? 0 : $response['filedataid'];
			$response['filename'] = empty($response['filename'])? '' : $response['filename'];

			$response['imageUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'];
			$response['thumbUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'] . '&type=thumb';
			$response['deleteUrl'] = 'filedata/delete?filedataid=' . $response['filedataid'];

			$this->sendAsJson($response);
		}
	}

	/**
	 * Uploads an image and sets it as the logo in one step
	 */
	public function actionUploadLogoUrl()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (isset($_POST['urlupload']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('content_attach', 'uploadUrl', array('url' => $_POST['urlupload']));

			if (!empty($response['errors']))
			{
				$this->sendAsJson($response);
				return;
			}

			$response2 = $api->callApi('content_attach', 'setLogo', array('filedataid' => $response['filedataid']));
			if (!empty($response2['errors']))
			{
				$this->sendAsJson($response2);
				return;
			}

			$result['imageUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'];
			$result['thumbUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'] . '&thumb=1';
			$result['filedataid'] = $response['filedataid'];

			$this->sendAsJson($result);
		}
	}

	/**
	 * Uploads a file.
	 */
	public function actionUploadFile()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ($_FILES AND !empty($_FILES['file']))
		{
			$api = Api_InterfaceAbstract::instance();

			if (!empty($_REQUEST['uploadFrom']))
			{
				$_FILES['file']['uploadFrom'] = $_REQUEST['uploadFrom'];
			}

			if (!empty($_REQUEST['nodeid']))
			{
				$_FILES['file']['parentid'] = $_REQUEST['nodeid'];
			}

			$response = $api->callApi('content_attach', 'upload', array('file' => $_FILES['file']));

			if (!empty($response['errors']))
			{
				return $this->sendAsJson($response);
			}

			$response['imageUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'];
			$response['thumbUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'] . '&type=thumb';
			$response['mediumUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'] . '&type=medium';
			$response['deleteUrl'] = 'filedata/delete?filedataid=' . $response['filedataid'];

			$this->sendAsJson($response);
		}
	}

	/**
	 * Uploads a photo. Returns an edit block and the photo URL.
	 */
	public function actionUploadPhoto()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ($_FILES AND !empty($_FILES) )
		{
			if (!empty($_FILES['file']))
			{
				$fileData = $_FILES['file'];
			}
			else if (!empty($_FILES['files']))
			{
				if (is_array($_FILES['files']['name']))
				{
					$fileData = array('name' => $_FILES['files']['name'][0],
					'type' => $_FILES['files']['type'][0], 'tmp_name' => $_FILES['files']['tmp_name'][0],
					'size' => $_FILES['files']['size'][0], 'error' => $_FILES['files']['error'][0]);
				}
				else
				{
					$fileData = $_FILES['files'];
				}
			}

			if (isset($_POST['galleryid']))
			{
				$galleryid = intval($_POST['galleryid']);
			}
			else
			{
				$galleryid = '';
			}

			if (isset($_POST['uploadFrom']))
			{
				$fileData['uploadFrom'] = $_POST['uploadFrom'];
			}
			else
			{
				$fileData['uploadFrom'] = '';
			}

			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('content_attach', 'uploadPhoto', array('file' => $fileData));
			if (!empty($response['filedataid']))
			{
				$templater = new vB5_Template('photo_edit');
				$imgUrl = 'filedata/fetch?filedataid=' . $response['filedataid'] . "&type=thumb";
				$templater->register('imgUrl', $imgUrl);
				$templater->register('filedataid', $response['filedataid']);
				$response['edit'] = $templater->render();
				$response['imgUrl'] = $imgUrl;
				$response['galleryid'] = $galleryid;
			}
			//need this to avoid errors with iframe transport.
			header("Content-type: text/plain");
			$this->sendAsJson($response);
		}
	}

	/** This method uploads an image and sets it as the logo in one step **/
	public function actionUploadLogo()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if ($_FILES AND !empty($_FILES['file']))
		{
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('content_attach', 'upload', array('file' => $_FILES['file']));

			if (!empty($response['errors']))
			{
				$this->sendAsJson($response);
				return;
			}

			if (empty($response['filedataid']))
			{
				echo 'unknown error';
				return;
			}

			$response2 = $api->callApi('content_attach', 'setLogo', array('filedataid' => $response['filedataid']));
			if (!empty($response2['errors']))
			{
				$this->sendAsJson($response2);
				return;
			}

			$response['imageUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'];
			$response['thumbUrl'] = 'filedata/fetch?filedataid=' . $response['filedataid'] . '&type=thumb';
			$response['filedataid'] = $response['filedataid'];
			$this->sendAsJson($response);

		}
		else
		{
			echo "No files to upload";
		}
	}

	/** This method sets an uploaded image as the logo**/
	public function actionSetlogo()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (isset($_POST['filedataid']))
		{
			$styleselection = (isset($_POST['styleselection'])) ? trim($_POST['styleselection']) : 'current';
			$api = Api_InterfaceAbstract::instance();
			$response = $api->callApi('content_attach', 'setLogo', array('filedataid' => $_POST['filedataid'], 'styleselection' => $styleselection));
			$this->sendAsJson($response);
		}
	}

	// Used by ckeditor's Image dialog > Upload tab > Send it to server button. Look for filebrowserImageUploadUrl in ckeditor.js
	public function actionCKEditorInsertImage()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		$options = array(
			'param_name' => 'upload',
			'uploadFrom' => 'CKEditorInsertImage'
		);

		$this->upload_handler = new blueImpUploadHandler($options, $this->api);

		header('Pragma: no-cache');
		header('Cache-Control: private, no-cache');
		header('Content-Disposition: inline; filename="files.json"');

		$this->upload_handler->post();

	}

	/** This method uploads an image as filedata and returns an array of useful information including the filedataid and links to the image and the thumbnail **/
	public function actionUpload()
	{
		if (empty($this->upload_handler))
		{
			$this->upload_handler = new blueImpUploadHandler(null, $this->api);
		}

		header('Pragma: no-cache');
		header('Cache-Control: private, no-cache');
		header('Content-Disposition: inline; filename="files.json"');

		switch ($_SERVER['REQUEST_METHOD']) {
		case 'HEAD':
		case 'GET':
			$this->upload_handler->get();
			break;
		case 'POST':
			$this->upload_handler->post();
			break;
		case 'DELETE':
			$this->upload_handler->delete();
			break;
		default:
			http_response_code(405);
		}
	}

	/**
	 * This sets a social group/blog picture. Not currently used when changing icon from the *blog* admin settings page.
	 */
	public function actionUploadSGIcon()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		//Let's just let the API handle this.
		$api = Api_InterfaceAbstract::instance();
		if (!empty($_FILES['file']))
		{
			if (!empty($_REQUEST['uploadFrom']))
			{
				$_FILES['file']['uploadFrom'] = $_REQUEST['uploadFrom'];
			}
			else
			{
				$_FILES['file']['uploadFrom'] = 'sgicon';
			}

			if (!empty($_REQUEST['nodeid']))
			{
				$_FILES['file']['parentid'] = $_REQUEST['nodeid'];
			}

			$response = $api->callApi('content_attach', 'upload', array('file' => $_FILES['file']));
		}
		elseif(!empty($_REQUEST['url']))
		{
			$response = $api->callApi('content_attach', 'uploadUrl', array('url' => $_REQUEST['url']));
		}
		else
		{
			throw new Exception('error_attachment_missing');
		}

		if (!empty($response['errors']))
		{
			return $this->sendAsJson($response);
		}

		$filedataid = $response['filedataid'];

		// default = update the channel (which is the previous behavior, also used by blogs)
		if (!isset($_REQUEST['updatechannel']) OR !empty($_REQUEST['updatechannel']))
		{
			$response = $api->callApi('content_channel', 'update', array($_REQUEST['nodeid'], array('filedataid' => $response['filedataid'])));

			if (!empty($response['errors']))
			{
				return $this->sendAsJson($response);
			}
		}

		$response = array();
		$response['filedataid'] = $filedataid;
		$response['imageUrl'] = 'filedata/fetch?filedataid=' . $filedataid;
		$response['thumbUrl'] = 'filedata/fetch?filedataid=' . $filedataid . '&type=thumb';
		$response['mediumUrl'] = 'filedata/fetch?filedataid=' . $filedataid . '&type=medium';
		$response['deleteUrl'] = 'filedata/delete?filedataid=' . $filedataid;

		$this->sendAsJson($response);
	}

	/*
	 *	Replaces an existing attachment's settings with the new setting as provided
	 *	in the $_REQUEST data. Note, existing means it has a nodeid.
	 *
	 *	Used by ckeditor.js's vBulletin.ckeditor.modifyDialogs() and content_entry_box.js's vBulletin.contentEntryBox.handleAttachmentControl()
	 */
	public function actionSaveAttachmentSetting()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (empty($_REQUEST['attachmentid']) OR !intval($_REQUEST['attachmentid']))
		{
			$response = array('error' => 'Invalid Attachmentid');	// todo create phrase for this?
			$this->sendAsJson($response);
		}

		$data = array();
		$data['nodeid'] = intval($_REQUEST['attachmentid']);

		// filedataid, filename required per content_attach API's cleanInput(). Let's grab the
		// existing data.
		$fileInfo = $this->api->callApi('content_attach', 'fetchImage', array('id' => $data['nodeid']));

		if (!empty($fileInfo['errors']))
		{
			$this->sendAsJson($fileInfo);
			return;
		}
		else if (empty($fileInfo) OR empty($fileInfo['filedataid']) OR empty($fileInfo['filename']))
		{
			$response = array('error' =>  'Failed to fetch the necessary attachment information');
			$this->sendAsJson($response);
			return;
		}

		$data['filedataid'] = $fileInfo['filedataid'];
		$data['filename'] = $fileInfo['filename'];

		// We only use $availableSettings so we know which values to extract
		// from the $_POST variable. This is not here for cleaning,
		// which happens in the API. See the text and attach API cleanInput
		// methods.
		$settings = array();
		$availableSettings =  $this->api->callApi('content_attach', 'getAvailableSettings', array());
		$availableSettings = (isset($availableSettings['settings'])? $availableSettings['settings'] : array());
		foreach ($availableSettings AS $key)
		{
			if (isset($_REQUEST[$key]))
			{
				$settings[$key] = $_REQUEST[$key];
			}
		}
		$data['settings'] = $settings;

		// try to update
		$attachid =  $this->api->callApi('content_attach', 'update',
			array(
				'nodeid' => $data['nodeid'],
				'data' => $data
			)
		);

		if (!empty($attachid['errors']))
		{
			$this->sendAsJson($attachid);
			return;
		}

		$response = array('success' => true);
		$this->sendAsJson($response);
	}

	/*
	 *	Fetches the filedataid given idname & idvalue, typically set in the queryparams of
	 *	a filedata fetch URL (ex. /filedata/fetch?id=1234). Currently only handles the case
	 *	idname = 'id', which points to an attachment's nodeid.
	 *
	 *	Used by ckeditor.js's vBulletin.ckeditor.modifyDialogs()
	 */
	public function actionFetchFiledataid()
	{
		// require a POST request for this action
		$this->verifyPostRequest();

		if (empty($_REQUEST['idname']) OR empty($_REQUEST['id']) OR !intval($_REQUEST['id']))
		{
			$response = array('error' => 'Invalid Parameters');
			$this->sendAsJson($response);
			return;
		}

		$idname = $_REQUEST['idname'];
		$id = intval($_REQUEST['id']);

		$fileInfo = false;
		switch ($idname)
		{
			case 'id':
				$fileInfo = $this->api->callApi('content_attach', 'fetchImage', array('id' => $id));
				break;
			default:
				break;
		}

		if (!empty($fileInfo['errors']))
		{
			$this->sendAsJson($fileInfo);
			return;
		}

		if (isset($fileInfo['filedataid']))
		{
			$response = array('filedataid' => $fileInfo['filedataid']);
			$this->sendAsJson($response);
			return;
		}
		else
		{
			$response = array('error' => 'Failed to fetch filedataid');
			$this->sendAsJson($response);
			return;
		}
	}
}

// @TODO each class should be in a separate file
class blueImpUploadHandler
{
	protected $options;
	private $partials = array();
	private $fileData = array();
	protected $api;
	protected $baseurl;

	function __construct($options=null, $api)
	{
		$this->api = $api;
		$this->baseurl = vB5_Template_Options::instance()->get('options.frontendurl');
		$this->options = array(
		    'script_url' => $_SERVER['PHP_SELF'],
		    'param_name' => 'files',
		    // The php.ini settings upload_max_filesize and post_max_size
		    // take precedence over the following max_file_size setting:
		    'max_file_size' => 500000,
		    'min_file_size' => 1,
		    'accept_file_types' => '/.+$/i',
		    'max_number_of_files' => 5,
		    'discard_aborted_uploads' => true,
		    'image_versions' => array(
		        // Uncomment the following version to restrict the size of
		        // uploaded images. You can also add additional versions with
		        // their own upload directories:
		        /*
		           'large' => array(
		           'upload_dir' => dirname(__FILE__).'/files/',
		           'upload_url' => dirname($_SERVER['PHP_SELF']).'/files/',
		           'max_width' => 1920,
		           'max_height' => 1200
		           ),
		        */
		       /* 'thumbnail' => array(
		            'upload_dir' => dirname(__FILE__).'/thumbnails/',
		            'upload_url' => dirname($_SERVER['PHP_SELF']).'/thumbnails/',
		            'max_width' => 80,
		            'max_height' => 80
		        ) */
		        )
		);

		if ($options) {
			$this->options = array_merge($this->options, $options);
		}
	}

	private function get_file_object($file_name) {
		if (array_key_exists($file_name, $this->fileData)) {
			$file = new stdClass();
			$file->name = $file_name;
			$file->size = $this->fileData[$file_name]['filesize'];
			$file->filedataid = $this->fileData[$file_name]['filedataid'];
			$file->url = $this->fileData[$file_name]['url'];
			$file->delete_url = $this->fileData[$file_name]['delete_url'];
			$file->thumb_url = $this->fileData[$file_name]['thumb_url'];
			$file->delete_type = 'DELETE';
			return $file;
		}
		return null;
	}

	private function get_file_objects() {
		$files = array();
		foreach ($this->fileData as $filename => $fileInfo)
		{
			$file = new stdClass();
			$file->name = $filename;
			$file->size = $fileInfo['filesize'];
			$file->filedataid = $fileInfo['filedataid'];
			$file->url =$fileInfo['url'];
			$file->delete_url = $fileInfo['delete_url'];
			$file->thumb_url = $fileInfo['thumb_url'];
			$file->delete_type = 'DELETE';
			return $file;
	}


	}

	private function has_error($uploaded_file, $file, $error) {
		if ($error) {
			return $error;
		}

		if ($uploaded_file && is_uploaded_file($uploaded_file)) {
			$file_size = filesize($uploaded_file);
		} else {
			$file_size = $_SERVER['CONTENT_LENGTH'];
		}
		if ($this->options['max_file_size'] && (
			$file_size > $this->options['max_file_size'] ||
			$file->size > $this->options['max_file_size'])
		) {
			return 'maxFileSize';
		}
		if ($this->options['min_file_size'] &&
		$file_size < $this->options['min_file_size']) {
			return 'minFileSize';
		}
		if (is_int($this->options['max_number_of_files']) && (
			count($this->fileData) >= $this->options['max_number_of_files'])
		)
		{
			return 'maxNumberOfFiles';
		}
		return $error;
	}

	private function handle_file_upload($uploaded_file, $name, $size, $type, $error)
	{

		$file = new stdClass();
		$file->name = basename(stripslashes($name));
		$file->size = intval($size);
		$file->type = $type;
		if (!empty($_POST['uploadFrom']))
		{
			$file->uploadfrom = $_POST['uploadFrom'];
		}
		if (!empty($_POST['parentid']))
		{
			$file->parentid = $_POST['parentid'];
		}
		// need to pass in any upload errors to API
		if (!empty($error) AND is_numeric($error))
		{
			$file->error = intval($error);
		}

		// Validation is and should be done in the API
		//$error = $this->has_error($uploaded_file, $file, $error);

		if ($file->name)
		{
			if ($file->name[0] === '.')
			{
				$file->name = substr($file->name, 1);
			}

			$append_file = $file->size > filesize($uploaded_file);

			if ($uploaded_file && is_uploaded_file($uploaded_file))
			{
				// multipart/formdata uploads (POST method uploads)
				if ($append_file)
				{

					if (!array_key_exists($file->name, $this->partials))
					{
						$this->partials[$file->name] = '';
					}
					$this->partials[$file->name] .= file_get_contents($uploaded_file);
					$file_size = strlen($this->partials[$file->name] );

					if ($file_size >= $file->size)
					{
						$file->contents = $this->partials[$file->name] ;
						$file->size = $file_size;
						$fileInfo = $this->api->callApi('content_attach', 'upload', array($file));
					}

				}
				else

				{
					$file_size = filesize($uploaded_file);
					// todo: set tmp_name so we can check is_uploaded_file() in API???
					$file->contents = file_get_contents($uploaded_file);
					$fileInfo = $this->api->callApi('content_attach', 'upload', array($file));
				}
			}
			else
			{
				// Non-multipart uploads (PUT method support)
				$file->tmp_name = $uploaded_file;
				$file_size = filesize($uploaded_file);
				$fileInfo = $this->api->callApi('content_attach', 'upload', array($file));

			}
			if (!empty($fileInfo['errors']))
			{
				// return all errors. Image upload might have multiple error messages regarding resize failures.
				$file->error = $fileInfo['errors'];
			}
			else
			{
				if ($file_size === $file->size)
				{
					$file->url = 'filedata/fetch?filedataid=' . $fileInfo['filedataid'] ;
					$file->thumbnail_url = 'filedata/fetch?filedataid=' . $fileInfo['filedataid'] . '&type=thumb' ;
				}

				if (isset($fileInfo))
				{
					$this->fileData[$name] = $fileInfo;
					$this->fileData[$name]['url'] = 'filedata/fetch?filedataid=' . $fileInfo['filedataid'] ;
					$this->fileData[$name]['thumbnail_url'] = 'filedata/fetch?filedataid=' . $fileInfo['filedataid'] . '&type=thumb' ;
					$this->fileData[$name]['delete_url'] ='filedata/delete?filedataid=' . $fileInfo['filedataid'] ;
					$file->filedataid = $fileInfo['filedataid'] ;
				}

				$file->size = $file_size;
				$file->delete_url =  $this->baseurl . '/filedata/delete?filedataid=' . $fileInfo['filedataid'] ;
				$file->delete_type = 'DELETE';
			}
		}
		else
		{
			$file->error = $error;
		}
		return $file;
	}

	public function get()
	{

		if (empty($_FILES) AND empty($_REQUEST['file']))
		{
			$controller = new vB5_Frontend_Controller();
			$controller->sendAsJson(array());
			return ;
		}

		$file_name = isset($_REQUEST['file']) ? basename(stripslashes($_REQUEST['file'])) : null;
		if ($file_name)
		{
			$info = $this->get_file_object($file_name);
		}
		else
		{
			$info = $this->get_file_objects();
		}

		$controller = new vB5_Frontend_Controller();
		$controller->sendAsJson($info);
	}

	public function post()
	{
		if (isset($_FILES[$this->options['param_name']]))
		{
			$upload = $_FILES[$this->options['param_name']];
		}
		else
		{
			$upload =  array(
				'tmp_name' => null,
				'name' => null,
				'size' => null,
				'type' => null,
				'error' => 'no_file_to_upload',
			);
		}

		$info = array();
		if (is_array($upload['tmp_name']))
		{
			foreach ($upload['tmp_name'] AS $index => $value)
			{
				$info[] = $this->handle_file_upload(
					$upload['tmp_name'][$index],
					isset($_SERVER['HTTP_X_FILE_NAME']) ?
						$_SERVER['HTTP_X_FILE_NAME'] : $upload['name'][$index],
					isset($_SERVER['HTTP_X_FILE_SIZE']) ?
						$_SERVER['HTTP_X_FILE_SIZE'] : $upload['size'][$index],
					isset($_SERVER['HTTP_X_FILE_TYPE']) ?
						$_SERVER['HTTP_X_FILE_TYPE'] : $upload['type'][$index],
					$upload['error'][$index]
				);
			}
		}
		else
		{
			$info[] = $this->handle_file_upload(
				$upload['tmp_name'],
				isset($_SERVER['HTTP_X_FILE_NAME']) ?
					$_SERVER['HTTP_X_FILE_NAME'] : $upload['name'],
				isset($_SERVER['HTTP_X_FILE_SIZE']) ?
					$_SERVER['HTTP_X_FILE_SIZE'] : $upload['size'],
				isset($_SERVER['HTTP_X_FILE_TYPE']) ?
					$_SERVER['HTTP_X_FILE_TYPE'] : $upload['type'],
				$upload['error']
			);
		}

		foreach ($info AS $file)
		{
			unset($file->contents);
		}

		header('Vary: Accept');

		if (isset($this->options['uploadFrom']) AND $this->options['uploadFrom'] == 'CKEditorInsertImage')
		{
			header('Content-type: text/html');

			$funcNum = $_GET['CKEditorFuncNum'];
			$editorId = $_GET['CKEditor'];

			$api = Api_InterfaceAbstract::instance();

			if (!empty($info))
			{
				$url = isset($info[0]->url) ? $info[0]->url : '';
				$error = isset($info[0]->error) ? $info[0]->error : '';
			}
			else
			{
				$url = '';
				$error = 'error_uploading_image';
			}

			if (is_array($error))
			{
				if (!is_array($error[0]))
				{
					$error = array($error);
				}

				$phrases = $api->callApi('phrase', 'renderPhrases', array($error));
				$error = implode("\n", $phrases['phrases']);
			}
			else if (!empty($error))
			{
				$phrases = $api->callApi('phrase', 'renderPhrases', array(array($error)));
				$error = $phrases['phrases'][0];
			}

			//encode to ensure we don't encounter js syntax error
			$errorEncode = json_encode($error);

			echo "<script type=\"text/javascript\">window.parent.CKEDITOR.tools.callFunction($funcNum, '$url', $errorEncode);";

			$havefile = false;
			foreach ($info AS $file)
			{
				if (!empty($file->filedataid))
				{
					// vBulletin.ckeditor.insertImageAttachment() is now called downstream of vBulletin.ckeditor.closeFileDialog()
					//echo "window.parent.vBulletin.ckeditor.insertImageAttachment('$editorId', {$file->filedataid}, '{$file->name}');";
					$havefile = true;
					break;
				}
			}

			if ($havefile AND empty($error))
			{
				// the image inserts (<img> element in the editor body & hidden inputs in the form) are handled as
				// part of closeFileDialog() (normally would be handled by the onOk handler of the dialog)
				echo "window.parent.vBulletin.ckeditor.closeFileDialog('$editorId', " . json_encode($info) . ");";
			}

			echo "</script>";
			exit;
		}

		if (isset($_SERVER['HTTP_ACCEPT']) && (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false))
		{
			header('Content-type: application/json');
		}
		else
		{
			header('Content-type: text/plain');
		}

		$controller = new vB5_Frontend_Controller();
		$controller->sendAsJson($info);
	}

	public function delete()
	{
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 103065 $
|| #######################################################################
\*=========================================================================*/
