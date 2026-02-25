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

class vB5_Template_Cache
{
	const PLACEHOLDER_PREFIX = '<!-- ##template_';
	const PLACEHOLDER_SUFIX = '## -->';

	protected static $instance;
	protected $cache = array();
	protected $renderTemplatesInReverseOrder = false;

	protected $preloadHashKey = '';
	protected $preloadTemplates = array();
	protected $textOnlyReplace = array();

	/**
	 *
	 * @var array Stores the template info for direct descendants of the parent template.
	 */
	protected $pending = array();

	public static function instance()
	{
		if (!isset(self::$instance))
		{
			$c = __CLASS__;

			if (vB5_Template_Options::instance()->get('options.cache_templates_as_files'))
			{
				$c .= '_Filesystem';
			}
			self::$instance = new $c;
		}

		return self::$instance;
	}

	public function isTemplateText()
	{
		return true;
	}

	/**
	 * Stores template info for deferred fetching & rendering, and returns a placeholder
	 * @param string $templateName
	 * @param array $args
	 * @return string
	 */
	public function register($templateName, $args)
	{
		$pos = isset($this->pending[$templateName]) ? count($this->pending[$templateName]) : 0;
		$placeholder = $this->getPlaceholder($templateName, $pos);

		$this->pending[$templateName][$placeholder] = $args;

		return $placeholder;
	}

	/**
	 * Register variables in template
	 * @param vB5_Template $templater
	 * @param array $templateArgs
	 */
	protected function registerTemplateVariables($templater, $templateArgs)
	{
		// this is for allowing indexed access to variables
		$templater->register('arg', array_values($templateArgs));

		// also registered named variables
		foreach ($templateArgs as $key=>$value)
		{
			if (is_string($key))
			{
				$templater->register($key, $value);
			}
		}
	}

	/**
	 * Instructs the class to render the templates in reverse order or not
	 *
	 * @param	bool
	 */
	public function setRenderTemplatesInReverseOrder($value)
	{
		$this->renderTemplatesInReverseOrder = (bool) $value;
	}

	/**
	 * Replaces all template placeholders in $content with the rendered templates
	 * @param string $content
	 */
	public function replacePlaceholders(&$content)
	{
		// This function procceses subtemplates by level

		$missing = array_diff(array_keys($this->pending), array_keys($this->cache));
		if (!empty($missing))
		{
			$this->fetchTemplate($missing);
		}

		// move pending templates to a new variable, so they are not re-processed by subtemplates
		$levelPending = & $this->pending;
		unset($this->pending);
		$this->pending = array();

		// This line is important. In BBCode parser, the templates of inner BBCode are registered firstly
		// So they should be replaced later than the outer BBCode templates. See VBV-4834.
		if ($this->renderTemplatesInReverseOrder)
		{
			$levelPending = array_reverse($levelPending);
		}

		foreach ($levelPending as $templateName => $templates)
		{
			foreach ($templates as $placeholder => $templateArgs)
			{
				$templater = new vB5_Template($templateName);
				$this->registerTemplateVariables($templater, $templateArgs);

				try
				{
					$replace = $templater->render(false);
				}
				catch (vB5_Exception_Api $e)
				{
					$e->prependTemplate($templateName);

					if (isset($templateArgs['isWidget']) AND $templateArgs['isWidget'])
					{
						$errorTemplate = new vB5_Template(vB5_Template::WIDGET_ERROR_TEMPLATE);

						// we want to make the registered variables available to error template
						$this->registerTemplateVariables($errorTemplate, $templateArgs);

						$errorlist = $e->getErrors();
						//shouldn't happen but let's make sure we have an error message
						if(!$errorlist)
						{
							$errorlist = array('widget_error');
						}

						$errorTemplate->register('errorlist', $errorlist);
						if(vB5_Config::instance()->debug)
						{
							$errorTemplate->register('template', $e->getTemplate());
							$errorTemplate->register('controller', $e->getController());
							$errorTemplate->register('method', $e->getMethod());
							$errorTemplate->register('arguments', print_r($e->getArguments(), true));
						}

						$replace = $errorTemplate->render(false);
					}
					else
					{
						throw $e;
					}
				}

				$content = str_replace($placeholder, $replace, $content);
				unset($templater);
			}
		}
	}

	public function getTemplate($templateId)
	{

		if (is_array($templateId))
		{
			return $this->fetchTemplate($templateId);
		}

		if (!isset($this->cache[$templateId]))
		{
			$this->fetchTemplate($templateId);
		}

		if (isset($this->cache[$templateId]))
		{
			return $this->cache[$templateId];
		}

		throw new Exception('Non-existent template requested: ' . htmlspecialchars($templateId));
	}

	protected function getPlaceholder($templateName, $pos)
	{
		return self::PLACEHOLDER_PREFIX . $templateName . '_' . $pos . self::PLACEHOLDER_SUFIX;
	}

	/**
	 * Receives either a template name or an array of template names to be fetched from the API
	 * @param mixed $templateName
	 */
	protected function fetchTemplate($templateName)
	{
		if (is_array($templateName))
		{
			$method = 'fetchBulk';
			$arguments = array('template_names' => $templateName);
		}
		else
		{
			$method = 'fetch';
			$arguments = array('name' => $templateName);
		}

		if ($styleId = vB5_Template_Stylevar::instance()->getPreferredStyleId())
		{
			$arguments['styleid'] = $styleId;
		}
		$response = Api_InterfaceAbstract::instance()->callApi('template', $method, $arguments);
		// this api call may return a bunch of subtemplates as well

		if (is_array($response) AND isset($response['textonly']))
		{
			$placeholder =  $this->getPlaceholder($templateName, '_to');
			$this->cache[$templateName] = "\$final_rendered = \"" . $placeholder . "\";";
			$this->textOnlyReplace[$placeholder] = $response['template'];
		}
		else if (is_array($response))
		{
			foreach ($response AS $id => $code)
			{
				if (is_array($code) AND isset($code['textonly']))
				{
					//We use a placeholder;
					$placeholder =  $this->getPlaceholder($id, '_to');
					$this->cache[$id] = "\$final_rendered = \"" . $placeholder . "\";";
					$this->textOnlyReplace[$placeholder] = $code['template'];
				}
				else
				{
					// in this layer we need to use vB5_Template_Runtime instead of vB_Template_Runtime
					$code = str_replace('vB_Template_Runtime', 'vB5_Template_Runtime', $code);
					$this->cache[$id] = $code;
				}
			}
		}
		else
		{
			//This probably doesn't do what you think it does.  The response is always going to be an
			//array of some kind unless its a value like false (which is shouldn't be)
			// in this layer we need to use vB5_Template_Runtime instead of vB_Template_Runtime
			$response = str_replace('vB_Template_Runtime', 'vB5_Template_Runtime', $response);
			$this->cache[$templateName] = $response;
		}
	}

	public function replaceTextOnly(&$finalRendered)
	{
		foreach($this->textOnlyReplace AS $placeholder => $template)
		{
			$finalRendered = str_replace($placeholder, $template, $finalRendered);
		}
	}

}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
