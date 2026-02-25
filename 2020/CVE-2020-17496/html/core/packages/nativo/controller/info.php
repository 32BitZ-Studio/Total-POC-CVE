<?php

class Nativo_Controller_Info extends vB5_Frontend_Controller
{
	public function actionMeta()
	{
		header('Content-type: application/xml');
 		$api = Api_InterfaceAbstract::instance();
		$info = $api->callApi('nativo:nativo', 'meta', array());


		$xml = new XMLWriter();
		$xml->openMemory();
		$xml->startDocument();
		$xml->startElement('postrelease');

		if(!isset($info['errors']))
		{
			foreach($info AS $name => $value)
			{
				$xml->writeElement($name, $value);
			}
			$xml->writeElement('styleid', vB5_Template_Stylevar::instance()->getPreferredStyleId());
			$xml->writeElement('mobilestyleid_advanced', '');
			$xml->writeElement('mobilestyleid_basic', '');
			$xml->writeElement('vbseo', 0);
			$xml->writeElement('vbseoversion', '');
			$xml->writeElement('healthcheck', 1);
		}
		else
		{
			$phraseController = vB5_Template_Phrase::instance();
			foreach($channels['errors'] AS $error)
			{
				$phraseController->register($error[0]);
			}

			$xml->startElement('errors');
			foreach($channels['errors'] AS $error)
			{
				$xml->writeElement('error', call_user_func_array(array($phraseController, 'getPhrase'), $error));
			}
			$xml->endElement();
		}

		$xml->endElement();
		$xml->endDocument();
		echo $xml->outputMemory();
	}

	public function actionForums()
	{
		header('Content-type: application/xml');
		$api = Api_InterfaceAbstract::instance();
		$channels = $api->callApi('nativo:nativo', 'forums');

		$xml = new XMLWriter();
		$xml->openMemory();
		$xml->startDocument();
		$xml->startElement('categories');

		if(!isset($channels['errors']))
		{
			foreach ($channels['forums'] AS $channel)
			{
				$xml->startElement('category');
				$xml->writeAttribute('id', $channel['id']);
				unset($channel['id']);
				foreach($channel AS $name => $value)
				{
					$xml->writeElement($name, $value);
				}
				$xml->endElement();
			}
		}
		else
		{
			$phraseController = vB5_Template_Phrase::instance();
			foreach($channels['errors'] AS $error)
			{
				$phraseController->register($error[0]);
			}

			$xml->startElement('errors');
			foreach($channels['errors'] AS $error)
			{
				$xml->writeElement('error', call_user_func_array(array($phraseController, 'getPhrase'), $error));
			}
			$xml->endElement();
		}

		$xml->endElement();
		$xml->endDocument();
		echo $xml->outputMemory();
	}

	function actionTemplate()
	{
		header('Content-type: application/xml');
		$template = vB5_Template::staticRender('nativo_topic');

		//remove the read class the hard way.  The actual computations
		//are to heavily tied up on the content date, which we don't want
		//to set to a non zero value for other reasons.  This avoids
		//coded a very nativo specific solution in core.
		$re = '#class\\s*=\\s*[\'"][^\'"]*@CustomCssClass[^\'"]*[\'"]#';
		if(preg_match($re, $template, $matches))
		{
			$classString = $matches[0];
			$re = '#(?<=[\'" ])read(?=[\'" ])#';

			$newClassString = preg_replace($re, '', $classString);
			$template = str_replace($classString, $newClassString, $template);
		}

		$xml = new XMLWriter();
		$xml->openMemory();
		$xml->startDocument();
		$xml->startElement('templates');
		$xml->startElement('template');
		$xml->writeAttribute('type', 'desktop');
		$xml->writeCDATA($template);
		$xml->endElement();
		$xml->endElement();

		$xml->endDocument();
		echo $xml->outputMemory();
	}
}
