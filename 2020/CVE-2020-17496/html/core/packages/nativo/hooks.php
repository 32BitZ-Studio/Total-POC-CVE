<?php
class nativo_Hooks
{
	public static function hookTemplateGroupPhrase($params)
	{
		$params['groups']['nativo'] = 'group_nativo';
	}
}

