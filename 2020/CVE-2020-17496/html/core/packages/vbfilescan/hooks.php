<?php
class vbfilescan_Hooks
{
	public static function hookAdminSettingsSelectOptions($params)
	{
		if($params['settingid'] == 'enabled_scanner')
		{
			$vbphrase = vB_Api::instanceInternal('phrase')->fetch(array('vbfilescan_clamav_label'));
			$params['options']['vbfilescan:clamav'] = $vbphrase['vbfilescan_clamav_label'];
		}
	}
}
