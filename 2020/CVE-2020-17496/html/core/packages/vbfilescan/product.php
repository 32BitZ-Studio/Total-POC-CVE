<?php

class vbfilescan_Product
{
/*
	vBulletin Filescan Package
*/

/*
	$vbMinVersion ;
		Sets the minimum version of vBulletin this product is valid for.
		The product will only be active if the running version is equal to, or greater than, this minimum.
		If this is not set, then it will run on any version less than or equal to the maximum (see vbMaxVersion).

	$vbMaxVersion ;
		Sets the maximum version of vBulletin this product is valid for.
		The product will only be active if the running version is less than, or equal to, this maximum.
		If this is not set, then it will run on any version greater than or equal to the minimum (see vbMinVersion).
*/

	public $vbMinVersion = '5.5.5 Alpha 1';
	public $vbMaxVersion = '5.9.9';

	public static $AutoInstall = true;

	public $hookClasses = array(
		'vbfilescan_Hooks'
	);
}
