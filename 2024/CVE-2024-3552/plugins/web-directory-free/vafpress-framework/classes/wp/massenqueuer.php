<?php

/**
 * For singleton accessor, use VP_W2DC_WP_MassEnqueuer class instead.
 */
class VP_W2DC_WP_MassEnqueuer
{
	private static $_instance = null;

	public static function instance()
	{
		if(self::$_instance == null)
		{
			self::$_instance = new VP_W2DC_WP_Enqueuer();
		}
		return self::$_instance;
	}

}