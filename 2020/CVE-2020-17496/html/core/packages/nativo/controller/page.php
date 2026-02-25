<?php

class Nativo_Controller_Page extends vB5_Frontend_Controller
{
	public function actionDetail($args)
	{
		/*
		 	This approach is problematic, but its the least of several evils.  The problem is that
			our templates want us to pass in the image url for the avatar, but the placeholder value
			for nativo is for the entire image element.  While its possible to tweak the templates
			to substitute the placeholder for the element based on some data values, it bends the
			core templates too far to support an add on.

			The other approach would be to clone the templates so that we can customize them as product
			specific templates.  That, however, defeats the main point of using the templates which is
			to automatically pick up any site cusomizations.

			The approach here is to generate the page as normal and to alter the text afterward to
			meet the requirements of the nativo system.  This is potentially fragile, but we've done
			two things to mitigate that
			1) We mark the specific section of text for the nativo post in the nativo specific template,
				making it unlikely that the re's used will jump the treads and do something to the rest of
				the page (particularly if its altered in sitebuilder).
			2) We render the template with the guest avatar initially so if the markup is altered so that
				the replace fails, we'll get something presentable if not 100% correct.
		*/
		ob_start();
		$pagecontroller = new vB5_Frontend_Controller_Page();
		$pagecontroller->index($args);
		$text = ob_get_clean();

		//find the chunk of text we want to manipulate.  The two step process has much better
		//performance as complex REs on big strings do crazy things.
		$re= "#<!-- start nativo fullpost -->(.*)<!-- end nativo fullpost -->#s";
		if (preg_match($re, $text, $matches))
		{
			$oldtext = $matches[0];
			$newtext = $matches[1];

			//find the actual span for the avatar and replace with placeholder
			$re = "#(<span class=[\"'][^\"']*b-avatar[^\"']*[\"']>)(?:.(?!</span>))*.(</span>)#s";
			$newtext = preg_replace($re, '$1<!-- @AuthorLogo -->$2', $newtext);
			$text = str_replace($oldtext, $newtext, $text);
		}
		echo $text;
	}
}
