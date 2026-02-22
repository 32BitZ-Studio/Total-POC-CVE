<?php
function wc_comp_rep_shop_employees() {
	if (!current_user_can('manage_options')) {
      wp_die( __('You do not have sufficient permissions to access this page.') );
    }
	$output = '<div class="wrap">';
	$output .= '<h1>Employees</h1>';
	$output .= '<p>The employees feature is available only in premiume version which you can get in 35$ one time fees with all time future updates.</p>';
	$output .= '<h2>Premiume Plugin Details</h2>';
	$output .= '<h3>Jobs</h3>
			<p>
				A customer looking into your website services, and Parts area, will have an option to select add to cart the cart widget is available in premiume version so wherever you add the widget the ordered service or part would be added into that cart and user can then order more services or parts during that time. So once a user is done with all order he would go to cart page where he will see his total of parts and services if a service is ordered then part installation charges would not apply also if any service enabled pick up and delivery and its charges that would be added in extras to cart page only 1 time. Similar if a service say laptop rental available for week or 1 days charges would be added once in extras on cart page, where user can modify that means if he dont want to get any of these both extra services he/she can just delete them and order other service.
			</p>
			<p>
			Employees also have option to start a job which come in jobs so employee start working on that job and then send it to next employee changing the status of job for customer to get Email and view by entering to his account by loging in. Login details would be emailed to customer during his job creation. Employee can only see the jobs he created or someone else assigned him. Once he assign job to someone else he would not able to make any change into that job unless its assigned back to him. Admin can do all things anytime. But the employee would able to see list of jobs in specefic period he started or he did. 
			</p>
			';
	$output .= '<h3>Employees</h3>';
	$output .= '<p>This is where admin can add a new employee and his login details would be sent to him on his Email. When a job is created by admin or any other employee they can assign that to themself or anyone else in system. Employees then will list the details of things they doing in job so in final invoice all details can come up like installed parts details, provided services details etc.</p>
	<p>When a job is assigned to an employee by admin or if he created job himself or the job was ordered from the cart system by client, employee will start working on job and if he install a part in job he will select part from parts list. Same for services then he will assign job to other employee or mark system as done. Which would be informed to admin users and client by Email.</p>
	';
	$output .= '<h3>Clients</h3>';
	$output .= '<p>Clients get login details while they order direct from front end or when their job is created by employee or admin by using that login details they can check the status of their ordered job anytime that who and what work is going on in their computer.</p>';	
	
	$output .= "<form action='https://www.2checkout.com/checkout/purchase' method='post'>
  <input type='hidden' name='sid' value='102588421'>
  <input type='hidden' name='quantity' value='1'>
  <input type='hidden' name='product_id' value='4'>
  <input name='submit' type='submit' value='Buy from 2CO' >
</form>
<span>2Checkout.com Inc. (Ohio, USA) is a payment facilitator for goods and services provided by http://www.webfulcreations.com.</span>";	
	$output .= '</div>';

	echo wp_kses_post($output);
}//add category function ends here.
?>