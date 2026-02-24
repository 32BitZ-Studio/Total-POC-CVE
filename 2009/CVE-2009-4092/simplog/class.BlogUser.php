<?php 

	/*******************************************************************
	 * $Id: class.BlogUser.php,v 1.2 2004/02/06 07:57:14 f-bomb Exp $
	 *
	 * class.BlogUser.php
	 * Author: Jason Buberel
	 * Copyright (C) 2003, Jason Buberel
	 * jason@buberel.org
	 * http://www.buberel.org/
	 *
	 *******************************************************************
	 This program is free software; you can redistribute it and/or modify it
	 under the terms of the GNU General Public License as published by the
	 Free Software Foundation; either version 2 of the License, or (at your
	 option) any later version.

	 This program is distributed in the hope that it will be useful, but
	 WITHOUT ANY WARRANTY; without even the implied warranty of
	 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	 General Public License for more details.

	 You should have received a copy of the GNU General Public License along
	 with this program; if not, write to the Free Software Foundation, Inc.,
	 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
	 *******************************************************************
	 *
	 * This class is meant to represent the overall BlogUser and to act
     * as a container of all of the blogs hosted on that server instance.
     * Initially, this will provide methods for retrieving the list of
     * BlogInfo objects for each of the blogs listed in the blog_list
     * table. There are also methods for adding and removing entrie blogs.
     *
     * To use BlogUser, you create a new instance using the provided
     * constructor:
     *  include_once("class.BlogUser.php");
     *  $myBlogUser = new BlogUser();
     *
	 */

include_once("lib.php");
include_once("class.BlogInfo.php");

class BlogUser {
    // private variables
    var $userLogin;
    var $userEmail;
    var $userName;
    var $userId;
    var $adminFlag;


    // constructor.
    function BlogUser ($userId, $userLogin, $userEmail, $userName, $adminFlag) {
        
        $this->userLogin = $userLogin;
        $this->userEmail = $userEmail;
        $this->userName = $userName;
        $this->userId = $userId;
        $this->adminFlag = $adminFlag;
    }




}

?>
