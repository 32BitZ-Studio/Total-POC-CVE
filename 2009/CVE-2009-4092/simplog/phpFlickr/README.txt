phpFlickr Class 1.2.1
Written by Dan Coulter (dan@dancoulter.com)
Project Homepage: http://www.phpflickr.com/
Sourceforge Project Page: http://www.sourceforge.net/projects/phpflickr/
Released under GNU General Public License (http://www.gnu.org/copyleft/gpl.html)
For more information about the class and upcoming tools and toys using it,
visit http://www.phpflickr.com or http://www.sourceforge.net/projects/phpflickr/

Installation instructions:
1.  Be sure to have these PEAR prereqs installed:
        HTTP_Request
        PHPUnit
        DB
    If you have PEAR installed on your *nix server, you can run "pear install <package>"
    from the command line.  You can find much more information and documentation
    at http://pear.php.net/.  You can get detailed installation instructions there.
    
2.  Copy xml.php and phpFlickr.php into the same folder on your server.  They need to
    be readible by your web server.  You can put them into an include folder defined
    in your php.ini file, if you like, though it's not required.  
    
3.  All you have to do now is include the file in your PHP scripts and create an     
    instance.  For example:
    $f = new phpFlickr("<your API Key>");

    The constructor requires your API key as an argument.  If you want to use
    the Flickr API methods that require authentication, you'll need to include your
    login information as arguments in the login() function (Flickr requires an unencrypted
    password, but a new auth scheme is in the works). For example:
    $f = new phpFlickr("<your API Key>")
    $f->login("your@email.address", "your password");

    One final note.  The constructor has a second argument.  If you set it to true,
    all API calls that return an error will cause the script to "die" and echo the
    error code.  By default, error results will return a false and you can access the 
    error with the getErrorMsg() method.

4.  All of the API methods have been implemented in my class.  You can see a full list
    and documentation here: http://www.flickr.com/services/api/.  To call a method,
    remove the "flickr." part of the name and replace any periods with underscores.
    For example, instead of flickr.photos.search, you would call $f->photos_search()
    or instead of flickr.photos.licenses.getInfo, you would call
    $f->photos_licenses_getInfo() (yes, it is case sensitive).
    All functions have their arguments implemented in the list order on their
    documentation page (a link to which is included with each function in the clasS).
    The only exception to this is photos_search() which has so many optional arguments
    that it's easier for everyone around if you just have to pass an associative array
    of arguments.  See the comment in the photos_search() definition in phpFlickr.php 
    for more information.

Using Caching:
    Caching can be very important to a project.  Just a few calls to the Flickr API
    can take long enough to bore your average web user (depending on the calls you
    are making).  I've built in caching that will access either a database or files
    in your filesystem.  To enable caching, use the phpFlickr::enableCache() function.
    This function requires at least two arguments. The first will be the type of
    cache you're using (either "db" or "fs")
    
    1.  If you're using database caching, you'll need to supply a PEAR::DB connection
        string. For example: 
        $flickr->enableCache("db", "mysql://user:password@server/database");
        The third (optional) argument is expiration of the cache in seconds (defaults 
        to 600).  The fourth (optional) argument is the table where you want to store
        the cache.  This defaults to flickr_cache and will attempt to create the table
        if it does not already exist.
    
    2.  If you're using filesystem caching, you'll need to supply a folder where the
        web server has write access. For example: 
        $flickr->enableCache("fs", "/var/www/phpFlickrCache");
        The third (optional) argument is, the same as in the Database caching, an
        expiration in seconds for the cache.
        Note: filesystem caching will probably be slower than database caching. I
        haven't done any tests of this, but if you get large amounts of calls, the
        process of cleaning out old calls may get hard on your server.
        
        You may not want to allow the world to view the files that are created during
        caching.  If you want to hide this information, either make sure that your
        permissions are set correctly, or disable the webserver from displaying 
        *.cache files.  In Apache, you can specify this in the configuration files
        or in a .htaccess file with the following directives:
        
        <FilesMatch "\.cache$">
            Deny from all
        </FilesMatch>
        
        Alternatively, you can specify a directory that is outside of the web server's
        document root.
        
Other Notes:
    1.  Many of the methods have optional arguments.  For these, I have implemented 
        them in the same order that the Flickr API documentation lists them. PHP
        allows for optional arguments in function calls, but if you want to use the
        third optional argument, you have to fill in the others to the left first.
        You can use the "NULL" value (without quotes) in the place of an actual
        argument.  For example:
        $f->groups_pools_getPhotos($group_id, NULL, NULL, 10);
        This will get the first ten photos from a specific group's pool.  If you look
        at the documentation, you will see that there is another argument, "page". I've
        left it off because it appears after "per_page".

That's it! Enjoy the class.  Check out the project page (listed above) for updates
and news.  I plan to implement file uploads and functions to aggregate data from
several different methods for easier use in a web application.  Thanks for your
interest in this project!

    Please email me or submit all problems or questions to the Help Forum on
    my project page:
        http://sourceforge.net/forum/forum.php?forum_id=469652

 
