var deployJava = {
    debug: null,

    firefoxJavaVersion: null,

    // mime-type of the DeployToolkit plugin object
    oldMimeType: 'application/npruntime-scriptable-plugin;DeploymentToolkit',
    mimeType: 'application/java-deployment-toolkit',

    browserName: null,
    browserName2: null,

    /**
     * Returns an array of currently-installed JRE version strings.  
     * Version strings are of the form #.#[.#[_#]], with the function returning
     * as much version information as it can determine, from just family 
     * versions ("1.4.2", "1.5") through the full version ("1.5.0_06").
     *
     * Detection is done on a best-effort basis.  Under some circumstances 
     * only the highest installed JRE version will be detected, and 
     * JREs older than 1.4.2 will not always be detected.
     */
    getJREs: function() {
        var list = new Array();
        if (deployJava.isPluginInstalled()) {
            var plugin =  deployJava.getPlugin();
            var VMs = plugin.jvms;
            for (var i = 0; i < VMs.getLength(); i++) {
                list[i] = VMs.get(i).version;
            }
        } else {
            var browser = deployJava.getBrowser();

            if (browser == 'MSIE') {
                if (deployJava.testUsingActiveX('1.7.0')) {
                    list[0] = '1.7.0';
                } else if (deployJava.testUsingActiveX('1.6.0')) {
                    list[0] = '1.6.0';
                } else if (deployJava.testUsingActiveX('1.5.0')) {
                    list[0] = '1.5.0';
                } else if (deployJava.testUsingActiveX('1.4.2')) {
                    list[0] = '1.4.2';
                } else if (deployJava.testForMSVM()) {
                    list[0] = '1.1';
                }
            } else if (browser == 'Netscape Family') {
                deployJava.getJPIVersionUsingMimeType();
                if (deployJava.firefoxJavaVersion != null) {
                    list[0] = deployJava.firefoxJavaVersion;
                } else if (deployJava.testUsingMimeTypes('1.7')) {
                    list[0] = '1.7.0'; 
                } else if (deployJava.testUsingMimeTypes('1.6')) {
                    list[0] = '1.6.0';
                } else if (deployJava.testUsingMimeTypes('1.5')) {
                    list[0] = '1.5.0';
                } else if (deployJava.testUsingMimeTypes('1.4.2')) {
                    list[0] = '1.4.2';
                } else if (deployJava.browserName2 == 'Safari') {
                    if (deployJava.testUsingPluginsArray('1.7.0')) {
                        list[0] = '1.7.0'; 
                    } else if (deployJava.testUsingPluginsArray('1.6')) {
                        list[0] = '1.6.0';
                    } else if (deployJava.testUsingPluginsArray('1.5')) {
                        list[0] = '1.5.0';
                    } else if (deployJava.testUsingPluginsArray('1.4.2')) {
                        list[0] = '1.4.2';
                    }
                }
            }
        }
            
        if (deployJava.debug) {
            for (var i = 0; i < list.length; ++i) {
                alert('We claim to have detected Java SE ' + list[i]);
            }
        }
    
        return list;
    },
    
    // obtain JPI version using navigator.mimeTypes array
    // if found, set the version to deployJava.firefoxJavaVersion
    getJPIVersionUsingMimeType: function() {
        // Walk through the full list of mime types.
        for (var i = 0; i < navigator.mimeTypes.length; ++i) {
            var s = navigator.mimeTypes[i].type;
            // The jpi-version is the plug-in version.  This is the best
            // version to use.
            var m = s.match(/^application\/x-java-applet;jpi-version=(.*)$/);
            if (m != null) {
                deployJava.firefoxJavaVersion = m[1];
                break;
            }
        }
    },
      
    /*
     * returns true if the ActiveX or XPI plugin is installed
     */
    isPluginInstalled: function() {
        var plugin = deployJava.getPlugin();
        if (plugin && plugin.jvms) {
            return true;
        } else {
            return false;
        }
    },
    
     
    allowPlugin: function() {
        deployJava.getBrowser();

        // Chrome, Safari, and Opera browsers find the plugin but it 
        // doesn't work, so until we can get it to work - don't use it.
        var ret = ('Chrome' != deployJava.browserName2 &&
            'Safari' != deployJava.browserName2 &&
            'Opera' != deployJava.browserName2);
        return ret;
    },

    getPlugin: function() {
        deployJava.refresh();

        var ret = null;
        if (deployJava.allowPlugin()) {
            ret = document.getElementById('deployJavaPlugin');
        }
        return ret;
    },

    getBrowser: function() {

        if (deployJava.browserName == null) {
            var browser = navigator.userAgent.toLowerCase();
    
            if (deployJava.debug) {
                alert('userAgent -> ' + browser);
            }

            // order is important here.  Safari userAgent contains mozilla,
            // and Chrome userAgent contains both mozilla and safari.
            if (browser.indexOf('msie') != -1) {
                deployJava.browserName = 'MSIE';
                deployJava.browserName2 = 'MSIE';
            } else if (browser.indexOf('firefox') != -1) {
                deployJava.browserName = 'Netscape Family';
                deployJava.browserName2 = 'Firefox';
            } else if (browser.indexOf('chrome') != -1) {
                deployJava.browserName = 'Netscape Family';
                deployJava.browserName2 = 'Chrome';
            } else if (browser.indexOf('safari') != -1) {
                deployJava.browserName = 'Netscape Family';
                deployJava.browserName2 = 'Safari';
            } else if (browser.indexOf('opera') != -1) {
                deployJava.browserName = 'Netscape Family';
                deployJava.browserName2 = 'Opera';
            } else if ((browser.indexOf('trident/7') != -1) && (browser.indexOf("rv:11")!=-1)) {
                deployJava.browserName = 'MSIE';
                deployJava.browserName2 = 'MSIE';
            } else {
                deployJava.browserName = '?';
                deployJava.browserName2 = 'unknown';
            }

            if (deployJava.debug) {
                alert ('Detected browser name:'+ deployJava.browserName +
                       ', ' + deployJava.browserName2);
            }
        }
        return deployJava.browserName;
    },
    
    
    testUsingActiveX: function(version) {
        var objectName = 'JavaWebStart.isInstalled.' + version + '.0';
    
        if (!ActiveXObject) {
            if (deployJava.debug) {
              alert ('Browser claims to be IE, but no ActiveXObject object?');
            }
            return false;
        }
    
        try {
            return (new ActiveXObject(objectName) != null);
        } catch (exception) {
            return false;
        }
    },
    

    testForMSVM: function() {
        var clsid = '{08B0E5C0-4FCB-11CF-AAA5-00401C608500}';

        if (typeof oClientCaps != 'undefined') {
            var v = oClientCaps.getComponentVersion(clsid, "ComponentID");
            if ((v == '') || (v == '5,0,5000,0')) {
                return false;
            } else {
                return true;
            } 
        } else {
            return false;
        }
    },

    
    testUsingMimeTypes: function(version) {
        if (!navigator.mimeTypes) {
            if (deployJava.debug) {
                alert ('Browser claims to be Netscape family, but no mimeTypes[] array?');
            }
            return false;
        }
    
        for (var i = 0; i < navigator.mimeTypes.length; ++i) {
            s = navigator.mimeTypes[i].type;
            var m = s.match(/^application\/x-java-applet\x3Bversion=(1\.8|1\.7|1\.6|1\.5|1\.4\.2)$/);
            if (m != null) {
                if (deployJava.compareVersions(m[1], version)) {
                    return true;   
                }
            }
        }
        return false;
    },
    
    testUsingPluginsArray: function(version) {
        if ((!navigator.plugins) || (!navigator.plugins.length)) {
            return false;
        }
        var platform = navigator.platform.toLowerCase();

        for (var i = 0; i < navigator.plugins.length; ++i) {
            s = navigator.plugins[i].description;
            if (s.search(/^Java Switchable Plug-in (Cocoa)/) != -1) {
                // Safari on MAC
                if (deployJava.compareVersions("1.5.0", version)) {
                    return true;
                }
            } else if (s.search(/^Java/) != -1) {
                if (platform.indexOf('win') != -1) {
                    // still can't tell - opera, safari on windows
                    // return true for 1.5.0 and 1.6.0
                    if (deployJava.compareVersions("1.5.0", version) ||
                        deployJava.compareVersions("1.6.0", version)) {
                        return true;
                    }
                }
            }
        }
        // if above dosn't work on Apple or Windows, just allow 1.5.0
        if (deployJava.compareVersions("1.5.0", version)) {
            return true;
        }
        return false;
    },
        
    // return true if 'installed' (considered as a JRE version string) is
    // greater than or equal to 'required' (again, a JRE version string).
    compareVersions: function(installed, required) {

        var a = installed.split('.');
        var b = required.split('.');
    
        for (var i = 0; i < a.length; ++i) {
            a[i] = Number(a[i]);
        }
        for (var i = 0; i < b.length; ++i) {
            b[i] = Number(b[i]);
        }
        if (a.length == 2) {
            a[2] = 0;      
        }
    
        if (a[0] > b[0]) return true;
        if (a[0] < b[0]) return false;
    
        if (a[1] > b[1]) return true;
        if (a[1] < b[1]) return false;
    
        if (a[2] > b[2]) return true;
        if (a[2] < b[2]) return false;
    
        return true;
    },
    
    writePluginTag: function() {
        var browser = deployJava.getBrowser();

        if (browser == 'MSIE') {
            document.write('<' + 
                'object classid="clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" ' +
                'id="deployJavaPlugin" width="0" height="0">' +
                '<' + '/' + 'object' + '>');
        } else if (browser == 'Netscape Family' && deployJava.allowPlugin()) {
            deployJava.writeEmbedTag();
        }
    },

    refresh: function() {
        navigator.plugins.refresh(false);

        var browser = deployJava.getBrowser();
        if (browser == 'Netscape Family' && deployJava.allowPlugin()) {
            var plugin = document.getElementById('deployJavaPlugin');
            // only do this again if no plugin
            if (plugin == null) {
                deployJava.writeEmbedTag();
            }
        }
     },

    writeEmbedTag: function() {
        var written = false;
        if (navigator.mimeTypes != null) {
            for (var i=0; i < navigator.mimeTypes.length; i++) {
                if (navigator.mimeTypes[i].type == deployJava.mimeType) {
                    if (navigator.mimeTypes[i].enabledPlugin) {
                        document.write('<' +
                            'embed id="deployJavaPlugin" type="' +
                            deployJava.mimeType + '" hidden="true" />');
                        written = true;
                    }
                }
            }
            // if we ddn't find new mimeType, look for old mimeType
            if (!written) for (var i=0; i < navigator.mimeTypes.length; i++) {
                if (navigator.mimeTypes[i].type == deployJava.oldMimeType) {
                    if (navigator.mimeTypes[i].enabledPlugin) {
                        document.write('<' +
                            'embed id="deployJavaPlugin" type="' +
                            deployJava.oldMimeType + '" hidden="true" />');
                    }
                }
            }
        }
    },

    do_initialize: function() {
        deployJava.writePluginTag();
    }
      
};
deployJava.do_initialize();
