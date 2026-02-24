import datetime

# sysout color option
Green="\033[0;32m"        # Green
Black="\033[0;30m"        # Black
Yellow="\033[0;33m"       # Yellow
Red="\033[0;31m"          # Red
White="\033[0;37m"        # White
# Bold High Intensty
BIBlack="\033[1;90m"      # Black
BIRed="\033[1;91m"        # Red
BIGreen="\033[1;92m"      # Green
BIYellow="\033[1;93m"     # Yellow
BIBlue="\033[1;94m"       # Blue
BIPurple="\033[1;95m"     # Purple
BICyan="\033[1;96m"       # Cyan
BIWhite="\033[1;97m"      # White


# user options
user_agent = 'Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36'
timeout_seconds = 5
verbose = False  
dt = datetime.datetime.now() 


exit = '{!} Ending hp-cve-check ....'
example = '      python3 hp-cve-check.py -i 192.168.223.1 -O output.txt\n      python3 hp-cve-check.py -I targets.txt -O output.txt'

synerror = '{X} Syntax Error, see usage:'

underline = '    ----------------------------------------'



art = '''
                        ________________
                    _/_______________/|
                    /___________/___//||    HP CVE Check
                    |===        |----| || 
                    |           |   �| ||    Author: Tyler Butler 
                    |___________|   �| ||            @tbutler0x90
                    | ||/.�---.||    | ||    
                    |-||/_____\||-.  | |�
                    |_||==HP===||_|__|/      
'''


badchars = [
    '<',
    '>',
    '&lt;',
    '&gt;',
    'a',
    'a2',
    'abbr',
    'acronym',
    'address',
    'animate',
    'animatemotion',
    'animatetransform',
    'applet',
    'area',
    'article',
    'aside',
    'audio',
    'audio2',
    'b',
    'base',
    'basefont',
    'bdi',
    'bdo',
    'bgsound',
    'big',
    'blink',
    'blockquote',
    'body',
    'br',
    'button',
    'canvas',
    'caption',
    'center',
    'cite',
    'code',
    'col',
    'colgroup',
    'command',
    'content',
    'custom tags',
    'data',
    'datalist',
    'dd',
    'del',
    'details',
    'dfn',
    'dialog',
    'dir',
    'div',
    'dl',
    'dt',
    'element',
    'em',
    'embed',
    'fieldset',
    'figcaption',
    'figure',
    'font',
    'footer',
    'form',
    'frame',
    'frameset',
    'h1',
    'head',
    'header',
    'hgroup',
    'hr',
    'html',
    'i',
    'iframe',
    'iframe2',
    'image',
    'image2',
    'image3',
    'img',
    'img2',
    'input',
    'input2',
    'input3',
    'input4',
    'ins',
    'isindex',
    'kbd',
    'keygen',
    'label',
    'legend',
    'li',
    'link',
    'listing',
    'main',
    'map',
    'mark',
    'marquee',
    'menu',
    'menuitem',
    'meta',
    'meter',
    'multicol',
    'nav',
    'nextid',
    'nobr',
    'noembed',
    'noframes',
    'noscript',
    'object',
    'ol',
    'optgroup',
    'option',
    'output',
    'p',
    'param',
    'picture',
    'plaintext',
    'pre',
    'progress',
    'q',
    'rb',
    'rp',
    'rt',
    'rtc',
    'ruby',
    's',
    'samp',
    'script',
    'section',
    'select',
    'set',
    'shadow',
    'slot',
    'small',
    'source',
    'spacer',
    'span',
    'strike',
    'strong',
    'style',
    'sub',
    'summary',
    'sup',
    'svg',
    'table',
    'tbody',
    'td',
    'template',
    'textarea',
    'tfoot',
    'th',
    'thead',
    'time',
    'title',
    'tr',
    'track',
    'tt',
    'u',
    'ul',
    'var',
    'video',
    'video2',
    'wbr',
    'xmp',
    ]

