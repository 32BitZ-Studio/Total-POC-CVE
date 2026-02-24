name 'tissues'
maintainer 'Alex Markessinis'
maintainer_email 'markea125@gmail.com'
license 'MIT'
description 'Install patch for CVE-2017-0145 AKA WannaCry.'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version '0.1.5'
chef_version '>= 12.1' if respond_to?(:chef_version)
supports 'windows'
depends 'windows', '>= 3.0.5'
issues_url 'https://github.com/MelonSmasher/chef_tissues/issues'
source_url 'https://github.com/MelonSmasher/chef_tissues'
