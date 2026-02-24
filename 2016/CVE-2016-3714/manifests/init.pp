class imagick_secure {
  file { '/etc/ImageMagick/policy.xml':
    ensure  => present,
    mode    => '0644',
    owner   => 'root',
    group   => 'root',
    content => template('imagick_secure/etc/ImageMagick/policy.xml.erb'),
    require => Exec["imagick_exists"]
  }

  exec { "imagick_exists":
    command => '/bin/true',
    onlyif  => '/usr/bin/test -f /etc/ImageMagick/policy.xml'
  }
}