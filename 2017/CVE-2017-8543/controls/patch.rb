# encoding: utf-8
# author: ApexInfa

control 'CVE-2017-8543' do
  impact 1.0
  title 'Update for CVE-2017-8543 vulnerability should exist'
  desc '
   Checks Windows systems for hotfixes that patch against the CVE-2017-8543 vulnerability.
   If this test fails, you should run Windows update ASAP.
  '

  os_version = powershell('(Get-WmiObject -Class Win32_OperatingSystem).Version').strip.to_sym

  platform_hotfixes = { '10.0.15063'.to_sym => /KB4022725/, # Windows 10 (1703)
                        '10.0.14393'.to_sym => /KB4022715/, # Windows Server 2016; Windows 10 (1607)
                        '10.0.10586'.to_sym => /KB4022714/, # Windows 10 (1511)
                        '10.0.10240'.to_sym => /KB4022727/, # Windows 10
                        '6.3.9600'.to_sym => /KB4022726/, # Windows Server 2012 R2, Windows 8.1
                        '6.2.9200'.to_sym => /KB4022724/, # Windows Server 2012; Windows 8
                        '6.1.7601'.to_sym => /KB4022719/, # Windows Server 2008 R2 (SP1); Windows 7 (SP1)
                        '6.1.7600'.to_sym => //, # Windows Server 2008 R2; Windows 7
                        '6.0.6002'.to_sym => /KB4024402/, # Windows Server 2008 (SP2);	Windows Vista (SP2)
                        '6.0.6001'.to_sym => //, # Windows Server 2008 (SP1); Windows Vista (SP1)
                        '6.0.6000'.to_sym => // } # Windows Vista

  describe powershell('Get-HotFix | Select \'HotFixID\'') do
    its('stdout') { should match(platform_hotfixes[os_version]) }
  end
end
