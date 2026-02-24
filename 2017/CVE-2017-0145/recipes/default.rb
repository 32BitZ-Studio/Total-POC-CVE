#
# Cookbook:: tissues
# Recipe:: default

# Are we on Windows?
if node['platform_family'] == 'windows'
  # Create a hash of the available patch urls
  urls = {
      :v61 => {
          :server => {
              :x64 => 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu'
          },
          :desktop => {
              :x64 => 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x64_2decefaa02e2058dcd965702509a992d8c4e92b3.msu',
              :x86 => 'http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.1-kb4012212-x86_6bb04d3971bb58ae4bac44219e7169812914df3f.msu'
          }
      },
      :v62 => {
          :server => {
              :x64 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8-rt-kb4012214-x64_b14951d29cb4fd880948f5204d54721e64c9942b.msu'
          },
          :desktop => {
              :x64 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x64_f05841d2e94197c2dca4457f1b895e8f632b7f8e.msu',
              :x86 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/05/windows8-rt-kb4012598-x86_a0f1c953a24dd042acc540c59b339f55fb18f594.msu'
          }
      },
      :v63 => {
          :server => {
              :x64 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu'
          },
          :desktop => {
              :x64 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x64_5b24b9ca5a123a844ed793e0f2be974148520349.msu',
              :x86 => 'http://download.windowsupdate.com/c/msdownload/update/software/secu/2017/02/windows8.1-kb4012213-x86_e118939b397bc983971c88d9c9ecc8cbec471b05.msu'
          }
      }
  }

  # Switch on the OS version
  case ::Windows::VersionHelper.nt_version node
    when 6.1
      # 'Windows 7 or Server 2008R2'
      version = :v61
    when 6.2
      # 'Windows 8 or Server 2012'
      version = :v62
    when 6.3
      # 'Windows 8.1 or Server 2012R2'
      version = :v63
    else
      # Not supported
      version = false
  end

  # If we got a version
  if version
    # Switch on the machine architecture
    case node['kernel']['machine']
      when "x86_64"
        # If we are x64 then check to see if we are on a server version
        if ::Windows::VersionHelper.server_version? node
          chosen_url = urls[version][:server][:x64]
        else
          chosen_url = urls[version][:desktop][:x64]
        end
      when "i686"
        # If we are x86 then we know that there is no server os, so select the desktop url
        chosen_url = urls[version][:desktop][:x86]
      else
        # Otherwise something odd happened
        chosen_url = false
    end

    if chosen_url
      # Wrap install in a try catch
      begin
        # Install the MSU from the url
        msu_package 'Install: MS17-010 - CVE-2017-0145 - WannaCry Patch' do
          source chosen_url
          action :install
        end
      rescue
        log 'MS17-010 install: failed to install patch' do
          message "Failed to install WannaCry patch..."
          level :error
        end
      end
    else
      log 'MS17-010 install: unable to determine patch source' do
        message "Failed to determine a source url for WannaCry patch..."
        level :error
      end
    end
  else
    log "MS17-010 install: windows version not supported: #{::Windows::VersionHelper.nt_version node}" do
      message "Found unsupported os version: #{::Windows::VersionHelper.nt_version node} ..."
      level :error
    end
  end
else
  log "MS17-010 install: platform not supported #{node['platform_family']}" do
    message "#{node['platform_family']} is not supported..."
    level :warn
  end
end