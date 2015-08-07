##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize
    super(
      'Name'         => 'BusyBox Ping Network',
      'Description'  => 'This module will be applied on a session connected
                         to a BusyBox sh shell. The script will ping a range of
                         ip adresses from the router or device executing BusyBox.',
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'http://vallejo.cc']
        ],
      'Platform'      => ['linux'],
       'SessionTypes'  => ['shell']
    )

    register_options(
      [
        OptAddress.new('IPRANGESTART',   [ true, "The first ip address of the range to ping.", nil ]),
        OptAddress.new('IPRANGEEND',   [ true, "The last ip address of the range to ping.", nil ])
      ], self.class)

  end

  def run

    #this module will send a sh script for busybox shell for doing ping to a range of ip address from
    #the router or device that is executing busybox. It could be possible to calculate each ip address
    #of the range of ip addresses in the ruby script and execute each ping command with cmd_exec, but
    #it would generate an unnecesary traffic in the connection with the busybox device (usually telnet)

    rand_str = ""; 16.times{rand_str  << (65 + rand(25)).chr}

    sh_script_lines=[
            "#!/bin/sh",
            "param1=#{datastore['IPRANGESTART']}",
            "param2=#{datastore['IPRANGEEND']}",
            "while true;",
            "  param1cpy=\"$param1\"",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec1=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec2=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  pos=`expr index \"$param1cpy\" \".\"`",
            "  pos=`expr $pos - 1`",
            "  octec3=`expr substr \"$param1cpy\" 1 $pos`",
            "  pos=`expr $pos + 2`",
            "  len=`expr length \"$param1cpy\"`",
            "  param1cpy=`expr substr \"$param1cpy\" $pos $len`",
            "  octec4=\"$param1cpy\"",
            "  carry=0",
            "  len=`expr length \"$octec4\"`",
            "  temp=`expr match \"$octec4\" \"255\"`",
            "  if [ $temp -eq $len ]; then",
            "    octec4=0",
            "    carry=1",
            "  else",
            "    octec4=`expr $octec4 + 1`",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec3\"`",
            "    temp=`expr match \"$octec3\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec3=0",
            "      carry=1",
            "    else",
            "      octec3=`expr \"$octec3\" + 1`",
            "    fi",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec2\"`",
            "    temp=`expr match \"$octec2\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec2=0",
            "      carry=1",
            "    else",
            "      octec2=`expr $octec2 + 1`",
            "    fi",
            "  fi",
            "  if [ $carry -eq 1 ]; then",
            "    carry=0",
            "    len=`expr length \"$octec1\"`",
            "    temp=`expr match \"$octec1\" \"255\"`",
            "    if [ $temp -eq $len ]; then",
            "      octec1=0",
            "      carry=1",
            "    else",
            "      octec1=`expr $octec1 + 1`",
            "    fi",
            "  fi",
            "  ping -c 1 \"$param1\"",
            "  param1=\"$octec1\"\".\"\"$octec2\"\".\"\"$octec3\"\".\"\"$octec4\"",
            "  temp=`expr match \"$param1\" \"$param2\"`",
            "  len=`expr length \"$param2\"`",
            "  if [ $temp -eq $len ]; then",
            "    break",
            "  fi",
            "done",
            "ping -c 1 \"$param1\"",
            rand_str
            ]

    full_results = ""

    #send script and receive echos
    count=0
    sh_script_lines.each do |sh_script_line|
      session.shell_write(sh_script_line + "\n")
      count+=1
      Rex::sleep(0.03)
      #receiving echos
      if count%20==0
        result=session.shell_read()
        vprint_status(result)
        if result.include? rand_str
          #some ping results could have been read together with the echo of the sh script sent
          full_results << result.split(rand_str)[-1]
        end        
        Rex::sleep(0.03)
      end
    end
 
    #receive last pending echo
    result=session.shell_read()
    vprint_status(result)
    if result.include? rand_str
      #some ping results could have been read together with the echo of the sh script sent
      full_results << result.split(rand_str)[-1]
    end        

    #receiving ping results    
    print_status("Script has been sent to the busybox device. Doing ping to the range of addresses.")    
    while true
      result = session.shell_read()
      if result.length>0
        print_status(result)
        full_results << result
        if result.include? rand_str
          break
        end
      end
      Rex::sleep(0.5)
    end
      
    #storing results
    p = store_loot("Pingnet", "text/plain", session, full_results, "#{datastore['IPRANGESTART']}"+"-"+"#{datastore['IPRANGEEND']}", "BusyBox Device Network Range Pings")
    print_good("Pingnet results saved to #{p}")
      
  end

end