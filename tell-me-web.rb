#!/usr/bin/env ruby

################################################################################
#    Tell Me Web?
#  
#    license: GPL 
#    released date: 2011-02-06
#     
#    last updated:  2011-02-06
#
#    (c) Aung Khant, http://yehg.net               
#                                                 
#    YGN Ethical Hacker Group, Yangon, Myanmar
#
#    Check the update via
#    svn checkout http://tellmeweb.googlecode.com/svn/trunk/ tellmeweb
#
#
#    How it works
#    
#    The tellmeweb takes gnmap outpout (-oG) generated together with -sV option.
#    It takes all hosts with http & https ports open.
#    Then it feeds them into whatweb. 
#
#
################################################################################


require 'erb'
require 'fileutils'

# path to whatweb
$whatweb = '/pentest/web/whatweb/_git_working/WhatWeb/whatweb'
$whatweb_opt = ' -U "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"  --follow-redirect=never -v '

def print_banner
  puts "\n=============================================================
Tell Me Web?
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://tellmeweb.googlecode.com/svn/trunk/ tellmeweb
=============================================================\n\n"
end


def errmsg(s)
    puts s.to_s
    exit!
end
    
def main()

    print_banner

    errmsg("\nUsage:\nruby #{$0} nmap-out-file-in-gnmap-format\nruby #{$0} nmap-out-file-in-gnmap-format A[ggressive]") if ARGV.length < 1

    nmapout = ARGV[0]
    aggressive = ARGV[1]

    unless File.file?nmapout
       errmsg('[x] File is not found or not valid!')
    end
    unless aggressive == nil
        aggressive = ' -a 4 -r '
    else 
        aggressive = ' '
    end
    ip = ''
    ip_ports = []

    tmp1 = ''
    tmp2 = []
    found_http = 0
    sf = File.new(nmapout,"r")
    furl = []
    while fline = sf.gets
        fu = ''
        
        if fline.length > 1  and fline !~ /^#/ 
        
            if fline =~ /Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \(([^\(^\)].*?)\)\tPorts: ([\S\w\W\s,\/\|\.0-9a-zA-Z\(\)\?\\]+)+/ || fline =~ /Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\(\))\tPorts: ([\S\w\W\s,\/\|\.0-9a-zA-Z\(\)\?\\]+)+/  
                
                ip = $1

                tmp1 = $3            

                tmp2 = []
                tmp2 = fline.scan(/Ports: ([\S\w\W\s,\/\|\.0-9a-zA-Z\(\)\?\\]+)+/)

                tmp3 = ''
                tmp3 = tmp2[0][0].to_s if tmp2.size == 1
                
                tmp4 = tmp3.split(',') if tmp3.length > 1
                tmp4.each do |t|
                    if t =~ /([\d{1,5}]+)\/open\/tcp\/\/http/ 
                        lnk =   ip + ':'  + $1
                        lnk.gsub!("\r\n","")
                        lnk.gsub!("\n","")
                        ip_ports << lnk
                        found_http = 1
                    elsif t =~ /([\d{1,5}]+)\/open\/tcp\/\/https/ 
                        lnk =   ip + ':'  + $1
                        lnk.gsub!("\r\n","")
                        lnk.gsub!("\n","")
                        ip_ports << lnk
                        found_http = 1
                    elsif t =~ /([\d{1,5}]+)\/open\/tcp\/\/ssl\|https/ 
                        lnk =   'https://' + ip + ':'  + $1
                        lnk.gsub!("\r\n","")
                        lnk.gsub!("\n","")
                        ip_ports << lnk
                        found_http = 1
                    end 
                end
                

                
            end
           
        end
        
    end


    if ip_ports.size > 0
        links = []         
        ip_ports.uniq!           
        ip_ports.each do |target|
            if target=~ /:\/\//
                target1   = target
                target1.gsub!("https://","")
                tfn = target1.split(':')
            else
                tfn = target.split(':')
            end
            fn = tfn[0] + '_' + tfn[1] + '.whatweb ' 
            fn.gsub!("http://")
            fn.gsub!("https://")
            wcmd = $whatweb + $whatweb_opt + ' --log-full=' + fn + aggressive  + target
            if aggressive =~ /a/
                puts '**Aggressive Scan  -> ' + target
            else
                puts '**Current -> ' + target
            end
            puts '   log file as ' + fn
            #puts '  [Start] ' + wcmd
            puts
            r = system(wcmd)
            if r == nil || r == false
                puts
                puts '[X]  whatweb path not found!'
                puts
                puts '*Configure path to whatweb executable in $whatweb variable at line 33'
                exit!
            end            
            puts
            puts 
        end
    else
        puts   '[*] No http/https ports found in input file'
    end

puts 
end

if __FILE__ == $0
  main()
end

