#!/usr/bin/env ruby

require 'nokogiri'
require 'haloformat'



=begin
	
Sample of OSSEC file

<group name="apache,">
  <rule id="30100" level="0">
    <decoded_as>apache-errorlog</decoded_as>
    <description>Apache messages grouped.</description>
  </rule>    

  <rule id="30101" level="0">
    <if_sid>30100</if_sid>
    <match>^[error] </match>
    <description>Apache error messages grouped.</description>
  </rule>
</group>

=end

=begin
	
Sample of actual Halo rule

{
  "iea_policy": {
    "name": "Apache",
    "description": "Apache messages grouped.",
    "platform": "linux",
    "template": "false",
    "retired": "false",
    "system": "false",
    "rules": [
      {
        "name": "Apache error messages grouped.",
        "search pattern": "^[error] ",
        "file_path": "/var/log/apache2/error.log",
        "kind": "text",
        "active": true,
        "alert": true,
        "critical": true
      }
    ]
  }
}
	
=end

=begin

Sample of format using class

HaloFormat.header
	HaloFormat.name + rb_file_master + HaloFormat.commaend
	HaloFormat.description + ////check_name//// + HaloFormat.commaend
	HaloFormat.platform + "Linux" + HaloFormat.commaend #or Windows
	HaloFormat.template
	HaloFormat.retired
	HaloFormat.system
	HaloFormat.rules
		HaloFormat.leftcurl
			HaloFormat.name + ////check_desc//// + HaloFormat.commaend
			HaloFormat.searchpattern + ////check_match//// + HaloFormat.commaend
			HaloFormat.filepath + ////need to discover dir/file//// + HaloFormat.commaend
			HaloFormat.kind + "Text" + HaloFormat.commaend
			HaloFormat.active
			HaloFormat.alert
			HaloFormat.critical
		HaloFormat.rightcurl+HaloFormat.comma

		### count number of rules and finish the last one with
		HaloFormat.rightcurl
		###
HaloFormat.footer	
=end

inputter = []
commands = []
ossec_dir = "./data/"
output_dir = "./converted/"

ARGV.each {|arg| commands << arg}
rb_file_master = Dir.glob(ossec_dir+"*.xml")

rb_file_master.each do |rb_file|
	xml = Nokogiri::XML.parse(open rb_file)
      xml.css('group rule').each do |host|
        begin
          check_decoded_as = host.css('decoded_as')
          check_if_sid = host.css('if_sid')
          check_regex = host.css('regex')
          check_name = host.css('group')
          check_desc = host.css('description')
          check_match = host.css('match')

          inputter << [check_decoded_as.to_s,
		       		   check_if_sid.to_s,
		  			   check_regex.to_s,
		  			   check_name.to_s,
		  			   check_desc.to_s,
		  			   check_match.to_s]
        rescue Exception => e
          puts Messages.err
        next
        end
      end
  end

match_ary = []
if ARGV[0] == 'convert'
	inputter.each do |matchers| 
	unless matchers[5].empty?
			puts matchers[5]+"|"+matchers[4]
	end
end

elsif ARGV[0] == 'list'
	puts "[+] List of OSSEC XML files..."
	rb_file_master.each do |filename|
		puts "[>>>] "+filename.gsub(/#{ossec_dir}/, '')
	end
else puts Messages.usage
end
end
