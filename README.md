#ossec2halo

The ossec2halo tool was built to convert the <a href="http://www.ossec.net/" target="new">OSSEC Open Source Host-based Intrusion Detection System (HIDS)</a> rules to the format used by CloudPassage® Halo®.

Note - CloudPassage does not provide the OSSEC rules. You must download OSSEC from its website and copy the rules into the ./data directory.

##Requirements
* require 'nokogiri'

You must also install Ruby 1.8+ and it is recommended that you install git for easy downloading of the repository.

##Usage

### Listing Available OSSEC Rules
<pre>
./ossec2halo.rb list

e.g.
<b>./ossec2halo.rb list</b>
[+] List of OSSEC XML files...
[>>>] apache_rules.xml
[>>>] arpwatch_rules.xml
[>>>] asterisk_rules.xml
[>>>] attack_rules.xml
[>>>] bro-ids_rules.xml
[>>>] cimserver_rules.xml
...
[>>>] wordpress_rules.xml
[>>>] zeus_rules.xml
</pre>

###Generating CloudPassage® Halo® Policy Files
<pre>
./ossec2halo.rb convert

e.g.
<b>./ossec2halo.rb convert</b>
[+] Converting OSSEC .xml files to CloudPassage® Halo® .json format...
[>>>] Generated OSSEC_apache_rules.json in ./converted/
[>>>] Generated OSSEC_arpwatch_rules.json in ./converted/
[>>>] Generated OSSEC_asterisk_rules.json in ./converted/
[>>>] Generated OSSEC_attack_rules.json in ./converted/
[>>>] Generated OSSEC_bro-ids_rules.json in ./converted/
[>>>] Generated OSSEC_cimserver_rules.json in ./converted/
...
[>>>] Generated OSSEC_wordpress_rules.json in ./converted/
[>>>] Generated OSSEC_zeus_rules.json in ./converted/
</pre>

##References

* CloudPassage - <a href="http://www.cloudpassage.com" target="new">http://www.cloudpassage.com</a>
* OSSEC - <a href="http://www.ossec.net/" target="new">http://www.ossec.net/</a>
* OSSEC License - <a href="http://www.ossec.net/?page_id=52" target="new">http://www.ossec.net/?page_id=52</a>

##To Do

* Specify individual files to convert
* Create additional rules per log directory

Want to fix it? Fork the repo and make it happen.

##Contact

To provide any feedback or ask any questions please reach out to Andrew Hay on Twitter at <a href="http://twitter.com/andrewsmhay" target="new">@andrewsmhay</a> or CloudPassage at <a href="http://twitter.com/cloudpassage" target="new">@cloudpassage</a>.

##About CloudPassage
CloudPassage is the leading cloud infrastructure security company and creator of Halo, the industry's first and only security and compliance platform purpose-built for elastic cloud environments. Halo's patented architecture operates seamlessly across any mix of software-defined data center, public cloud, and even hardware infrastructure. Industry-leading enterprises including multiple trust Halo to protect their cloud and software-defined datacenter environments. Headquartered in San Francisco, CA, CloudPassage is backed by Benchmark Capital, Tenaya Capital, Shasta Ventures, and other leading investors. For more information, please visit <a href="http://www.cloudpassage.com" target="new">http://www.cloudpassage.com</a>.

CloudPassage® and Halo® are registered trademarks of CloudPassage, Inc.

##About OSSEC
OSSEC is a full platform to monitor and control your systems. It mixes together all the aspects of HIDS (host-based intrusion detection), log monitoring and SIM/SIEM together in a simple, powerful and open source solution. It is also backed and fully supported by <a href="http://www.trendmicro.com/" target"new">Trend Micro</a>.

OSSEC is copyrighted © 2013 by Trend Micro, Inc.