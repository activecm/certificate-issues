#!/bin/bash

#Provides a summary of certificate issues in the zeek logs below the
#current directory.
#Copyright 2021-2022, Active Countermeasures.
#Released under GPL 3.0
#William Stearns <bill@activecountermeasures.com>

#Version 1.0.0

#Sample runs:
#Look at a single sensor on an AC-Hunter system
#	cd /opt/zeek/remotelogs/sensor1/ ; certificate_issues.sh | less
#Look at all sensors on an AC-Hunter system
#	cd /opt/zeek/remotelogs/ ; certificate_issues.sh | less
#Look at the local logs on an Zeek/Espy/Active-Flow system
#	cd /opt/zeek/logs/ ; certificate_issues.sh | less

#max_days=" -mtime -30 "		#Limit to just SSL log files created in the last 30 days
max_days=" "				#Process SSL log files of any age


if [ -z "`type -path jq`" ]; then
	echo "jq utility not installed, installing.  sudo may prompt you to enter your password."
	if [ -n "`type -path apt`" ]; then
		sudo apt install jq >&2
	elif [ -n "`type -path yum`" ]; then
		sudo yum install jq >&2
	else
		echo "Unable to locate an appropriate installer.  Please install the jq utility and rerun this tool." >&2
		exit 1
	fi
fi
if [ -n "`type -path zeek-cut`" ]; then
	cutter_tool='zeek-cut'
elif [ -n "`type -path bro-cut`" ]; then
	cutter_tool='bro-cut'
else
	echo "zeek-cut utility not installed, installing.  sudo may prompt you to enter your password."
	if [ -n "`type -path apt`" ]; then
		sudo apt install zeek-aux >&2 || exit 1
	elif [ -n "`type -path yum`" ]; then
		sudo yum install zeek-aux >&2 || exit 1
	else
		echo "Unable to locate an appropriate installer.  Please install the zeek-cut utility and rerun this tool." >&2
		exit 1
	fi
fi

echo -e '#Seen\tsource_ip\tserver_ip\tsrv_prt\tTLS_ver\thostname\t\tInvalid Certificate Code'
for one_file in `find . $max_days -iname 'ssl.*.log.gz'` ; do
	case `file -b -Z "$one_file"` in
	CSV\ text*|ASCII\ text*|FGDC-STD-001-1998)			#FGDC... is a misidentification of the gzip compressed TSV format.
		#File is text, so we assume it's tab separated
		zcat $one_file \
		 | awk -F'\t' '$21 != "ok" && $21 != "-" {print}' \
		 | "$cutter_tool" id.orig_h id.resp_h id.resp_p version server_name validation_status
		;;
	JSON\ data*)
		#File is json, so we use jq to extract the right fields
		zcat $one_file \
		 | jq -r 'select(."validation_status" != "ok" and ."validation_status" != null) | (."id.orig_h"|tostring) + "\t" + (."id.resp_h"|tostring) + "\t" + (."id.resp_p"|tostring) + "\t" + (."version"|tostring) + "\t" + (."server_name"|tostring) + "\t" + (."validation_status"|tostring)'
		;;
	*)
		#Hmmm, unknown file type.
		echo "We do not recognize the file type of $one_file:" >&2
		echo "Here is the file type: " >&2
		file -b -Z "$one_file" >&2
		echo "Here is the uncompressed file type: " >&2
		zcat "$one_file" | file -b -Z - >&2
		echo "Please notify support@activecountermeasures.com with the above output so we can improve the program." >&2
		exit 1
		;;
	esac
done \
 | sort -k 2 -V \
 | uniq -c

