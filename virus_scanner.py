import subprocess
import fnmatch
import os,time
from stat import * # ST_SIZE etc
import csv

filename= str(raw_input('Please Enter the filename :'))
print "======File Info======"
try:
    st = os.stat(filename)
except IOError:
    print "failed to get information about", filename
else:
    print "file size:", st[ST_SIZE]
    print "file modified:", time.asctime(time.localtime(st[ST_MTIME]))
    print "access rights:",st[ST_MODE]

res = subprocess.check_output(["strings", filename])
md5 = subprocess.check_output(["md5sum", filename]).split()[0]
sha1 = subprocess.check_output(["sha1sum", filename]).split()[0]
sha256 = subprocess.check_output(["sha256sum", filename]).split()[0]
obj_dump = subprocess.check_output(["objdump","-f", filename])

str_list = res.splitlines()

#process the output line by line

def dll_check(strings):
	dll_list=[]
	for line in strings:
		if (fnmatch.fnmatch(line, '*.DLL')):
			dll_list.append(line)
		elif (fnmatch.fnmatch(line, '*.dll')):
			dll_list.append(line)
	return dll_list;

def file_permission_check(strings):
	file_man_list=[]
	for line in strings:
		if ("File" in line or "file" in line):
			file_man_list.append(line)	
	return file_man_list;

def memory_access_commands(strings):
	mem_man_list=[]
	for line in strings:
		if ("Heap" in line or "heap" in line or "alloc" in line or "flag" in line ):
			mem_man_list.append(line)	
	return mem_man_list;

def process_commands(strings):
	process_list=[]
	for line in strings:
		if ("Process" in line  ):
			process_list.append(line)	
	return process_list;


print "======Used Windows Dlls======"
print dll_check(str_list)
print "======Used File Manipulation Commands======"
print file_permission_check(str_list)
print "======Used Memory Access Commands======"
print memory_access_commands(str_list)
print "======Used Process Manipulation Commands======"
print process_commands(str_list)



archi = "x86 (32 bit)"
if "x86-64" in obj_dump:
    archi = "x64 (64 bit)"
elif "architecture: i386" in obj_dump:
    pass
else:
    archi = "UNKNOWN"

print "======Program Architecture======"
print archi

print "======Results from Virus Database======"
with open('db.csv', 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in reader:
            if md5 == row[4] or sha1 == row[5] or sha256 == row[6]:
                print "Virus Name \t : %s" % row[3]
                print "Virus Type \t : %s" % row[10]
        else:
        	print "No matches found !"