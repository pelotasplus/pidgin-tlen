import re
import codecs

# a very simple and brainless script that converts a Tlen.pl
# emote set (emo.xml) file to a Gaim theme file
#
# input: emo.xml
# output: theme

header = """Name=Tlen.pl
Description=Emoticons from the Tlen.pl official client.
Icon=usmiech4_.gif

Author=o2.pl

[default]
"""

outFile = file("theme", "w")
outFile.write(header);

fileName = re.compile("<i i='.*' g='([^']*)'")
emote = re.compile("<t>(.*)</t>")

for line in codecs.EncodedFile(file("emo.xml"), "utf8", "iso8859-2").readlines():
	m = fileName.search(line)
	if m:
		outFile.write("\n" + m.groups()[0].strip() + "\t")
	else:
		m = emote.search(line)
		if m:
			emo = m.groups()[0]
			emo = emo.strip()
			emo = emo.replace("&lt;", "<");
			emo = emo.replace("&gt;", ">");
			outFile.write(" " + emo)
		
