with open("rf.xml", "r") as infile:
  indata = infile.read().split("\n")
for i in range(len(indata)):
  if '<TTGlyph name="uni0025"' in indata[i]:
    theoff = i
newchar = '      <component glyphName="uni0020" x="747" y="0" flags="0x4"/>'
outdata = indata[0:theoff + 1] + [newchar]*(0xfffd - 3) + indata[theoff+1:]
with open("rf2.xml", "w") as outfile:
  outfile.write("\n".join(outdata))
