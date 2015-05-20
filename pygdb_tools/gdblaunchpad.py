import sys
import re
from omniplay.gdbscripts import ScriptUtilities

utils = ScriptUtilities()

outfile = utils.get_redirect_file()

if outfile != None:
   sys.stdout = open(outfile, 'w')

scriptname = utils.get_arg("SCRIPT")

#strip off the trailing ".py" if any
scriptname = re.sub(r"\.py$", '', scriptname)

#Run the script!
__import__(scriptname)
