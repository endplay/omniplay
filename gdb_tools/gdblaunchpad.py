"""
This is used to set up the environment for running other gdb scripts.
See OmniplayEnvironment.run_gdb_script
"""
import sys
import re
from omniplay.gdbscripts import ScriptUtilities

utils = ScriptUtilities()

outfile = utils.get_redirect_file()

if outfile == None:
    #gdb in -batch-silent mode suppresses stdout
    sys.stdout = sys.stderr
else:
    sys.stdout = open(outfile, 'w')

scriptname = utils.get_arg("SCRIPT")

#strip off the trailing ".py" if any
scriptname = re.sub(r"\.py$", '', scriptname)

#Run the script!
__import__(scriptname)
