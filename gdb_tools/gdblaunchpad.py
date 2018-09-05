"""
This is used to set up the environment for running other gdb scripts.
See OmniplayEnvironment.run_gdb_script
"""
import sys
import os
import re
from omniplay.gdbscripts import ScriptUtilities

import imp

utils = ScriptUtilities()

outfile = utils.get_redirect_file()

if outfile == None:
    #gdb in -batch-silent mode suppresses stdout
    sys.stdout = sys.stderr
else:
    sys.stdout = open(outfile, 'w')

scriptname = utils.get_arg("SCRIPT")

if not os.path.isfile(scriptname):
    #look in the gdb scripts folder
    omniplay_dir = os.environ["OMNIPLAY_DIR"]
    script_dir = "gdb_tools"

    newname = '/'.join([omniplay_dir, script_dir, scriptname])
    if not os.path.isfile(newname):
        raise IOError("Could not find file: " + scriptname)

    scriptname = newname

imp.load_source('__main__', scriptname)
