"""
Unit test for the filemap.  Does trivial file write, then parses the filemap 
on that file to make sure its sane
"""
import omniplay

import collections
import tempfile

FilemapState = collections.namedtuple('FilemapState_simple',
    ['tmpfilename', 'env', 'ckpt'])

def record(env):
    """
    The actual body of the test
    """
    tup = tempfile.mkstemp()
    tmp = tup[1]
    
    ckpt = env.record('echo "Hello World" > ' + tmp)

    return FilemapState(tmpfilename=tmp, env=env, ckpt=ckpt)
    
def parse(state):
    """
    Does any static checking on the logs/recordings or system state
    """
    env = state.env

    tmpdir = tempfile.mkdtemp()
    children = env.parsegroup(state.ckpt.group_id, tmpdir)
    env.filemap(state.tmpfilename)

    omniplay.run_shell("rm -rf " + tmpdir)

    return len(children)

def replay(state):
    """
    Replay portion of the test
    """
    env = state.env
    logdir = env.get_record_dir(state.ckpt.group_id)
    env.replay(logdir)

def dump(state, outdir):
    """
    Creates a full dump of the replay, for debugging purpose
    """
    state.env.parsegroup(state.ckpt.group_id, outdir)

