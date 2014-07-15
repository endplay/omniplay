"""@package dmesg
Omniplay dmesg helper.  Tools to parse the dmesg output from a systemlog.
"""

import omniplay

import threading
import time

def _thread_start(dmesg):
    dmesg._poll_dmesg()

class OmniplayDmesg(object):
    """
    Utility class for monitoring dmesg during recording and replaying of objects
    """
    def __init__(self):
        self._dmesg = ""
        self._dmesg_lock = threading.Lock()
        self._running = False
        self._t = None


    def _clear_dmesg(self):
        """
        Clears the dmesg buffer
        """
        omniplay.run_shell("sudo dmesg --clear")
        self._dmesg = ""

    def _read_dmesg(self):
        """
        Reads the dmesg buffer into self
        """
        with self._dmesg_lock:
            proc = omniplay.run_shell("sudo dmesg --read-clear", outp=omniplay.PIPE)
            out = proc.communicate()
            self._dmesg = ''.join([self._dmesg, out[0]])
        return out[0]

    def _poll_dmesg(self):
        """
        Periodically polls dmesg.
        Never returns
        """
        try:
            self._dmesg_lock.acquire()
            while self._running:
                self._dmesg_lock.release()
                self._read_dmesg()
                time.sleep(.01)
                self._dmesg_lock.acquire()
            self._dmesg_lock.release()
        except (KeyboardInterrupt, SystemExit):
            # Just break out of the loop and exit
            print "Killing dmesg monitor"
            pass
        
    def start_recording(self):
        """
        Clears dmesg, then begins recording
        """
        assert self._t is None, "dmesg recording already started"
        self._dmesg = ""
        self._clear_dmesg()
        self._running = True

        # Start thread that periodically polls dmesg
        self._t = threading.Thread(target=_thread_start, args=(self, ))
        self._t.start()

    def stop_recording(self):
        """
        Stops recording dmesg
        
        @returns the recorded dmesg
        """
        # Stop thread periodically polling dmesg
        with self._dmesg_lock:
            self._running = False

        if self._t is not None:
            self._t.join()
            self._t = None
        else:
            return None

        # Read dmesg
        self._read_dmesg()

        # Return dmesg
        return self._dmesg

    def get_dmesg(self):
        """
        Gets the recorded dmesg to this point
        """
        with self._dmesg_lock:
            ret = self._dmesg

        return ret

