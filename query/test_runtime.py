#!/usr/bin/python

import sys
import runtime

def main():
    rt = runtime.RunTimeInfo()
    rt.check_system()

    replay_process_id = str(sys.argv[1])

    print("Running replay process " + replay_process_id)
    p = rt.replay_process(replay_process_id)
    p.wait()
    print("Replayed process rc: %d" % p.returncode)

    print("Running replay process %s with DATA linkage" %
            replay_process_id)
    # test running the data linkage now
    p, pin_process = rt.run_linkage(replay_process_id, "DATA", flags="-ao")
    p.wait()
    pin_process.wait()

    print("Replayed process rc: %d, pid was %d" %
            (p.returncode, p.pid))
    print("Pin process rc: %d, pid was %d" % 
            (pin_process.returncode, pin_process.pid))

if __name__ == "__main__":
    main()
