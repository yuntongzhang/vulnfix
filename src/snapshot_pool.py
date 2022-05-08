from snapshot import *

# a place for storing all hashes of snapshots in use
snapshot_hashes = set()

pass_ss = list()
fail_ss = list()

def add_new_snapshots(new_passes, new_fails):
    """
    When new snapshots are added to pool, they will be sanitized here as well.
    """
    global pass_ss, fail_ss
    for ss in new_passes:
        hash = calc_single_ss_hash(ss)
        snapshot_hashes.add(hash)
        pass_ss.append(ss)

    for ss in new_fails:
        hash = calc_single_ss_hash(ss)
        snapshot_hashes.add(hash)
        fail_ss.append(ss)

    pass_ss, fail_ss = sanitize_snapshots(pass_ss, fail_ss)


def calc_single_ss_hash(snapshot):
    ret = hash(frozenset(snapshot.items()))
    return ret


def is_new_snapshot(snapshot):
    hash = calc_single_ss_hash(snapshot)
    is_new = hash not in snapshot_hashes
    return is_new
