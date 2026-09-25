"""Compare address unions, independently of their CIDR representation."""
import ipaddress


def networks(values):
    return list(ipaddress.collapse_addresses(ipaddress.ip_network(v) for v in values))


def subtract(left, right):
    """Yield inclusive integer intervals in left but not right, in O(N+M)."""
    j = 0
    for network in left:
        start, end = int(network.network_address), int(network.broadcast_address)
        while j < len(right) and int(right[j].broadcast_address) < start:
            j += 1
        k = j
        while k < len(right) and int(right[k].network_address) <= end:
            other_start, other_end = int(right[k].network_address), int(right[k].broadcast_address)
            if other_start > start:
                yield start, other_start - 1
            start = max(start, other_end + 1)
            if start > end:
                break
            k += 1
        if start <= end:
            yield start, end
        j = k


def summarize(intervals, version):
    count, sample = 0, []
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    for start, end in intervals:
        count += end - start + 1
        if len(sample) < 20:
            for net in ipaddress.summarize_address_range(address(start), address(end)):
                sample.append(str(net))
                if len(sample) == 20:
                    break
    return count, sample


def coverage_delta(before, after, version):
    old, new = networks(before), networks(after)
    if any(n.version != version for n in old + new):
        raise ValueError('coverage comparison mixes address families')
    added, added_sample = summarize(subtract(new, old), version)
    removed, removed_sample = summarize(subtract(old, new), version)
    return {'addresses_added': added, 'addresses_removed': removed,
            'addresses_retained': sum(n.num_addresses for n in old) - removed,
            'added_cidr_sample': added_sample, 'removed_cidr_sample': removed_sample,
            'representation_only': set(before) != set(after) and added == removed == 0}
