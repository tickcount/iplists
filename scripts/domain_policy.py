"""Guard suffix rules against public/shared hosting boundaries."""
import hashlib


class DomainPolicy:
    def __init__(self, text, shared, normalize):
        self.exact, self.wildcards, self.exceptions = set(), set(), set()
        self.shared = shared
        for line in text.splitlines():
            rule = line.strip()
            if not rule or rule.startswith('//'):
                continue
            target = self.exact
            if rule.startswith('!'):
                target, rule = self.exceptions, rule[1:]
            elif rule.startswith('*.'):
                target, rule = self.wildcards, rule[2:]
            # A PSL rule can be a single label; normal domain inputs cannot.
            target.add(normalize('psl-validation.' + rule).split('.', 1)[1])

    def reason(self, domain):
        if domain in self.shared:
            return self.shared[domain]
        if domain in self.exceptions:
            return None
        if domain in self.exact or domain.partition('.')[2] in self.wildcards:
            return 'Public Suffix List boundary (ICANN or private hosting)'
        return None


def load_policy(settings, base, normalize):
    if not settings:
        return None, None
    path = base / settings['public_suffix_file']
    body = path.read_bytes()
    text = body.decode('utf-8')
    if not all(marker in text for marker in ('// ===BEGIN ICANN DOMAINS===',
                                             '// ===END ICANN DOMAINS===',
                                             '// ===BEGIN PRIVATE DOMAINS===',
                                             '// ===END PRIVATE DOMAINS===')):
        raise ValueError('incomplete Public Suffix List snapshot')
    policy = DomainPolicy(text, settings.get('shared_suffixes', {}), normalize)
    if len(policy.exact) < 1000:
        raise ValueError('Public Suffix List snapshot is unexpectedly small')
    return policy, {'file': settings['public_suffix_file'],
                    'sha256': hashlib.sha256(body).hexdigest(),
                    'shared_suffixes': policy.shared,
                    'rules': len(policy.exact) + len(policy.wildcards) + len(policy.exceptions)}
