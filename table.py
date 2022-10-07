import sys
from collections import defaultdict

results = defaultdict(dict) # domain => {sni => {fprint => result}}}

for line in sys.stdin:
    parts = line.split(' ')
    host,sni,fprint = parts[1].split('_')
    result = parts[2].strip()

    if sni not in results[host]:
        results[host][sni] = defaultdict(str)

    results[host][sni][fprint] = result


domains = sorted(results.keys())

print('  & ', ' & '.join(domains), '   \\\\')

for host in domains:
    host_res = []
    for sni in domains:
        sni_res = ''
        for fprint in ["chrome-105","go","openssl"]:
            okay = results[host][sni][fprint] == 'allowed'
            if okay:
                sni_res += '\\textcolor{blue}{O}'
            else:
                sni_res += '\\textcolor{red}{X}'

        host_res.append(sni_res)
    print('%s   & %s \\\\' % (host, ' & '.join(host_res)))
