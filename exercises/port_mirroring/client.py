#!/usr/bin/env python3

import requests
from timeit import default_timer as timer

ITERATIONS = 20000
times = []

if __name__ == '__main__':
    for i in range(ITERATIONS):
        start = timer()
        r = requests.get('http://10.0.2.2:80')
        end = timer()
        if r.status_code != 200:
            exit(1)
        times.append(end-start)
        if i % 1000 == 0:
            print(i, 'iterations done')
    with open('client_result.txt', 'w') as fd:
        fd.writelines(' '.join([str(t) for t in times]))
    print(sum(times)/ITERATIONS)

